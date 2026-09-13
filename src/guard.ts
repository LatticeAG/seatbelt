// Independent guard semantics (spec §2.5, §3.4).
// GuardCore implements arm/renew/stop/get, per-channel sequence discipline,
// sampling, bound enforcement, kill latching, kill retry, and emergency-slot
// evidence. It is driven by an injected clock and a KernelBackend, so the same
// code runs in the real guard process (LinuxKernel + CLOCK_BOOTTIME) and in the
// conformance harness (SimKernel + virtual time).

import type { KernelBackend, RunTree, RawSample } from "./kernel.js";
import type { EmergencyFile } from "./emergency.js";
import type { GuardInput, GuardReply, Reason, ResourceCaps, Sample } from "./schema.js";
import { SchemaError } from "./canon.js";
import { validateGuardInput } from "./schema.js";
import type { Json } from "./canon.js";

const GUARD_LEASE_MS = 750n;
const ARMING_BOUND_MS = 2000n; // setup timeout while ARMING
const FENCE_AFTER_MS = 2000n;  // populated persists past this → containment incomplete
const KILL_RETRY_MS = 1000n;

export interface GuardStopRecord {
  runId: string;
  killId: string;
  reason: Reason;
  scopeKind: "run" | "budget" | "host";
  scopeId: string;
  actor: string;
  requestId: string;
  requestedMs: bigint;
  signalSent: boolean;
  emptyObserved: boolean;
  observedMs: bigint | null;
}

interface GuardedRun {
  runId: string;
  epoch: string;
  containmentId: string;
  tree: RunTree;
  resources: ResourceCaps;
  wallDeadlineMs: bigint;
  /** arming deadline (start+2000) until first renew supplies heartbeat bound */
  heartbeatDeadlineMs: bigint;
  leaseUntilMs: bigint;
  lastSeq: bigint;
  lastInput: string | null;
  lastReply: GuardReply | null;
  latch: GuardStopRecord | null;
  sampleNo: bigint;
  lastCpuMs: bigint;
  lastMemMax: bigint;
  lastOom: bigint;
  lastTaskMax: bigint;
  lastSample: Sample | null;
  killRetryAtMs: bigint | null;
  /** latched at this ms; used for the 2000ms populated→fence window */
  latchedAtMs: bigint | null;
  emptyReported: boolean;
  armed: boolean;
  armedAtMs: bigint;
}

export interface GuardTickEvent {
  runId: string;
  kind: "stop" | "sample" | "empty" | "fence-overdue";
  stop?: GuardStopRecord;
  sample?: Sample;
}

export class GuardCore {
  private kernel: KernelBackend;
  private emergency: EmergencyFile | null;
  private bootId: string;
  private runs = new Map<string, GuardedRun>();
  private killSeq = 0;
  private daemonEofSeen = false;
  constructor(kernel: KernelBackend, emergency: EmergencyFile | null, bootId: string) {
    this.kernel = kernel;
    this.emergency = emergency;
    this.bootId = bootId;
  }

  private newKillId(runId: string): string {
    this.killSeq++;
    return `kill_${runId}_${this.killSeq}`;
  }

  handle(input: GuardInput, now: bigint): GuardReply {
    const r = this.runs.get(input.run_id);
    const base: Omit<GuardReply, "seq"> = {
      ok: false, code: "BAD_HANDLE", lease_until_ms: "0", stopped: false, sample: null,
    };
    if (!r || r.epoch !== input.epoch) {
      return { seq: input.seq, ...base };
    }
    // Per-channel sequence: exact duplicate frame reuses its reply; any other
    // stale or gapped sequence stops all guarded runs (defensive).
    const seq = BigInt(input.seq);
    if (r.lastInput !== null && input.op !== "get") {
      if (r.lastSeq === seq && r.lastReply !== null && r.lastInput === canonicalGuardInput(input)) {
        return r.lastReply;
      }
      if (seq !== r.lastSeq + 1n) {
        this.stopAll(now, "CONTROL_LOST");
        return { seq: input.seq, ok: false, code: "BAD_SEQUENCE", lease_until_ms: "0", stopped: r.latch !== null, sample: r.lastSample };
      }
    }
    let reply: GuardReply;
    switch (input.op) {
      case "arm": {
        if (r.armed) {
          reply = { seq: input.seq, ok: false, code: "BAD_HANDLE", lease_until_ms: "0", stopped: r.latch !== null, sample: r.lastSample };
          break;
        }
        r.wallDeadlineMs = BigInt(input.deadline_ms);
        r.heartbeatDeadlineMs = r.armedAtMs + ARMING_BOUND_MS;
        r.leaseUntilMs = min3(now + GUARD_LEASE_MS, r.wallDeadlineMs, r.heartbeatDeadlineMs);
        r.armed = true;
        reply = { seq: input.seq, ok: true, code: "OK", lease_until_ms: r.leaseUntilMs.toString(), stopped: false, sample: null };
        break;
      }
      case "renew": {
        if (r.latch) {
          reply = { seq: input.seq, ok: false, code: "LATCHED", lease_until_ms: "0", stopped: true, sample: r.lastSample };
          break;
        }
        r.heartbeatDeadlineMs = BigInt(input.heartbeat_deadline_ms);
        // daemon liveness lease: not bounded by the guest heartbeat deadline —
        // an expired heartbeat fires HEARTBEAT, an expired lease CONTROL_LOST.
        r.leaseUntilMs = now + GUARD_LEASE_MS;
        reply = { seq: input.seq, ok: true, code: "OK", lease_until_ms: r.leaseUntilMs.toString(), stopped: false, sample: r.lastSample };
        break;
      }
      case "stop": {
        if (!r.latch) {
          this.latch(r, now, {
            killId: input.kill_id, reason: input.reason, scopeKind: input.scope_kind, scopeId: input.scope_id,
            actor: input.actor, requestId: input.request_id,
          });
        }
        reply = { seq: input.seq, ok: true, code: "OK", lease_until_ms: "0", stopped: true, sample: r.lastSample };
        break;
      }
      case "get": {
        reply = { seq: input.seq, ok: true, code: "OK", lease_until_ms: r.latch ? "0" : r.leaseUntilMs.toString(), stopped: r.latch !== null, sample: r.lastSample };
        break;
      }
    }
    if (input.op !== "get") {
      r.lastSeq = seq;
      r.lastInput = canonicalGuardInput(input);
      r.lastReply = reply;
    }
    return reply;
  }

  /** arm a run; returns the guard-side run entry */
  arm(runId: string, epoch: string, containmentId: string, tree: RunTree, resources: ResourceCaps, wallDeadlineMs: bigint, startMs: bigint, now: bigint): GuardReply {
    if (this.runs.has(runId)) {
      return { seq: "0", ok: false, code: "BAD_HANDLE", lease_until_ms: "0", stopped: false, sample: null };
    }
    const g: GuardedRun = {
      runId, epoch, containmentId, tree, resources,
      wallDeadlineMs, heartbeatDeadlineMs: startMs + ARMING_BOUND_MS,
      leaseUntilMs: min3(now + GUARD_LEASE_MS, wallDeadlineMs, startMs + ARMING_BOUND_MS),
      lastSeq: 0n, lastInput: null, lastReply: null,
      latch: null, sampleNo: 0n, lastCpuMs: 0n, lastMemMax: 0n, lastOom: 0n, lastTaskMax: 0n,
      lastSample: null, killRetryAtMs: null, latchedAtMs: null, emptyReported: false,
      armed: false, armedAtMs: startMs,
    };
    this.runs.set(runId, g);
    return this.handle({ op: "arm", seq: "1", run_id: runId, epoch, containment_id: containmentId, deadline_ms: wallDeadlineMs.toString(), resources }, now);
  }

  private latch(r: GuardedRun, now: bigint, info: { killId: string; reason: Reason; scopeKind: "run" | "budget" | "host"; scopeId: string; actor: string; requestId: string }): void {
    let signalSent = false;
    try {
      r.tree.kill();
      signalSent = true;
    } catch {
      signalSent = false;
    }
    r.latch = {
      runId: r.runId, killId: info.killId, reason: info.reason, scopeKind: info.scopeKind, scopeId: info.scopeId,
      actor: info.actor, requestId: info.requestId, requestedMs: now, signalSent, emptyObserved: false, observedMs: null,
    };
    r.latchedAtMs = now;
    r.killRetryAtMs = now + KILL_RETRY_MS;
    // emergency evidence: one slot per affected run after attempting kill
    try {
      this.emergency?.write({
        v: 1, run_id: r.runId, epoch: r.epoch, boot_id: this.bootId, kill_id: info.killId,
        reason: info.reason, scope_kind: info.scopeKind, scope_id: info.scopeId,
        actor: info.actor, request_id: info.requestId, requested_ms: now.toString(),
        signal_sent: signalSent, empty_observed: false,
      });
    } catch {
      /* emergency persistence failure cannot delay the kill */
    }
  }

  /** Daemon lifetime-pipe EOF: latch and kill every guarded run now. */
  daemonEof(now: bigint): void {
    this.daemonEofSeen = true;
    this.stopAll(now, "CONTROL_LOST");
  }

  private stopAll(now: bigint, reason: Reason): void {
    for (const r of this.runs.values()) {
      if (!r.latch) {
        const killId = this.newKillId(r.runId);
        this.latch(r, now, { killId, reason, scopeKind: "run", scopeId: r.runId, actor: "guard", requestId: killId });
      }
    }
  }

  private fireReason(r: GuardedRun, now: bigint, s: RawSample): Reason | null {
    // §7.1 trip order subset owned by the guard: CONTROL_LOST, WALL,
    // HEARTBEAT, MEMORY, TASKS, CPU. (AUDIT/CONTAINMENT originate daemon-side;
    // CAP/PROVIDER_ERRORS/RATE are ledger-side.)
    if (now >= r.leaseUntilMs) return "CONTROL_LOST";
    if (now >= r.wallDeadlineMs) return "WALL";
    if (now >= r.heartbeatDeadlineMs) return "HEARTBEAT";
    if (s.memoryMaxEvents > r.lastMemMax || s.oomEvents > r.lastOom) return "MEMORY";
    if (s.pidsMaxEvents > r.lastTaskMax) return "TASKS";
    const cpuMs = (s.usageUsec + 999n) / 1000n; // round up to ms
    if (cpuMs >= BigInt(r.resources.cpu_ms)) return "CPU";
    return null;
  }

  /**
   * Advance the guard to time `now`: sample each armed run, fire bounds, retry
   * kills once per second, and report observations to the daemon.
   */
  tick(now: bigint): GuardTickEvent[] {
    const events: GuardTickEvent[] = [];
    for (const r of this.runs.values()) {
      let s: RawSample;
      try {
        s = r.tree.sample();
      } catch {
        s = { populated: true, usageUsec: 0n, memoryCurrent: 0n, memoryMaxEvents: r.lastMemMax, oomEvents: r.lastOom, pidsMaxEvents: r.lastTaskMax };
      }
      r.sampleNo++;
      const sample: Sample = {
        run_id: r.runId, boot_id: this.bootId, sample_no: r.sampleNo.toString(), at_ms: now.toString(),
        cpu_ms: ((s.usageUsec + 999n) / 1000n).toString(), memory_bytes: s.memoryCurrent.toString(),
        memory_max_events: s.memoryMaxEvents.toString(), oom_events: s.oomEvents.toString(),
        task_max_events: s.pidsMaxEvents.toString(), populated: s.populated,
      };
      r.lastSample = sample;
      events.push({ runId: r.runId, kind: "sample", sample });

      if (!r.latch) {
        const reason = this.fireReason(r, now, s);
        if (reason !== null) {
          const killId = this.newKillId(r.runId);
          this.latch(r, now, { killId, reason, scopeKind: "run", scopeId: r.runId, actor: "guard", requestId: killId });
          events.push({ runId: r.runId, kind: "stop", stop: r.latch! });
        }
      } else {
        // kill retry once per second while populated persists
        if (s.populated && r.killRetryAtMs !== null && now >= r.killRetryAtMs) {
          try {
            r.tree.kill();
            r.latch.signalSent = true;
          } catch {
            /* recorded below */
          }
          r.killRetryAtMs = now + KILL_RETRY_MS;
        }
        if (!s.populated && !r.latch.emptyObserved && r.tree.reaped()) {
          r.latch.emptyObserved = true;
          r.latch.observedMs = now;
          events.push({ runId: r.runId, kind: "empty", stop: r.latch });
        }
        if (s.populated && r.latchedAtMs !== null && now - r.latchedAtMs > FENCE_AFTER_MS) {
          events.push({ runId: r.runId, kind: "fence-overdue", stop: r.latch });
        }
      }
      r.lastMemMax = s.memoryMaxEvents;
      r.lastOom = s.oomEvents;
      r.lastTaskMax = s.pidsMaxEvents;
    }
    return events;
  }

  /** Current latch for a run, if any. */
  latchOf(runId: string): GuardStopRecord | null {
    return this.runs.get(runId)?.latch ?? null;
  }
  sampleOf(runId: string): Sample | null {
    return this.runs.get(runId)?.lastSample ?? null;
  }
  isStopped(runId: string): boolean {
    return this.runs.get(runId)?.latch !== undefined && this.runs.get(runId)!.latch !== null;
  }
  /** Remove bookkeeping after the run is terminal and empty. */
  retire(runId: string): void {
    const r = this.runs.get(runId);
    if (r && r.latch && r.latch.emptyObserved) {
      r.tree.cleanup();
      this.runs.delete(runId);
    }
  }
  hasRun(runId: string): boolean {
    return this.runs.has(runId);
  }
}

function min3(a: bigint, b: bigint, c: bigint): bigint {
  return a < b ? (a < c ? a : c) : b < c ? b : c;
}

function canonicalGuardInput(input: GuardInput): string {
  return JSON.stringify(input);
}

export { GUARD_LEASE_MS };
export function makeGuardInput(v: Json): GuardInput {
  return validateGuardInput(v);
}
export { SchemaError };
