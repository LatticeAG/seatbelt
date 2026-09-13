// The authoritative sequencer (spec §2, §3, §7). One sequencer serializes
// reservations, markers, cancellations, cap changes, breaker changes, and
// stops. A single SQLite BEGIN IMMEDIATE transaction is the serialization
// point; expiry releases are committed inside the same serialized pass before
// the mutation they precede.

import { Fault } from "./errors.js";
import type { Response } from "./errors.js";
import { okResponse, errResponse } from "./errors.js";
import type { Json } from "./canon.js";
import { jcsBytes, SchemaError, jcs } from "./canon.js";
import { D, HASH_DOMAINS, SIGN_DOMAINS, sha256Hex, verifyDigest } from "./crypto.js";
import type {
  Action, Breaker, Budget, Capability, EventData, EventBody, Head, HostState,
  Intent, Outcome, PolicyBundle, Reason, ResourceCaps, Run, Sample,
  SignedEvent, Stop, Trust, EvidenceRef, Policy,
} from "./schema.js";
import { GENESIS_PREV, validateParams, VersionError } from "./schema.js";
import type { Method, Input } from "./schema.js";
import { GUEST_ONLY_METHODS, READONLY_METHODS } from "./schema.js";
import type { Store } from "./store.js";
import { eventHash, blobToJ } from "./store.js";
import {
  DIMS, spendToVec, vecToSpend, vecAdd, vecLe, vecIsZero, vecExceeds,
  type SpendVec, vecZero,
} from "./spend.js";
import { MAX_RESERVED_PER_RUN } from "./profile.js";
import type { KernelBackend, RunTree } from "./kernel.js";
import type { GuardTickEvent } from "./guard.js";
import type { AdapterPort } from "./adapter.js";
import { actionHashOf, sealedIntentOf, quoteHashOf } from "./adapter.js";
import type { ObjectStore } from "./objects.js";
import type { EmergencyFile } from "./emergency.js";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { Buffer } from "node:buffer";

export type Surface = "control" | "fd3";

export interface Caller {
  surface: Surface;
  /** authenticated principal: uid_<n> on control, cap_<capability_id> on fd3 */
  principal: string;
  uid: number | null;
  capabilityId: string | null;
}

export interface GuardPort {
  arm(run: Run, resources: ResourceCaps, deadlineMs: bigint): { containmentId: string } | null;
  renew(runId: string, epoch: string, heartbeatDeadlineMs: bigint): void;
  relayStop(msg: {
    runId: string; epoch: string; killId: string; reason: Reason;
    scopeKind: "run" | "budget" | "host"; scopeId: string; actor: string; requestId: string;
  }): void;
  /** drive the guard to `now` and collect latch/sample/empty events */
  drive(now: bigint): GuardTickEvent[];
  isStopped(runId: string): boolean;
  latestSample(runId: string): Sample | null;
}

export interface ExecutorPort {
  startExecution(input: {
    actionId: string; operationKey: string; intent: Intent;
    dispatchSeq: string; deadlineMs: bigint;
  }): void;
}

export interface EngineDeps {
  store: Store;
  installationId: string;
  clock: () => bigint;
  bootId: string;
  sign: (signDomain: string, hashHex: string) => { key_id: string; sig: string };
  kernel: KernelBackend;
  guard: GuardPort;
  adapters: Map<string, AdapterPort>;
  executor: ExecutorPort | null;
  objects: ObjectStore | null;
  emergency: EmergencyFile | null;
  profile: "linux-contained-v1" | "offline-v1";
  watchScopes: { uid: number; budgets: string[] }[];
  liveAdapters: boolean;
  imageStore?: string | null;
  /** fault injection: named commit boundaries that fail (tests only) */
  failpoints?: Set<string>;
  /** supplied when the store was recovered; bounds recovery emissions */
  onFenced?: () => void;
}

const MUTATING: ReadonlySet<Method> = new Set([
  "host.stop", "host.recover", "policy.apply",
  "budget.create", "budget.tighten", "budget.close",
  "run.start", "run.heartbeat", "run.stop",
  "action.reserve", "action.dispatch", "action.cancel", "action.reconcile",
  "breaker.reset", "watch.stop",
]);

const STOP_METHODS: ReadonlySet<Method> = new Set(["host.stop", "run.stop", "watch.stop"]);

type Outcome2 = { ok: true; result: unknown } | { ok: false; fault: Fault };

export class Engine {
  private s: Store;
  private d: EngineDeps;
  private killSeq = 0;
  private probeDeadlines = new Map<string, bigint>();
  private memStops = new Map<string, Stop>();
  private guardLagMs = 0n;
  private auditLagMs = 0n;
  private lastLookupMs = -100000n;
  private lookupBusy = false;
  private pendingTrees = new Map<string, RunTree>();
  private pendingDispatch: { action: Action; intent: Intent; deadline: bigint } | null = null;

  constructor(deps: EngineDeps) {
    this.d = deps;
    this.s = deps.store;
  }

  get store(): Store {
    return this.s;
  }
  private now(): bigint {
    return this.d.clock();
  }
  hostState(): HostState {
    return (this.s.metaGet("host_state") as HostState | undefined) ?? "RECOVERING";
  }
  epoch(): string {
    return (this.s.metaGet("epoch") as string | undefined) ?? "1";
  }
  activePolicyHash(): string | null {
    return (this.s.metaGet("active_policy_hash") as string | null | undefined) ?? null;
  }
  activePolicy(): PolicyBundle | null {
    const h = this.activePolicyHash();
    return h === null ? null : (this.s.policyByHash(h) ?? null);
  }
  treeFor(runId: string): RunTree | undefined {
    return this.pendingTrees.get(runId);
  }
  setExecutor(ex: ExecutorPort | null): void {
    this.d.executor = ex;
  }
  setGuardLag(ms: bigint): void {
    this.guardLagMs = ms;
  }

  private newKillId(): string {
    this.killSeq++;
    return `kill_${this.epoch()}_${this.s.eventHead().seq}_${this.killSeq}`;
  }

  // ---------- event emission & projection ----------

  private emit(data: EventData, actor: string, requestId: string, at: bigint): SignedEvent {
    if (this.d.failpoints?.has("journal_write")) throw new Error("failpoint:journal_write");
    if (this.d.failpoints?.has("stop_journal") && (data.kind === "StopLatched" || data.kind === "StopObserved" || data.kind === "RunEnded")) throw new Error("failpoint:stop_journal");
    const head = this.s.eventHead();
    const seq = (BigInt(head.seq) + 1n).toString();
    const body: EventBody = {
      v: 1, installation_id: this.d.installationId, epoch: this.epoch(), boot_id: this.d.bootId,
      seq, prev: head.hash, at_ms: at.toString(), actor, request_id: requestId,
      policy: this.activePolicyHash(), data,
    };
    const hash = eventHash(body);
    const { key_id, sig } = this.d.sign(SIGN_DOMAINS.EVENT, hash);
    const ev: SignedEvent = { body, hash, key_id, sig };
    this.s.appendEvent(ev);
    this.project(ev);
    return ev;
  }

  /** Apply an event's projection effects inside the current transaction. */
  private project(ev: SignedEvent): void {
    const data = ev.body.data;
    switch (data.kind) {
      case "PolicyActivated": {
        const h = D(HASH_DOMAINS.POLICY, data.policy.body as unknown as Json);
        this.s.putPolicy(h, BigInt(data.policy.body.revision), data.policy);
        this.s.metaSet("active_policy_hash", h);
        break;
      }
      case "BudgetCreated": {
        this.s.putBudget(data.budget);
        this.s.initCounters("budget", data.budget.budget_id, spendToVec(data.budget.limit));
        this.s.insertAncestry(data.budget.parent, data.budget.budget_id);
        this.s.putBreaker({
          budget_id: data.budget.budget_id, state: "CLOSED", revision: "1", reason: null,
          opened_ms: null, probe_id: null, errors: "0", admission_times_ms: [],
        });
        break;
      }
      case "BudgetTightened": {
        const b = this.s.budget(data.budget_id)!;
        this.s.putBudget({ ...b, limit: data.after, revision: data.revision });
        const c = this.s.counter("budget", b.budget_id);
        for (const dim of DIMS) this.s.setCounter("budget", b.budget_id, dim, c.held[dim], c.charged[dim], BigInt(data.after[dim]));
        break;
      }
      case "BudgetClosed": {
        const b = this.s.budget(data.budget_id)!;
        this.s.putBudget({ ...b, state: "CLOSED", revision: data.revision });
        break;
      }
      case "RunCreated": {
        this.s.putRun(data.run);
        this.s.putCapability(data.capability);
        this.s.initCounters("run", data.run.run_id, spendToVec(data.run.limit));
        break;
      }
      case "RunArmed": {
        const r = this.s.run(data.run_id)!;
        const hb = minBig(BigInt(ev.body.at_ms) + 1000n, BigInt(r.deadline_ms));
        this.s.putRun({ ...r, state: "ACTIVE", revision: "2", heartbeat_deadline_ms: hb.toString() });
        break;
      }
      case "HeartbeatAccepted": {
        const r = this.s.run(data.run_id)!;
        this.s.putRun({ ...r, last_beat: data.beat, heartbeat_deadline_ms: data.deadline_ms });
        break;
      }
      case "UsageObserved": {
        const cur = (this.s.metaGet("latest_samples") as Sample[] | undefined) ?? [];
        const rest = cur.filter((x) => x.run_id !== data.sample.run_id);
        rest.push(data.sample);
        rest.sort((a, b) => a.run_id.localeCompare(b.run_id));
        this.s.metaSet("latest_samples", rest as unknown as Json);
        break;
      }
      case "RunEnded": {
        const r = this.s.run(data.run_id)!;
        this.s.putRun({ ...r, state: data.state, revision: (BigInt(r.revision) + 1n).toString() });
        const cap = this.s.capabilityForRun(data.run_id);
        if (cap && !cap.revoked) this.s.putCapability({ ...cap, revoked: true });
        break;
      }
      case "ActionReserved": {
        const a = data.action;
        this.s.putAction(a);
        const run = this.s.run(a.intent.run_id)!;
        const path = this.s.budgetPath(run.budget_id);
        const q = spendToVec(a.quote.upper);
        for (const b of path) {
          const c = this.s.counter("budget", b);
          for (const dim of DIMS) this.s.setCounter("budget", b, dim, c.held[dim] + q[dim], c.charged[dim]);
          this.s.insertHold(a.action_id, "budget", b, q);
        }
        const rc = this.s.counter("run", a.intent.run_id);
        for (const dim of DIMS) this.s.setCounter("run", a.intent.run_id, dim, rc.held[dim] + q[dim], rc.charged[dim]);
        this.s.insertHold(a.action_id, "run", a.intent.run_id, q);
        for (const b of path) {
          const br = this.s.breaker(b)!;
          const window = BigInt(this.activePolicy()!.body.breaker.window_ms);
          const at = BigInt(ev.body.at_ms);
          const kept = br.admission_times_ms.map((t) => BigInt(t)).filter((t) => at - window < t && t <= at);
          kept.push(at);
          this.s.putBreaker({ ...br, admission_times_ms: kept.map((t) => t.toString()) });
        }
        break;
      }
      case "ActionDispatched": {
        const a = this.s.action(data.action_id)!;
        const run = this.s.run(a.intent.run_id)!;
        const path = this.s.budgetPath(run.budget_id);
        const q = spendToVec(a.quote.upper);
        for (const b of path) {
          const c = this.s.counter("budget", b);
          for (const dim of DIMS) this.s.setCounter("budget", b, dim, c.held[dim] - q[dim], c.charged[dim] + q[dim]);
        }
        const rc = this.s.counter("run", run.run_id);
        for (const dim of DIMS) this.s.setCounter("run", run.run_id, dim, rc.held[dim] - q[dim], rc.charged[dim] + q[dim]);
        this.s.deleteHolds(a.action_id);
        this.s.putAction({ ...a, state: "DISPATCHED", dispatch_seq: ev.body.seq });
        {
          const dl = minBig(BigInt(ev.body.at_ms) + BigInt(a.quote.duration_ms), BigInt(run.deadline_ms));
          this.s.outboxPut(a.action_id, "MARKED", this.epoch(), { action_id: a.action_id, deadline_ms: dl.toString() });
        }
        break;
      }
      case "ActionReleased": {
        const a = this.s.action(data.action_id)!;
        if (a.state !== "RESERVED") break; // only RESERVED holds capacity
        const run = this.s.run(a.intent.run_id)!;
        const path = this.s.budgetPath(run.budget_id);
        const q = spendToVec(a.quote.upper);
        for (const b of path) {
          const c = this.s.counter("budget", b);
          for (const dim of DIMS) this.s.setCounter("budget", b, dim, c.held[dim] - q[dim], c.charged[dim]);
        }
        const rc = this.s.counter("run", run.run_id);
        for (const dim of DIMS) this.s.setCounter("run", run.run_id, dim, rc.held[dim] - q[dim], rc.charged[dim]);
        this.s.deleteHolds(a.action_id);
        this.s.putAction({ ...a, state: data.state });
        break;
      }
      case "ActionObserved": {
        const a = this.s.action(data.action_id)!;
        const priorState = a.state;
        const next: Action = {
          ...a, state: data.outcome.status, actual: data.outcome.actual,
          result_hash: data.outcome.result_hash, evidence: [...a.evidence, ...data.outcome.evidence],
        };
        this.s.putAction(next);
        const ob = this.s.outboxGet(a.action_id);
        if (ob) this.s.outboxPut(a.action_id, data.outcome.status === "UNKNOWN" ? "UNKNOWN" : "DONE", this.epoch(), { action_id: a.action_id });
        const run = this.s.run(a.intent.run_id)!;
        const path = this.s.budgetPath(run.budget_id);
        for (const b of path) {
          const br = this.s.breaker(b)!;
          if (data.outcome.status === "SUCCEEDED") {
            if (br.errors !== "0") this.s.putBreaker({ ...br, errors: "0" });
          } else if (priorState === "DISPATCHED") {
            this.s.putBreaker({ ...br, errors: (BigInt(br.errors) + 1n).toString() });
          }
        }
        break;
      }
      case "AdmissionDenied":
        break;
      case "StopLatched":
      case "StopObserved": {
        const st = data.stop;
        const existing = this.s.stop(st.kill_id);
        this.s.putStop(existing ? mergeStop(existing, st) : st);
        if (data.kind === "StopLatched") {
          for (const res of st.results) {
            const r = this.s.run(res.run_id);
            if (!r) continue;
            if (r.state === "ACTIVE" || r.state === "ARMING") {
              this.s.putRun({ ...r, state: "STOPPING", revision: (BigInt(r.revision) + 1n).toString(), kill_id: st.kill_id });
            }
          }
        }
        break;
      }
      case "BreakerChanged":
        this.s.putBreaker(data.breaker);
        break;
      case "ProbeObserved":
        break;
      case "HostChanged":
        this.s.metaSet("host_state", data.state);
        this.s.metaSet("epoch", data.epoch);
        break;
      case "RecoveryGap":
      case "MigrationApplied":
        break;
    }
  }

  private auto(): { actor: string; requestId: string } {
    return { actor: this.d.installationId, requestId: `auto_${(BigInt(this.s.eventHead().seq) + 1n).toString()}` };
  }

  /** Sequencer-front expiry pass: releases + probe deadlines at time t. */
  private expiryPass(now: bigint): void {
    for (const a of this.s.expiredReserved(now)) {
      const { actor, requestId } = this.auto();
      this.emit({ kind: "ActionReleased", action_id: a.action_id, state: "EXPIRED", reason: "EXPIRY" }, actor, requestId, now);
    }
    for (const [budgetId, deadline] of [...this.probeDeadlines.entries()]) {
      const br = this.s.breaker(budgetId);
      if (br && br.state === "HALF_OPEN" && now >= deadline) {
        const { actor, requestId } = this.auto();
        this.emit({ kind: "ProbeObserved", budget_id: budgetId, probe_id: br.probe_id!, success: false }, actor, requestId, now);
        this.emit({
          kind: "BreakerChanged",
          breaker: { ...br, state: "OPEN", revision: (BigInt(br.revision) + 1n).toString(), opened_ms: now.toString(), probe_id: null },
        }, actor, requestId, now);
        this.probeDeadlines.delete(budgetId);
      }
    }
  }

  /** periodic pass: drive guard, observe stops/empties, run pending probes */
  tick(now: bigint): void {
    // daemon liveness: renew every armed run's guard lease; the stored
    // heartbeat deadline is passed through unchanged so guest-facing
    // HEARTBEAT semantics are preserved.
    for (const run of this.s.liveRuns()) {
      if (run.state !== "ACTIVE" && run.state !== "ARMING") continue;
      try {
        this.d.guard.renew(run.run_id, run.epoch, BigInt(run.heartbeat_deadline_ms));
      } catch { /* guard channel failure surfaces through lease expiry */ }
    }
    const events = this.d.guard.drive(now);
    this.s.tx(() => {
      this.expiryPass(now);
      this.applyGuardEvents(events, now);
      for (const run of this.s.liveRuns()) {
        if (run.state !== "STOPPING" || run.kill_id === null) continue;
        const st = this.s.stop(run.kill_id);
        if (!st) continue;
        const sample = this.d.guard.latestSample(run.run_id);
        if (sample && !sample.populated) {
          const res = st.results.map((r) =>
            r.run_id === run.run_id && !r.empty_observed ? { ...r, empty_observed: true, observed_ms: now.toString() } : r);
          const { actor, requestId } = this.auto();
          this.emit({ kind: "StopObserved", stop: { ...st, results: res } }, actor, requestId, now);
          this.emit({ kind: "RunEnded", run_id: run.run_id, state: "STOPPED", exit_code: null }, actor, requestId, now);
          this.d.kernel.releaseUid?.(run.owner_uid);
        }
      }
      // dispatched actions whose execution deadline passed without an outcome
      for (const ob of this.s.outboxPending()) {
        if (ob.state !== "MARKED" && ob.state !== "ATTEMPTED") continue;
        const rec = ob.record as { deadline_ms?: string };
        if (rec.deadline_ms !== undefined && now > BigInt(rec.deadline_ms)) {
          const a = this.s.action(ob.action);
          if (a && a.state === "DISPATCHED") {
            const { actor, requestId } = this.auto();
            this.emit({ kind: "ActionObserved", action_id: a.action_id, outcome: { status: "UNKNOWN", actual: null, result_hash: null, evidence: [] } }, actor, requestId, now);
          }
        }
      }
      for (const br of this.s.breakersAll()) {
        if (br.state !== "HALF_OPEN" || br.probe_id === null) continue;
        const policy = this.activePolicy();
        if (!policy) continue;
        const ok = this.probeAdapter(policy.body, br.probe_id);
        const { actor, requestId } = this.auto();
        this.emit({ kind: "ProbeObserved", budget_id: br.budget_id, probe_id: br.probe_id, success: ok }, actor, requestId, now);
        if (ok) {
          this.emit({
            kind: "BreakerChanged",
            breaker: { ...br, state: "CLOSED", revision: (BigInt(br.revision) + 1n).toString(), reason: null, opened_ms: null, probe_id: null, errors: "0", admission_times_ms: [] },
          }, actor, requestId, now);
        } else {
          this.emit({
            kind: "BreakerChanged",
            breaker: { ...br, state: "OPEN", revision: (BigInt(br.revision) + 1n).toString(), opened_ms: now.toString(), probe_id: null },
          }, actor, requestId, now);
        }
        this.probeDeadlines.delete(br.budget_id);
      }
    });
  }

  private applyGuardEvents(events: GuardTickEvent[], now: bigint): void {
    for (const e of events) {
      const run = this.s.run(e.runId);
      if (!run) continue;
      if (e.kind === "sample" && e.sample) {
        if (run.state === "ARMING" || run.state === "ACTIVE" || run.state === "STOPPING") {
          const { actor, requestId } = this.auto();
          this.emit({ kind: "UsageObserved", sample: e.sample }, actor, requestId, now);
        }
        continue;
      }
      if (e.kind === "stop" && e.stop) {
        const gs = e.stop;
        if (!this.s.stop(gs.killId)) {
          const stopRec: Stop = {
            kill_id: gs.killId, scope: { kind: gs.scopeKind, id: gs.scopeId }, reason: gs.reason,
            requested_ms: gs.requestedMs.toString(), actor: gs.actor, request_id: gs.requestId,
            durable: true, signal_id: null, evidence: [],
            results: [{ run_id: run.run_id, signal_sent: gs.signalSent, empty_observed: gs.emptyObserved, observed_ms: gs.observedMs?.toString() ?? null }],
          };
          this.emit({ kind: "StopLatched", stop: stopRec }, gs.actor, gs.requestId, now);
        }
        this.releaseUndispatched(run, gs.reason, now);
        continue;
      }
      if (e.kind === "empty" && e.stop) {
        const gs = e.stop;
        const st = this.s.stop(gs.killId);
        if (st) {
          const res = st.results.map((r) =>
            r.run_id === run.run_id ? { ...r, signal_sent: r.signal_sent || gs.signalSent, empty_observed: true, observed_ms: now.toString() } : r);
          const { actor, requestId } = this.auto();
          this.emit({ kind: "StopObserved", stop: { ...st, results: res } }, actor, requestId, now);
        }
        const cur = this.s.run(run.run_id)!;
        if (cur.state === "STOPPING") {
          const { actor, requestId } = this.auto();
          this.emit({ kind: "RunEnded", run_id: run.run_id, state: "STOPPED", exit_code: null }, actor, requestId, now);
        }
        this.d.kernel.releaseUid?.(run.owner_uid);
        continue;
      }
      if (e.kind === "fence-overdue") {
        const st = this.s.stop(e.stop!.killId);
        if (st) {
          const { actor, requestId } = this.auto();
          this.emit({ kind: "StopObserved", stop: st }, actor, requestId, now);
        }
        this.fenceHost("CONTAINMENT", now);
      }
    }
  }

  private probeAdapter(policy: Policy, probeId: string): boolean {
    for (const pin of policy.adapters) {
      const a = this.d.adapters.get(pin.adapter);
      if (!a) return false;
      try {
        if (!a.probe(probeId, pin.tariff)) return false;
      } catch {
        return false;
      }
    }
    return true;
  }

  private fenceHost(reason: Reason, now: bigint): void {
    if (this.hostState() === "FENCED") return;
    const { actor, requestId } = this.auto();
    this.emit({ kind: "HostChanged", state: "FENCED", epoch: this.epoch(), boot_id: this.d.bootId, reason }, actor, requestId, now);
    const killId = this.newKillId();
    const live = this.s.liveRuns();
    const stop: Stop = {
      kill_id: killId, scope: { kind: "host", id: this.d.installationId }, reason,
      requested_ms: now.toString(), actor, request_id: requestId, durable: true,
      signal_id: null, evidence: [],
      results: live.map((r) => ({ run_id: r.run_id, signal_sent: false, empty_observed: false, observed_ms: null })),
    };
    this.emit({ kind: "StopLatched", stop }, actor, requestId, now);
    for (const r of live) {
      this.d.guard.relayStop({ runId: r.run_id, epoch: r.epoch, killId, reason, scopeKind: "host", scopeId: this.d.installationId, actor, requestId });
      this.releaseUndispatched(r, reason, now);
    }
    this.d.onFenced?.();
  }

  private releaseUndispatched(run: Run, reason: Reason, now: bigint): void {
    for (const a of this.s.reservedActions(run.run_id)) {
      const { actor, requestId } = this.auto();
      this.emit({ kind: "ActionReleased", action_id: a.action_id, state: "CANCELED", reason }, actor, requestId, now);
    }
  }

  private openBreaker(budgetId: string, reason: Reason, now: bigint, actor: string, requestId: string): void {
    const br = this.s.breaker(budgetId);
    if (!br || br.state === "OPEN") return;
    const nb: Breaker = {
      ...br, state: "OPEN", revision: (BigInt(br.revision) + 1n).toString(),
      reason, opened_ms: now.toString(), probe_id: null,
    };
    this.emit({ kind: "BreakerChanged", breaker: nb }, actor, requestId, now);
    const descendants = this.s.descendantsInclusive(budgetId);
    const affected = this.s.liveRuns().filter((r) => descendants.includes(r.budget_id));
    if (affected.length > 0) {
      const killId = this.newKillId();
      const stop: Stop = {
        kill_id: killId, scope: { kind: "budget", id: budgetId }, reason, requested_ms: now.toString(),
        actor, request_id: requestId, durable: true, signal_id: null, evidence: [],
        results: affected.map((r) => ({ run_id: r.run_id, signal_sent: false, empty_observed: false, observed_ms: null })),
      };
      this.emit({ kind: "StopLatched", stop }, actor, requestId, now);
      for (const r of affected) {
        this.d.guard.relayStop({ runId: r.run_id, epoch: r.epoch, killId, reason, scopeKind: "budget", scopeId: budgetId, actor, requestId });
        this.releaseUndispatched(r, reason, now);
      }
    }
  }

  private stopRun(run: Run, reason: Reason, actor: string, requestId: string, now: bigint, opts: {
    signalId?: string | null; evidence?: EvidenceRef[];
  } = {}): Stop {
    const prior = this.s.stopsForScope("run", run.run_id);
    if (prior.length > 0) return this.refreshStop(prior[0]!, now);
    const killId = this.newKillId();
    const stop: Stop = {
      kill_id: killId, scope: { kind: "run", id: run.run_id }, reason, requested_ms: now.toString(),
      actor, request_id: requestId, durable: true, signal_id: opts.signalId ?? null, evidence: opts.evidence ?? [],
      results: [{ run_id: run.run_id, signal_sent: false, empty_observed: false, observed_ms: null }],
    };
    this.emit({ kind: "StopLatched", stop }, actor, requestId, now);
    this.d.guard.relayStop({
      runId: run.run_id, epoch: run.epoch, killId, reason,
      scopeKind: "run", scopeId: run.run_id, actor, requestId,
    });
    this.releaseUndispatched(run, reason, now);
    return this.s.stop(killId)!;
  }

  private refreshStop(st: Stop, now: bigint): Stop {
    let changed = false;
    const results = st.results.map((r) => {
      const sample = this.d.guard.latestSample(r.run_id);
      if (!r.empty_observed && sample && !sample.populated) {
        changed = true;
        return { ...r, empty_observed: true, observed_ms: sample.at_ms };
      }
      return r;
    });
    const out = { ...st, results };
    if (changed) this.s.putStop(out);
    void now;
    return out;
  }

  // ---------- request pipeline ----------

  /**
   * Handle one already-framed request value. Returns the Response union;
   * INVALID_FRAME is produced by the transport layer before this point.
   */
  handle(caller: Caller, rawRequest: unknown): Response {
    let req: { request_id: string; method: Method; params: unknown };
    try {
      const env = rawRequest as { v?: unknown; request_id?: unknown; method?: unknown; params?: unknown };
      if (typeof env !== "object" || env === null || Array.isArray(env)) throw new SchemaError("request");
      const keys = Object.keys(env);
      for (const k of ["v", "request_id", "method", "params"]) {
        if (!keys.includes(k)) throw new SchemaError(`request missing ${k}`);
      }
      for (const k of keys) {
        if (!["v", "request_id", "method", "params"].includes(k)) throw new SchemaError(`request unknown ${k}`);
      }
      if (env.v !== 1) {
        if (typeof env.v === "number" && Number.isSafeInteger(env.v)) throw new VersionError();
        throw new SchemaError("request.v");
      }
      if (typeof env.request_id !== "string" || !/^[a-z][a-z0-9_-]{0,63}$/.test(env.request_id)) throw new SchemaError("request_id");
      const method = env.method;
      if (typeof method !== "string" || !(METHOD_LIST as readonly string[]).includes(method)) throw new SchemaError("method");
      const params = validateParams(method as Method, env.params);
      req = { request_id: env.request_id, method: method as Method, params };
    } catch (e) {
      const rid = extractRequestId(rawRequest);
      if (e instanceof VersionError) return errResponse(rid, new Fault("VERSION_UNSUPPORTED"));
      if (e instanceof Fault) return errResponse(rid, e);
      return errResponse(rid, new Fault("INVALID_SCHEMA"));
    }
    try {
      const out = this.dispatch(caller, req);
      return out.ok ? okResponse(req.request_id, out.result) : errResponse(req.request_id, out.fault);
    } catch (e) {
      if (e instanceof Fault) return errResponse(req.request_id, e);
      if (e instanceof SchemaError) return errResponse(req.request_id, new Fault("INVALID_SCHEMA"));
      throw e;
    }
  }

  private dispatch(caller: Caller, req: { request_id: string; method: Method; params: unknown }): Outcome2 {
    const policy = this.activePolicy();
    const roles = this.roles(caller, policy);
    if (caller.surface === "control" && roles.size === 0) {
      const bootstrapping = policy === null && ["policy.apply", "host.status", "metrics.read", "events.read", "breaker.get", "budget.get", "run.get", "action.get", "evidence.export"].includes(req.method);
      if (!bootstrapping) throw new Fault("UNAUTHENTICATED");
    }

    // surface validity: guest-only methods exist only on fd 3
    if (caller.surface === "control" && GUEST_ONLY_METHODS.includes(req.method)) throw new Fault("FORBIDDEN");
    let cap: Capability | undefined;
    if (caller.surface === "fd3") {
      cap = caller.capabilityId ? this.s.capability(caller.capabilityId) : undefined;
      if (!cap) throw new Fault("UNAUTHENTICATED");
      if (!(cap.methods as readonly string[]).includes(req.method)) throw new Fault("FORBIDDEN");
    }
    this.authorize(caller, req.method, req.params, roles, policy);

    const mutating = MUTATING.has(req.method);
    let inputHash = "";
    if (mutating) {
      inputHash = D(HASH_DOMAINS.REQUEST, { method: req.method, params: req.params } as unknown as Json);
      const prior = this.s.requestGet(caller.principal, req.request_id);
      if (prior) {
        if (prior.inputHash !== inputHash) throw new Fault("IDEMPOTENCY_CONFLICT");
        return blobToJ<{ ok: boolean; result?: unknown; fault?: { code: never } }>(prior.result) as never as Outcome2;
      }
    }

    const host = this.hostState();
    if (host === "FENCED") {
      if (!(READONLY_METHODS.includes(req.method) || STOP_METHODS.has(req.method) || req.method === "host.recover")) {
        throw new Fault("HOST_FENCED");
      }
    } else if (host === "RECOVERING") {
      if (!(READONLY_METHODS.includes(req.method) || STOP_METHODS.has(req.method))) throw new Fault("BUSY");
    }

    const exec = (): Outcome2 => {
      const now = this.now();
      if (mutating) this.expiryPass(now);
      return this.invoke(caller, req.method, req.params, req.request_id, now, roles, cap);
    };

    let out: Outcome2;
    if (STOP_METHODS.has(req.method)) {
      try {
        out = this.s.tx(exec);
      } catch (e) {
        if (e instanceof Fault && (e.code === "AUDIT_UNAVAILABLE" || e.code === "HOST_FENCED")) throw e;
        // journal failure on a stop → emergency path still latches + signals
        out = this.emergencyStop(caller, req.method, req.params, this.now());
      }
    } else {
      try {
        out = this.s.tx(exec);
      } catch (e) {
        if (e instanceof Fault) throw e;
        // durable-audit failure: fence the host in memory and try emergency slots
        this.auditFailure(this.now());
        throw new Fault("AUDIT_UNAVAILABLE");
      }
    }

    if (mutating) {
      const toStore = { ok: out.ok, result: out.ok ? out.result : null, fault: out.ok ? null : out.fault.toJSON() };
      const bytes = jcsBytes(toStore as unknown as Json);
      this.s.tx(() => {
        this.s.requestPut(caller.principal, req.request_id, inputHash, bytes, BigInt(this.s.eventHead().seq));
      });
    }
    return out;
  }

  /** Stop path when durable audit fails: latch in memory, signal guard, slot. */
  private emergencyStop(caller: Caller, method: Method, params: unknown, now: bigint): Outcome2 {
    const scope: Stop["scope"] = method === "host.stop"
      ? { kind: "host", id: this.d.installationId }
      : method === "watch.stop"
        ? { kind: "budget", id: (params as { budget_id: string }).budget_id }
        : { kind: "run", id: (params as { run_id: string }).run_id };
    const key = `${scope.kind}:${scope.id}`;
    let st = this.memStops.get(key);
    if (!st) {
      const killId = this.newKillId();
      const affected = scope.kind === "run"
        ? [this.s.run(scope.id)].filter((r): r is Run => r !== undefined)
        : scope.kind === "budget"
          ? this.s.liveRuns().filter((r) => this.s.budgetPath(r.budget_id).includes(scope.id))
          : this.s.liveRuns();
      st = {
        kill_id: killId, scope, reason: method === "watch.stop" ? "WATCH" : (params as { reason?: Reason }).reason ?? "OPERATOR",
        requested_ms: now.toString(), actor: caller.principal, request_id: "0",
        durable: false, signal_id: method === "watch.stop" ? (params as { signal_id: string }).signal_id : null,
        evidence: method === "watch.stop" ? [(params as { evidence: EvidenceRef }).evidence] : [],
        results: affected.map((r) => ({ run_id: r.run_id, signal_sent: false, empty_observed: false, observed_ms: null })),
      };
      this.memStops.set(key, st);
      for (const r of affected) {
        try {
          this.d.guard.relayStop({ runId: r.run_id, epoch: r.epoch, killId, reason: st.reason, scopeKind: scope.kind, scopeId: scope.id, actor: caller.principal, requestId: killId });
        } catch {
          /* physical stop still attempted */
        }
        try {
          if (this.d.failpoints?.has("emergency_fail")) throw new Error("failpoint:emergency_fail");
          this.d.emergency?.write({
            v: 1, run_id: r.run_id, epoch: r.epoch, boot_id: this.d.bootId, kill_id: killId,
            reason: st.reason, scope_kind: scope.kind, scope_id: scope.id,
            actor: caller.principal, request_id: killId, requested_ms: now.toString(),
            signal_sent: true, empty_observed: false,
          });
        } catch {
          /* R22: both sinks failing leaves incomplete evidence */
        }
      }
    }
    return { ok: true, result: st };
  }

  private roles(caller: Caller, policy: PolicyBundle | null): Set<string> {
    const roles = new Set<string>();
    if (caller.surface === "fd3") {
      roles.add("guest");
      return roles;
    }
    const uid = caller.uid!;
    if (policy) {
      if (policy.body.admin_uids.includes(uid)) roles.add("admin");
      if (policy.body.observer_uids.includes(uid)) roles.add("observer");
      if (policy.body.killer_uids.includes(uid)) roles.add("killer");
      if (policy.body.watch_uids.includes(uid)) roles.add("watch");
    }
    return roles;
  }

  private authorize(caller: Caller, method: Method, params: unknown, roles: Set<string>, policy: PolicyBundle | null): void {
    const has = (r: string) => roles.has(r);
    // bootstrap: before the first policy activation the authenticated control
    // peer provisions the installation (policy.apply + read-only methods).
    if (policy === null && (method === "policy.apply" || READONLY_METHODS.includes(method))) return;
    if (caller.surface === "fd3") {
      if (method === "run.stop" && (params as { reason?: string }).reason === "OPERATOR") throw new Fault("FORBIDDEN");
      return;
    }
    switch (method) {
      case "host.status": case "budget.get": case "run.get": case "action.get":
      case "breaker.get": case "events.read": case "metrics.read":
        if (has("admin") || has("observer") || has("killer")) return;
        throw new Fault("FORBIDDEN");
      case "evidence.export": {
        if (has("admin")) return;
        if (has("observer") && (params as { disclosure?: string }).disclosure === "METADATA") return;
        throw new Fault("FORBIDDEN");
      }
      case "host.stop":
        if (has("admin") || has("killer")) return;
        throw new Fault("FORBIDDEN");
      case "run.stop": {
        if ((params as { reason?: string }).reason === "SELF_STOP") throw new Fault("FORBIDDEN");
        if (has("admin") || has("killer")) return;
        throw new Fault("FORBIDDEN");
      }
      case "watch.stop": {
        if (!has("watch") && !has("admin")) throw new Fault("FORBIDDEN");
        const budgetId = (params as { budget_id?: string }).budget_id ?? "";
        const scope = this.d.watchScopes.find((w) => w.uid === caller.uid);
        if (!scope || !scope.budgets.includes(budgetId)) throw new Fault("FORBIDDEN");
        return;
      }
      default:
        if (has("admin")) return;
        throw new Fault("FORBIDDEN");
    }
  }

  private invoke(caller: Caller, method: Method, params: unknown, reqId: string, now: bigint, roles: Set<string>, cap?: Capability): Outcome2 {
    switch (method) {
      case "host.status": return ok(this.mHostStatus());
      case "host.stop": return this.mHostStop(caller, reqId, now);
      case "host.recover": return this.mHostRecover(params as Input["host.recover"], now);
      case "policy.apply": return this.mPolicyApply(caller, params as Input["policy.apply"], reqId, now);
      case "budget.create": return this.mBudgetCreate(caller, params as Input["budget.create"], reqId, now);
      case "budget.get": return this.mBudgetGet(params as Input["budget.get"]);
      case "budget.tighten": return this.mBudgetTighten(caller, params as Input["budget.tighten"], reqId, now);
      case "budget.close": return this.mBudgetClose(caller, params as Input["budget.close"], reqId, now);
      case "run.start": return this.mRunStart(caller, params as Input["run.start"], reqId, now);
      case "run.get": return this.mRunGet(params as Input["run.get"], caller, cap);
      case "run.heartbeat": return this.mHeartbeat(caller, params as Input["run.heartbeat"], reqId, now, cap);
      case "run.stop": return this.mRunStop(caller, params as Input["run.stop"], reqId, now, cap);
      case "action.reserve": return this.mActionReserve(caller, params as Input["action.reserve"], reqId, now, cap);
      case "action.dispatch": return this.mActionDispatch(caller, params as Input["action.dispatch"], reqId, now, cap);
      case "action.cancel": return this.mActionCancel(caller, params as Input["action.cancel"], reqId, now, cap);
      case "action.get": return this.mActionGet(params as Input["action.get"], caller, roles, cap);
      case "action.reconcile": return this.mActionReconcile(caller, params as Input["action.reconcile"], reqId, now);
      case "breaker.get": return this.mBreakerGet(params as Input["breaker.get"]);
      case "breaker.reset": return this.mBreakerReset(caller, params as Input["breaker.reset"], reqId, now);
      case "watch.stop": return this.mWatchStop(caller, params as Input["watch.stop"], reqId, now);
      case "events.read": return ok(this.mEventsRead(params as Input["events.read"]));
      case "evidence.export": return this.mEvidenceExport(caller, params as Input["evidence.export"], reqId, now);
      case "metrics.read": return ok(this.mMetricsRead());
    }
  }

  // ---------- host / policy / budgets ----------

  private mHostStatus(): unknown {
    return {
      state: this.hostState(), epoch: this.epoch(), boot_id: this.d.bootId,
      policy: this.activePolicyHash(), head: this.s.eventHead(),
      guard: this.guardLagMs <= 750n ? "READY" : "LOST",
    };
  }

  private mHostStop(caller: Caller, reqId: string, now: bigint): Outcome2 {
    const prior = this.s.stopsForScope("host", this.d.installationId);
    if (prior.length > 0) return ok(this.refreshStop(prior[0]!, now));
    const killId = this.newKillId();
    const live = this.s.liveRuns();
    const stop: Stop = {
      kill_id: killId, scope: { kind: "host", id: this.d.installationId }, reason: "OPERATOR",
      requested_ms: now.toString(), actor: caller.principal, request_id: reqId,
      durable: true, signal_id: null, evidence: [],
      results: live.map((r) => ({ run_id: r.run_id, signal_sent: false, empty_observed: false, observed_ms: null })),
    };
    this.emit({ kind: "HostChanged", state: "FENCED", epoch: this.epoch(), boot_id: this.d.bootId, reason: "OPERATOR" }, caller.principal, reqId, now);
    this.emit({ kind: "StopLatched", stop }, caller.principal, reqId, now);
    for (const r of live) {
      this.d.guard.relayStop({ runId: r.run_id, epoch: r.epoch, killId, reason: "OPERATOR", scopeKind: "host", scopeId: this.d.installationId, actor: caller.principal, requestId: reqId });
      this.releaseUndispatched(r, "OPERATOR", now);
    }
    return ok(this.s.stop(killId)!);
  }

  private mHostRecover(p: Input["host.recover"], now: bigint): Outcome2 {
    if (this.hostState() !== "FENCED") return bad(new Fault("CONFLICT"));
    if (BigInt(p.expected_epoch) !== BigInt(this.epoch())) return bad(new Fault("STALE_REVISION"));
    for (const r of this.s.liveRuns()) {
      const sample = this.d.guard.latestSample(r.run_id);
      if (!sample || sample.populated) return bad(new Fault("CONFLICT"));
    }
    const { actor, requestId } = this.auto();
    this.emit({ kind: "HostChanged", state: "RECOVERING", epoch: this.epoch(), boot_id: this.d.bootId, reason: "OPERATOR" }, actor, requestId, now);
    const recovering = {
      state: "RECOVERING", epoch: this.epoch(), boot_id: this.d.bootId,
      policy: this.activePolicyHash(), head: this.s.eventHead(), guard: "READY",
    };
    this.emit({ kind: "HostChanged", state: "READY", epoch: (BigInt(this.epoch()) + 1n).toString(), boot_id: this.d.bootId, reason: "OPERATOR" }, actor, requestId, now);
    return ok(recovering);
  }

  private mPolicyApply(caller: Caller, p: Input["policy.apply"], reqId: string, now: bigint): Outcome2 {
    const bundle = p.bundle;
    const quorum = this.verifyPolicyQuorum(bundle);
    if (quorum !== null) return bad(quorum);
    const active = this.activePolicy();
    if (active === null) {
      if (BigInt(p.expected_revision) !== 0n) return bad(new Fault("STALE_REVISION"));
      if (bundle.body.revision !== "1" || bundle.body.previous !== null) return bad(new Fault("CONFLICT"));
      this.emit({ kind: "PolicyActivated", policy: bundle }, caller.principal, reqId, now);
      const root: Budget = {
        budget_id: bundle.body.root_budget, parent: null, limit: bundle.body.root_limit,
        held: vecToSpend(vecZero()), charged: vecToSpend(vecZero()), state: "ACTIVE", revision: "1",
      };
      this.emit({ kind: "BudgetCreated", budget: root }, caller.principal, reqId, now);
      return ok({ policy: D(HASH_DOMAINS.POLICY, bundle.body as unknown as Json), revision: "1" });
    }
    const activeHash = this.activePolicyHash()!;
    if (BigInt(p.expected_revision) !== BigInt(active.body.revision)) return bad(new Fault("STALE_REVISION"));
    if (bundle.body.previous !== activeHash) return bad(new Fault("CONFLICT"));
    if (BigInt(bundle.body.revision) !== BigInt(active.body.revision) + 1n) return bad(new Fault("CONFLICT"));
    if (bundle.body.root_budget !== active.body.root_budget) return bad(new Fault("CONFLICT"));
    if (jcs(bundle.body.root_limit as unknown as Json) !== jcs(active.body.root_limit as unknown as Json)) return bad(new Fault("CONFLICT"));
    if (this.s.liveRuns().length > 0 || this.s.allReserved().length > 0) return bad(new Fault("CONFLICT"));
    this.emit({ kind: "PolicyActivated", policy: bundle }, caller.principal, reqId, now);
    return ok({ policy: D(HASH_DOMAINS.POLICY, bundle.body as unknown as Json), revision: bundle.body.revision });
  }

  /** Returns null on success, else the EVIDENCE_INVALID fault. */
  private verifyPolicyQuorum(bundle: PolicyBundle): Fault | null {
    const trust = this.s.metaGet("trust") as unknown as Trust | undefined;
    if (!trust) return new Fault("EVIDENCE_INVALID");
    const bodyHash = D(HASH_DOMAINS.POLICY, bundle.body as unknown as Json);
    const seen = new Set<string>();
    for (const s of bundle.signatures) {
      const principal = trust.principals.find((p) => p.key_id === s.key_id);
      if (!principal) continue;
      if (verifyDigest(SIGN_DOMAINS.POLICY, bodyHash, s.sig, hexToBytes(principal.public_key))) {
        seen.add(principal.principal_id);
      }
    }
    if (seen.size < Number(trust.threshold)) return new Fault("EVIDENCE_INVALID");
    return null;
  }

  private mBudgetCreate(caller: Caller, p: Input["budget.create"], reqId: string, now: bigint): Outcome2 {
    if (!this.activePolicy()) return bad(new Fault("CONFLICT"));
    const parent = this.s.budget(p.parent);
    if (!parent) return bad(new Fault("NOT_FOUND"));
    if (parent.state !== "ACTIVE") return bad(new Fault("CONFLICT"));
    if (this.s.budget(p.budget_id)) return bad(new Fault("CONFLICT"));
    if (this.s.depthOf(p.parent) + 1 > 7) return bad(new Fault("CONFLICT"));
    const b: Budget = {
      budget_id: p.budget_id, parent: p.parent, limit: p.limit,
      held: vecToSpend(vecZero()), charged: vecToSpend(vecZero()), state: "ACTIVE", revision: "1",
    };
    this.emit({ kind: "BudgetCreated", budget: b }, caller.principal, reqId, now);
    return ok(this.s.budget(p.budget_id)!);
  }

  private mBudgetGet(p: Input["budget.get"]): Outcome2 {
    const b = this.s.budget(p.budget_id);
    if (!b) return bad(new Fault("NOT_FOUND"));
    const c = this.s.counter("budget", b.budget_id);
    return ok({ ...b, held: vecToSpend(c.held), charged: vecToSpend(c.charged) });
  }

  private mBudgetTighten(caller: Caller, p: Input["budget.tighten"], reqId: string, now: bigint): Outcome2 {
    const b = this.s.budget(p.budget_id);
    if (!b) return bad(new Fault("NOT_FOUND"));
    if (BigInt(p.expected_revision) !== BigInt(b.revision)) return bad(new Fault("STALE_REVISION"));
    if (b.state !== "ACTIVE") return bad(new Fault("CONFLICT"));
    const c = this.s.counter("budget", b.budget_id);
    const next = spendToVec(p.limit);
    if (!vecLe(next, c.cap)) return bad(new Fault("CONFLICT"));
    if (!vecLe(vecAdd(c.held, c.charged), next)) return bad(new Fault("CONFLICT"));
    this.emit({ kind: "BudgetTightened", budget_id: b.budget_id, before: vecToSpend(c.cap), after: p.limit, revision: (BigInt(b.revision) + 1n).toString() }, caller.principal, reqId, now);
    let saturates = false;
    for (const dim of DIMS) {
      if (c.charged[dim] > 0n && c.charged[dim] === next[dim]) saturates = true;
    }
    if (saturates) this.openBreaker(b.budget_id, "CAP", now, caller.principal, reqId);
    const out = this.s.budget(b.budget_id)!;
    const cc = this.s.counter("budget", b.budget_id);
    return ok({ ...out, held: vecToSpend(cc.held), charged: vecToSpend(cc.charged) });
  }

  private mBudgetClose(caller: Caller, p: Input["budget.close"], reqId: string, now: bigint): Outcome2 {
    const b = this.s.budget(p.budget_id);
    if (!b) return bad(new Fault("NOT_FOUND"));
    if (BigInt(p.expected_revision) !== BigInt(b.revision)) return bad(new Fault("STALE_REVISION"));
    if (b.state !== "ACTIVE") return bad(new Fault("CONFLICT"));
    const c = this.s.counter("budget", b.budget_id);
    if (!vecIsZero(c.held)) return bad(new Fault("CONFLICT"));
    const descendants = this.s.descendantsInclusive(b.budget_id);
    for (const d of descendants) {
      if (d === b.budget_id) continue;
      if (this.s.budget(d)!.state !== "CLOSED") return bad(new Fault("CONFLICT"));
    }
    for (const r of this.s.liveRuns()) {
      if (descendants.includes(r.budget_id)) return bad(new Fault("CONFLICT"));
    }
    this.emit({ kind: "BudgetClosed", budget_id: b.budget_id, revision: (BigInt(b.revision) + 1n).toString() }, caller.principal, reqId, now);
    const out = this.s.budget(b.budget_id)!;
    return ok(out);
  }

  // ---------- runs ----------

  private mRunStart(caller: Caller, p: Input["run.start"], reqId: string, now: bigint): Outcome2 {
    const policy = this.activePolicy();
    if (!policy) return bad(new Fault("CONFLICT"));
    const budget = this.s.budget(p.budget_id);
    if (!budget) return bad(new Fault("NOT_FOUND"));
    if (budget.state !== "ACTIVE") return bad(new Fault("CONFLICT"));
    if (this.s.run(p.run_id)) return bad(new Fault("CONFLICT"));
    const path = this.s.budgetPath(p.budget_id);
    for (const b of path) {
      if (this.s.budget(b)!.state !== "ACTIVE") return bad(new Fault("CONFLICT"));
      if (this.s.breaker(b)!.state !== "CLOSED") return bad(new Fault("BREAKER_OPEN"));
    }
    if (this.s.countRuns(["ARMING", "ACTIVE", "STOPPING"]) >= Number(BigInt(policy.body.max_runs))) return bad(new Fault("BUSY"));
    if (!vecLe(spendToVec(p.limit), spendToVec(policy.body.max_run_limit))) return bad(new Fault("CONFLICT"));
    if (!capsLe(p.resources, policy.body.max_resources)) return bad(new Fault("CONFLICT"));
    // offline-v1 is ledger-only: no runs admitted. linux-contained-v1 needs
    // real host containment; anything else fails closed as UNSUPPORTED_HOST.
    if (this.d.profile !== "linux-contained-v1") return bad(new Fault("UNSUPPORTED_HOST"));
    if (!this.d.kernel.containmentSupported().ok) return bad(new Fault("UNSUPPORTED_HOST"));
    if (this.d.imageStore && !imagePresent(this.d.imageStore, p.launch.image)) return bad(new Fault("ADAPTER_UNAVAILABLE"));
    // containment preflight: the launch descriptor must not assume host/foreign
    // zone lifetimes — executable and argv resolve inside the pinned image,
    // never against host paths such as the control socket.
    if (!launchPreflightOk(p.launch, this.d)) return bad(new Fault("UNSUPPORTED_HOST"));
    const uid = this.d.kernel.allocateUid ? this.d.kernel.allocateUid() : null;
    if (uid === null || uid === undefined) return bad(new Fault("BUSY"));

    const run: Run = {
      run_id: p.run_id, budget_id: p.budget_id, owner_uid: caller.uid ?? 0,
      policy: this.activePolicyHash()!, capability_id: `cap_${p.run_id}`,
      epoch: this.epoch(), boot_id: this.d.bootId, state: "ARMING", revision: "1",
      limit: p.limit, held: vecToSpend(vecZero()), charged: vecToSpend(vecZero()),
      resources: p.resources, start_ms: now.toString(),
      deadline_ms: (now + BigInt(p.resources.wall_ms)).toString(),
      last_beat: "0", heartbeat_deadline_ms: (now + 2000n).toString(), kill_id: null,
    };
    const capability: Capability = {
      capability_id: run.capability_id, run_id: run.run_id, epoch: run.epoch, boot_id: run.boot_id,
      channel_id: `chan_${p.run_id}`,
      methods: ["action.cancel", "action.dispatch", "action.get", "action.reserve", "run.get", "run.heartbeat", "run.stop"],
      revoked: false,
    };
    if (this.d.objects) this.d.objects.putJson(p.launch as unknown as Json);
    const launchHash = sha256Hex(jcsBytes(p.launch as unknown as Json));
    this.emit({ kind: "RunCreated", run, launch_hash: launchHash, capability }, caller.principal, reqId, now);

    try {
      const tree = this.d.kernel.createRunTree(p.run_id, p.resources);
      const arm = this.d.guard.arm(run, p.resources, now + BigInt(p.resources.wall_ms));
      if (arm === null) throw new Error("guard arm refused");
      this.pendingTrees.set(p.run_id, tree);
    } catch {
      const { actor, requestId } = this.auto();
      this.emit({ kind: "RunEnded", run_id: p.run_id, state: "FAILED", exit_code: null }, actor, requestId, now);
      this.d.kernel.releaseUid?.(uid);
      if (this.hostState() === "FENCED") return bad(new Fault("HOST_FENCED"));
      return bad(new Fault("UNSUPPORTED_HOST"));
    }
    this.emit({ kind: "RunArmed", run_id: p.run_id, containment_id: `tree_${p.run_id}` }, caller.principal, reqId, now);
    return ok({ run_id: p.run_id, state: "ACTIVE", revision: "2", kill_id: null });
  }

  private mRunGet(p: Input["run.get"], caller: Caller, cap?: Capability): Outcome2 {
    const run = this.s.run(p.run_id);
    if (caller.surface === "fd3") {
      if (!run || !cap || run.run_id !== cap.run_id) return bad(new Fault("NOT_FOUND"));
    } else if (!run) {
      return bad(new Fault("NOT_FOUND"));
    }
    const samples = (this.s.metaGet("latest_samples") as Sample[] | undefined) ?? [];
    const sample = samples.find((x) => x.run_id === run!.run_id) ?? null;
    const c = this.s.counter("run", run!.run_id);
    return ok({ run: { ...run!, held: vecToSpend(c.held), charged: vecToSpend(c.charged) }, sample });
  }

  private mHeartbeat(caller: Caller, p: Input["run.heartbeat"], reqId: string, now: bigint, cap?: Capability): Outcome2 {
    if (!cap || p.run_id !== cap.run_id) return bad(new Fault("NOT_FOUND"));
    const run = this.s.run(p.run_id);
    if (!run) return bad(new Fault("NOT_FOUND"));
    if (run.state === "ARMING") return bad(new Fault("CONFLICT"));
    if (run.state !== "ACTIVE") return bad(new Fault("STOPPED"));
    if (BigInt(p.beat) !== BigInt(run.last_beat) + 1n) return bad(new Fault("CONFLICT"));
    const deadline = minBig(now + BigInt(this.activePolicy()!.body.heartbeat_ms), BigInt(run.deadline_ms));
    this.emit({ kind: "HeartbeatAccepted", run_id: run.run_id, beat: p.beat, deadline_ms: deadline.toString() }, caller.principal, reqId, now);
    this.d.guard.renew(run.run_id, run.epoch, deadline);
    return ok({ accepted_beat: p.beat, deadline_ms: deadline.toString() });
  }

  private mRunStop(caller: Caller, p: Input["run.stop"], reqId: string, now: bigint, cap?: Capability): Outcome2 {
    const run = this.s.run(p.run_id);
    if (caller.surface === "fd3") {
      if (!run || !cap || run.run_id !== cap.run_id) return bad(new Fault("NOT_FOUND"));
    } else if (!run) {
      return bad(new Fault("NOT_FOUND"));
    }
    const prior = this.s.stopsForScope("run", run.run_id);
    if (prior.length > 0) return ok(this.refreshStop(prior[0]!, now));
    if (run.state === "STOPPED" || run.state === "FINISHED" || run.state === "FAILED") return bad(new Fault("STOPPED"));
    const stop = this.stopRun(run, p.reason, caller.principal, reqId, now);
    return ok(stop);
  }

  // ---------- actions ----------

  private mActionReserve(caller: Caller, p: Input["action.reserve"], reqId: string, now: bigint, cap?: Capability): Outcome2 {
    if (!cap) return bad(new Fault("UNAUTHENTICATED"));
    const run = this.s.run(cap.run_id);
    if (!run) return bad(new Fault("NOT_FOUND"));
    if (run.state !== "ACTIVE") return bad(new Fault("STOPPED"));
    const intent = p.intent;
    if (intent.run_id !== run.run_id) return bad(new Fault("NOT_FOUND"));
    if (this.s.action(p.action_id)) return bad(new Fault("CONFLICT"));
    if (this.s.actionByOperation(intent.operation_id)) return bad(new Fault("CONFLICT"));
    const policy = this.activePolicy()!;
    const pin = policy.body.adapters.find((a) => a.adapter === intent.adapter);
    if (!pin || pin.operation !== intent.operation) return bad(new Fault("ADAPTER_UNAVAILABLE"));
    if (pin.live && !this.d.liveAdapters) return bad(new Fault("ADAPTER_UNAVAILABLE"));
    if (intent.operation === "bounded_call" && !(pin.live && this.d.liveAdapters)) return bad(new Fault("ADAPTER_UNAVAILABLE"));
    const adapter = this.d.adapters.get(intent.adapter);
    if (!adapter) return bad(new Fault("ADAPTER_UNAVAILABLE"));

    const path = this.s.budgetPath(run.budget_id);
    for (const b of path) {
      if (this.s.breaker(b)!.state !== "CLOSED") return bad(new Fault("BREAKER_OPEN"));
    }
    const window = BigInt(policy.body.breaker.window_ms);
    const maxAdm = BigInt(policy.body.breaker.max_admissions);
    const fullAncestors: string[] = [];
    for (const b of path) {
      const br = this.s.breaker(b)!;
      const kept = br.admission_times_ms.map((t) => BigInt(t)).filter((t) => now - window < t && t <= now);
      if (kept.length !== br.admission_times_ms.length) {
        this.s.putBreaker({ ...br, admission_times_ms: kept.map((t) => t.toString()) });
      }
      if (BigInt(kept.length) >= maxAdm) fullAncestors.push(b);
    }
    if (fullAncestors.length > 0) {
      for (const b of fullAncestors) this.openBreaker(b, "RATE", now, caller.principal, reqId);
      this.emit({ kind: "AdmissionDenied", run_id: run.run_id, operation_id: intent.operation_id, code: "RATE_LIMIT", budgets: fullAncestors }, caller.principal, reqId, now);
      return bad(new Fault("RATE_LIMIT"));
    }

    const actionHash = actionHashOf(intent);
    const qres = adapter.quote(intent, pin, actionHash);
    if (!qres.ok) {
      if (qres.error === "UNBOUNDED_COST") return bad(new Fault("UNBOUNDED_COST"));
      if (qres.error === "PRICE_CHANGED") return bad(new Fault("PRICE_CHANGED"));
      return bad(new Fault("ADAPTER_UNAVAILABLE"));
    }
    const quote = qres.quote;
    if (quote.action_hash !== actionHash || quote.adapter !== pin.adapter || quote.tariff !== pin.tariff) return bad(new Fault("ADAPTER_UNAVAILABLE"));
    if (BigInt(quote.duration_ms) > BigInt(pin.max_duration_ms) || BigInt(quote.response_bytes) > BigInt(pin.max_response_bytes)) return bad(new Fault("ADAPTER_UNAVAILABLE"));
    if (quote.upper.calls !== "1") return bad(new Fault("ADAPTER_UNAVAILABLE"));
    if (!vecLe(spendToVec(quote.upper), spendToVec(intent.ceiling))) return bad(new Fault("CEILING_TOO_LOW"));

    const q = spendToVec(quote.upper);
    const deniers: string[] = [];
    for (const b of path) {
      const c = this.s.counter("budget", b);
      if (!vecLe(vecAdd(vecAdd(c.held, c.charged), q), c.cap)) deniers.push(b);
    }
    const rc = this.s.counter("run", run.run_id);
    let runDenied = !vecLe(vecAdd(vecAdd(rc.held, rc.charged), q), rc.cap);
    if (this.s.reservedActions(run.run_id).length >= MAX_RESERVED_PER_RUN) runDenied = true;
    if (runDenied) deniers.push(run.run_id);
    if (deniers.length > 0) {
      this.emit({ kind: "AdmissionDenied", run_id: run.run_id, operation_id: intent.operation_id, code: "CAP_EXCEEDED", budgets: deniers }, caller.principal, reqId, now);
      this.stopRun(run, "CAP", caller.principal, reqId, now);
      return bad(new Fault("CAP_EXCEEDED"));
    }

    const expiresMs = minBig(now + BigInt(policy.body.reservation_ms), BigInt(run.deadline_ms));
    const action: Action = {
      action_id: p.action_id, intent: sealedIntentOf(intent), hash: actionHash,
      quote, quote_hash: quoteHashOf(quote), state: "RESERVED",
      reserve_seq: (BigInt(this.s.eventHead().seq) + 1n).toString(),
      dispatch_seq: null, expires_ms: expiresMs.toString(),
      actual: null, result_hash: null, evidence: [],
    };
    if (this.d.objects) this.d.objects.put(jcsBytes(intent.payload as unknown as Json));
    if (this.d.failpoints?.has("reserve_commit")) throw new Error("failpoint:reserve_commit");
    this.emit({ kind: "ActionReserved", action }, caller.principal, reqId, now);
    return ok({ action_id: action.action_id, state: "RESERVED", upper: quote.upper, actual: null, result_hash: null });
  }

  private mActionDispatch(caller: Caller, p: Input["action.dispatch"], reqId: string, now: bigint, cap?: Capability): Outcome2 {
    if (!cap) return bad(new Fault("UNAUTHENTICATED"));
    const run = this.s.run(cap.run_id);
    if (!run) return bad(new Fault("NOT_FOUND"));
    if (run.state !== "ACTIVE") return bad(new Fault("STOPPED"));
    const a = this.s.action(p.action_id);
    if (!a || a.intent.run_id !== run.run_id) return bad(new Fault("NOT_FOUND"));
    if (a.state === "EXPIRED") return bad(new Fault("EXPIRED"));
    if (a.state !== "RESERVED") return bad(new Fault("CONFLICT"));
    if (now >= BigInt(a.expires_ms)) {
      this.emit({ kind: "ActionReleased", action_id: a.action_id, state: "EXPIRED", reason: "EXPIRY" }, caller.principal, reqId, now);
      return bad(new Fault("EXPIRED"));
    }
    const path = this.s.budgetPath(run.budget_id);
    for (const b of path) {
      if (this.s.breaker(b)!.state !== "CLOSED") return bad(new Fault("BREAKER_OPEN"));
    }
    const policy = this.activePolicy()!;
    const pin = policy.body.adapters.find((x) => x.adapter === a.quote.adapter)!;
    const adapter = this.d.adapters.get(pin.adapter);
    if (!adapter) return bad(new Fault("ADAPTER_UNAVAILABLE"));
    const exeNow = adapterExeHash(adapter);
    if (exeNow !== null && exeNow !== pin.executable_hash) {
      // installed adapter bytes drifted from the pinned digest — fence the host
      this.fenceHost("CONTAINMENT", now);
      return bad(new Fault("ADAPTER_UNAVAILABLE"));
    }
    if (adapter.tariffHash() !== a.quote.tariff) {
      this.emit({ kind: "ActionReleased", action_id: a.action_id, state: "EXPIRED", reason: "PRICE" }, caller.principal, reqId, now);
      return bad(new Fault("PRICE_CHANGED"));
    }
    this.emit({ kind: "ActionDispatched", action_id: a.action_id, upper: a.quote.upper }, caller.principal, reqId, now);

    let runSaturated = false;
    const rc = this.s.counter("run", run.run_id);
    for (const dim of DIMS) {
      if (rc.cap[dim] > 0n && rc.charged[dim] === rc.cap[dim]) runSaturated = true;
    }
    const saturatedBudgets: string[] = [];
    for (const b of path) {
      const c = this.s.counter("budget", b);
      for (const dim of DIMS) {
        if (c.cap[dim] > 0n && c.charged[dim] === c.cap[dim]) {
          saturatedBudgets.push(b);
          break;
        }
      }
    }
    for (const b of saturatedBudgets) this.openBreaker(b, "CAP", now, caller.principal, reqId);
    if (runSaturated && saturatedBudgets.length === 0) this.stopRun(run, "CAP", caller.principal, reqId, now);

    const full = this.s.action(a.action_id)!;
    const intent = this.reconstructIntent(full);
    this.pendingDispatch = {
      action: full, intent,
      deadline: minBig(now + BigInt(full.quote.duration_ms), BigInt(run.deadline_ms)),
    };
    return ok({ action_id: a.action_id, state: "DISPATCHED", upper: full.quote.upper, actual: null, result_hash: null });
  }

  takePendingDispatch(): { action: Action; intent: Intent; deadline: bigint } | null {
    const p = this.pendingDispatch;
    this.pendingDispatch = null;
    return p;
  }

  private reconstructIntent(a: Action): Intent {
    let payload: Intent["payload"] = a.intent.operation === "record"
      ? { kind: "record", value: "" }
      : { kind: "bounded_call", request: "", max_input_tokens: "0", max_output_tokens: "0" };
    if (this.d.objects) {
      try {
        payload = this.d.objects.getJson(a.intent.payload_hash) as Intent["payload"];
      } catch {
        /* sealed intent without available payload — retained as evidence only */
      }
    }
    return { ...a.intent, payload } as Intent;
  }

  private mActionCancel(caller: Caller, p: Input["action.cancel"], reqId: string, now: bigint, cap?: Capability): Outcome2 {
    if (!cap) return bad(new Fault("UNAUTHENTICATED"));
    const run = this.s.run(cap.run_id);
    if (!run) return bad(new Fault("NOT_FOUND"));
    if (run.state !== "ACTIVE") return bad(new Fault("STOPPED"));
    const a = this.s.action(p.action_id);
    if (!a || a.intent.run_id !== run.run_id) return bad(new Fault("NOT_FOUND"));
    if (a.state !== "RESERVED") return bad(new Fault("CONFLICT"));
    this.emit({ kind: "ActionReleased", action_id: a.action_id, state: "CANCELED", reason: "SELF_STOP" }, caller.principal, reqId, now);
    return ok({ action_id: a.action_id, state: "CANCELED", upper: a.quote.upper, actual: null, result_hash: null });
  }

  private mActionGet(p: Input["action.get"], caller: Caller, roles: Set<string>, cap?: Capability): Outcome2 {
    const a = this.s.action(p.action_id);
    if (caller.surface === "fd3") {
      if (!a || !cap || a.intent.run_id !== cap.run_id) return bad(new Fault("NOT_FOUND"));
    } else if (!a) {
      return bad(new Fault("NOT_FOUND"));
    }
    let resultB64: string | null = null;
    const maySee = caller.surface === "fd3" || roles.has("admin");
    if (maySee && a!.result_hash !== null && this.d.objects?.has(a!.result_hash)) {
      resultB64 = Buffer.from(this.d.objects.get(a!.result_hash)).toString("base64url");
    }
    return ok({ action: a, result_b64: resultB64 });
  }

  private mActionReconcile(caller: Caller, p: Input["action.reconcile"], reqId: string, now: bigint): Outcome2 {
    const a = this.s.action(p.action_id);
    if (!a) return bad(new Fault("NOT_FOUND"));
    if (a.state === "SUCCEEDED" || a.state === "FAILED") {
      return ok({ action_id: a.action_id, state: a.state, upper: a.quote.upper, actual: a.actual, result_hash: a.result_hash });
    }
    if (a.state !== "UNKNOWN") return bad(new Fault("CONFLICT"));
    if (this.lookupBusy || now - this.lastLookupMs < 1000n) {
      return ok({ action_id: a.action_id, state: "UNKNOWN", upper: a.quote.upper, actual: a.actual, result_hash: a.result_hash });
    }
    this.lastLookupMs = now;
    const policy = this.activePolicy()!;
    const pin = policy.body.adapters.find((x) => x.adapter === a.quote.adapter)!;
    const adapter = this.d.adapters.get(pin.adapter);
    if (!adapter) return bad(new Fault("ADAPTER_UNAVAILABLE"));
    const opKey = `seatbelt:${this.d.installationId}:${a.intent.operation_id}`;
    let res;
    try {
      this.lookupBusy = true;
      res = adapter.lookup(a.action_id, opKey, a.hash);
    } catch {
      this.lookupBusy = false;
      return ok({ action_id: a.action_id, state: "UNKNOWN", upper: a.quote.upper, actual: a.actual, result_hash: a.result_hash });
    }
    this.lookupBusy = false;
    return this.commitOutcome(a, res.outcome, res.resultBytes, now, caller.principal, reqId);
  }

  /** Commit an adapter outcome (execute completion or certified lookup). */
  commitOutcome(a0: Action, outcome: Outcome, resultBytes: Uint8Array | null, now: bigint, actor: string, requestId: string): Outcome2 {
    const a = this.s.action(a0.action_id)!;
    if (a.state !== "DISPATCHED" && a.state !== "UNKNOWN") {
      return ok({ action_id: a.action_id, state: a.state, upper: a.quote.upper, actual: a.actual, result_hash: a.result_hash });
    }
    if (outcome.actual !== null && vecExceeds(spendToVec(outcome.actual), spendToVec(a.quote.upper))) {
      this.emit({ kind: "ActionObserved", action_id: a.action_id, outcome: { status: "UNKNOWN", actual: outcome.actual, result_hash: outcome.result_hash, evidence: outcome.evidence } }, actor, requestId, now);
      this.fenceHost("PRICE", now);
      return bad(new Fault("BOUND_BREACH"));
    }
    if (resultBytes !== null && outcome.result_hash !== null) {
      if (sha256Hex(resultBytes) !== outcome.result_hash) {
        this.fenceHost("CONTAINMENT", now);
        return bad(new Fault("ADAPTER_UNAVAILABLE"));
      }
      this.d.objects?.put(resultBytes);
    }
    this.emit({ kind: "ActionObserved", action_id: a.action_id, outcome }, actor, requestId, now);
    if (outcome.status === "FAILED" || outcome.status === "UNKNOWN") {
      const run = this.s.run(a.intent.run_id)!;
      const path = this.s.budgetPath(run.budget_id);
      const threshold = BigInt(this.activePolicy()!.body.breaker.consecutive_errors);
      for (const b of path) {
        const br = this.s.breaker(b)!;
        if (BigInt(br.errors) >= threshold) this.openBreaker(b, "PROVIDER_ERRORS", now, actor, requestId);
      }
    }
    const cur = this.s.action(a.action_id)!;
    return ok({ action_id: cur.action_id, state: cur.state, upper: cur.quote.upper, actual: cur.actual, result_hash: cur.result_hash });
  }

  /** Public entry for the daemon executor path (commits in its own tx). */
  deliverOutcome(actionId: string, outcome: Outcome, resultBytes: Uint8Array | null, via: "execute" | "lookup"): Outcome2 {
    const now = this.now();
    return this.s.tx(() => {
      const a = this.s.action(actionId);
      if (!a) return bad(new Fault("NOT_FOUND"));
      const { actor, requestId } = this.auto();
      return this.commitOutcome(a, outcome, resultBytes, now, actor, requestId);
    });
  }

  // ---------- breakers / watch ----------

  private mBreakerGet(p: Input["breaker.get"]): Outcome2 {
    const b = this.s.breaker(p.budget_id);
    if (!b) return bad(new Fault("NOT_FOUND"));
    return ok(b);
  }

  private mBreakerReset(caller: Caller, p: Input["breaker.reset"], reqId: string, now: bigint): Outcome2 {
    const br = this.s.breaker(p.budget_id);
    if (!br) return bad(new Fault("NOT_FOUND"));
    if (BigInt(p.expected_revision) !== BigInt(br.revision)) return bad(new Fault("STALE_REVISION"));
    if (br.state !== "OPEN") return bad(new Fault("CONFLICT"));
    if (br.reason === null || !["RATE", "PROVIDER_ERRORS", "WATCH"].includes(br.reason)) return bad(new Fault("CONFLICT"));
    const policy = this.activePolicy()!;
    if (now < BigInt(br.opened_ms!) + BigInt(policy.body.breaker.cooldown_ms)) return bad(new Fault("CONFLICT"));
    const descendants = this.s.descendantsInclusive(p.budget_id);
    for (const r of this.s.liveRuns()) {
      if (descendants.includes(r.budget_id)) return bad(new Fault("CONFLICT"));
    }
    for (const d of descendants) {
      if (!vecIsZero(this.s.counter("budget", d).held)) return bad(new Fault("CONFLICT"));
    }
    for (const b of this.s.budgetPath(p.budget_id).slice(0, -1)) {
      if (this.s.breaker(b)!.state !== "CLOSED") return bad(new Fault("CONFLICT"));
    }
    const probeId = `probe_${p.budget_id}_${br.revision}`;
    const nb: Breaker = { ...br, state: "HALF_OPEN", revision: (BigInt(br.revision) + 1n).toString(), probe_id: probeId };
    this.emit({ kind: "BreakerChanged", breaker: nb }, caller.principal, reqId, now);
    this.probeDeadlines.set(p.budget_id, now + BigInt(policy.body.breaker.probe_timeout_ms));
    return ok(nb);
  }

  private mWatchStop(caller: Caller, p: Input["watch.stop"], reqId: string, now: bigint): Outcome2 {
    const budget = this.s.budget(p.budget_id);
    if (!budget) return bad(new Fault("NOT_FOUND"));
    const prior = this.s.stopBySignal(p.signal_id);
    if (prior) {
      const same = prior.scope.kind === "budget" && prior.scope.id === p.budget_id &&
        prior.evidence.length === 1 && jcs(prior.evidence[0] as unknown as Json) === jcs(p.evidence as unknown as Json);
      if (!same) return bad(new Fault("IDEMPOTENCY_CONFLICT"));
      return ok(this.refreshStop(prior, now));
    }
    const killId = this.newKillId();
    const descendants = this.s.descendantsInclusive(p.budget_id);
    const affected = this.s.liveRuns().filter((r) => descendants.includes(r.budget_id));
    const stop: Stop = {
      kill_id: killId, scope: { kind: "budget", id: p.budget_id }, reason: "WATCH",
      requested_ms: now.toString(), actor: caller.principal, request_id: reqId,
      durable: true, signal_id: p.signal_id, evidence: [p.evidence],
      results: affected.map((r) => ({ run_id: r.run_id, signal_sent: false, empty_observed: false, observed_ms: null })),
    };
    const br = this.s.breaker(p.budget_id)!;
    if (br.state !== "OPEN") {
      const nb: Breaker = { ...br, state: "OPEN", revision: (BigInt(br.revision) + 1n).toString(), reason: "WATCH", opened_ms: now.toString(), probe_id: null };
      this.emit({ kind: "BreakerChanged", breaker: nb }, caller.principal, reqId, now);
    }
    this.emit({ kind: "StopLatched", stop }, caller.principal, reqId, now);
    for (const r of affected) {
      this.d.guard.relayStop({ runId: r.run_id, epoch: r.epoch, killId, reason: "WATCH", scopeKind: "budget", scopeId: p.budget_id, actor: caller.principal, requestId: reqId });
      this.releaseUndispatched(r, "WATCH", now);
    }
    return ok(this.s.stop(killId)!);
  }

  // ---------- reads / export / metrics ----------

  private mEventsRead(p: Input["events.read"]): unknown {
    const after = BigInt(p.after);
    const limit = Number(BigInt(p.limit));
    const head = this.s.eventHead();
    const out: SignedEvent[] = [];
    let used = 512;
    for (const ev of this.s.eventsAfter(after, limit)) {
      const size = jcsBytes(ev as unknown as Json).length + 8;
      if (out.length === 0 && size > 65536 - used) throw new Fault("EVIDENCE_INVALID");
      if (used + size > 65536) break;
      out.push(ev);
      used += size;
    }
    const next = out.length > 0 ? out[out.length - 1]!.body.seq : p.after;
    return { events: out, next, head };
  }

  private mEvidenceExport(caller: Caller, p: Input["evidence.export"], reqId: string, _now: bigint): Outcome2 {
    void caller;
    void reqId;
    const headAt = (h: Head): boolean =>
      (BigInt(h.seq) === 0n && h.hash === GENESIS_PREV) || this.s.getEvent(BigInt(h.seq))?.hash === h.hash;
    if (!headAt(p.from) || !headAt(p.to) || BigInt(p.from.seq) > BigInt(p.to.seq)) return bad(new Fault("EVIDENCE_INVALID"));
    const trust = this.s.metaGet("trust") as unknown as Trust;
    const build = (events: SignedEvent[]): { body: object; hash: string } => {
      const to = events.length > 0 ? { seq: events[events.length - 1]!.body.seq, hash: events[events.length - 1]!.hash } : p.from;
      const policyHashes = new Set<string>();
      for (const ev of events) {
        if (ev.body.policy !== null) policyHashes.add(ev.body.policy);
        if (ev.body.data.kind === "PolicyActivated") policyHashes.add(D(HASH_DOMAINS.POLICY, ev.body.data.policy.body as unknown as Json));
      }
      const policies: PolicyBundle[] = [];
      for (const h of policyHashes) {
        const pb = this.s.policyByHash(h);
        if (pb) policies.push(pb);
      }
      const referenced = new Set<string>();
      for (const ev of events) {
        const d = ev.body.data;
        if (d.kind === "ActionReserved") referenced.add(d.action.intent.payload_hash);
        if (d.kind === "ActionObserved" && d.outcome.result_hash !== null) referenced.add(d.outcome.result_hash);
      }
      const objects: { hash: string; bytes_b64: string }[] = [];
      const missing: string[] = [];
      for (const h of [...referenced].sort()) {
        if (p.disclosure === "FULL" && this.d.objects?.has(h)) {
          objects.push({ hash: h, bytes_b64: Buffer.from(this.d.objects.get(h)).toString("base64url") });
        } else {
          missing.push(h);
        }
      }
      const body = {
        schema: "seatbelt-evidence/1", installation_id: this.d.installationId,
        from: p.from, to, events, policies, trust, objects, disclosure: p.disclosure, missing,
      };
      return { body, hash: D(HASH_DOMAINS.BUNDLE, body as unknown as Json) };
    };
    const cap = Math.min(128, Number(BigInt(p.to.seq) - BigInt(p.from.seq)));
    let events = this.s.eventsAfter(BigInt(p.from.seq), cap);
    let built = build(events);
    let signed = this.signBundle(built.body, built.hash);
    while (jcsBytes({ body: built.body, hash: built.hash, key_id: signed.key_id, sig: signed.sig } as unknown as Json).length > 65536 && events.length > 0) {
      events = events.slice(0, -1);
      built = build(events);
      signed = this.signBundle(built.body, built.hash);
    }
    const to = (built.body as { to: Head }).to;
    this.s.checkpointPut(BigInt(to.seq), to.hash, null);
    return ok({ body: built.body, hash: built.hash, key_id: signed.key_id, sig: signed.sig });
  }

  private signBundle(body: object, hash: string): { key_id: string; sig: string } {
    void body;
    return this.d.sign(SIGN_DOMAINS.BUNDLE, hash);
  }

  private mMetricsRead(): unknown {
    const root = this.s.budgetsAll().find((b) => b.parent === null);
    const c = root ? this.s.counter("budget", root.budget_id) : { held: vecZero(), charged: vecZero(), cap: vecZero() };
    return {
      runs_active: this.s.countRuns(["ACTIVE"]).toString(),
      runs_stopping: this.s.countRuns(["STOPPING"]).toString(),
      actions_unknown: this.s.actionsByState("UNKNOWN").length.toString(),
      holds: vecToSpend(c.held),
      charged: vecToSpend(c.charged),
      audit_lag_ms: this.auditLagMs.toString(),
      guard_lag_ms: this.guardLagMs.toString(),
    };
  }

  /** Journal failure mid-request: attempt in-memory fence + emergency slots. */
  private auditFailure(now: bigint): void {
    this.memStops.set(`host:${this.d.installationId}`, {
      kill_id: this.newKillId(), scope: { kind: "host", id: this.d.installationId }, reason: "AUDIT",
      requested_ms: now.toString(), actor: this.d.installationId, request_id: "0",
      durable: false, signal_id: null, evidence: [],
      results: this.s.liveRuns().map((r) => ({ run_id: r.run_id, signal_sent: false, empty_observed: false, observed_ms: null })),
    });
    const st = this.memStops.get(`host:${this.d.installationId}`)!;
    for (const r of this.s.liveRuns()) {
      try {
        this.d.guard.relayStop({ runId: r.run_id, epoch: r.epoch, killId: st.kill_id, reason: "AUDIT", scopeKind: "host", scopeId: this.d.installationId, actor: this.d.installationId, requestId: st.kill_id });
      } catch { /* kill attempted regardless */ }
      try {
        this.d.emergency?.write({
          v: 1, run_id: r.run_id, epoch: r.epoch, boot_id: this.d.bootId, kill_id: st.kill_id,
          reason: "AUDIT", scope_kind: "host", scope_id: this.d.installationId,
          actor: this.d.installationId, request_id: st.kill_id, requested_ms: now.toString(),
          signal_sent: true, empty_observed: false,
        });
      } catch { /* incomplete emergency evidence → RecoveryGap at recovery */ }
    }
    try {
      this.s.metaSet("host_state", "FENCED");
    } catch { /* journal broken; in-memory fence below */ }
  }

  /** Guest process exit observed by the daemon: release holds, end the run. */
  guestExit(runId: string, exitCode: number | null): void {
    const now = this.now();
    this.s.tx(() => {
      const run = this.s.run(runId);
      if (!run || (run.state !== "ACTIVE" && run.state !== "ARMING" && run.state !== "STOPPING")) return;
      for (const a of this.s.reservedActions(runId)) {
        const { actor, requestId } = this.auto();
        this.emit({ kind: "ActionReleased", action_id: a.action_id, state: "CANCELED", reason: "NORMAL_EXIT" }, actor, requestId, now);
      }
      for (const a of this.s.actionsByState("DISPATCHED")) {
        if (a.intent.run_id !== runId) continue;
        const { actor, requestId } = this.auto();
        this.emit({ kind: "ActionObserved", action_id: a.action_id, outcome: { status: "UNKNOWN", actual: null, result_hash: null, evidence: [] } }, actor, requestId, now);
      }
      if (run.state !== "STOPPING") {
        const { actor, requestId } = this.auto();
        this.emit({ kind: "RunEnded", run_id: runId, state: "FINISHED", exit_code: exitCode }, actor, requestId, now);
      }
    });
  }

  // ---------- recovery (§7.4) ----------

  /**
   * Deterministic recovery emission: HostChanged(RECOVERING); per prior-epoch
   * live run — EXPIRED releases on undispatched holds, UNKNOWN observations on
   * marked-but-unfinalized actions, RESTART stop + RunEnded(STOPPED) once the
   * tree is observed empty; one RecoveryGap per unimportable emergency group;
   * then epoch-incrementing HostChanged(READY). Never called when durable
   * host state is FENCED.
   */
  recover(now: bigint): void {
    if (this.hostState() === "FENCED") return;
    // stale-restore detection: the sidecar anchor records the highest head this
    // installation durably committed; a db head behind it means a stale backup.
    const anchor = this.s.anchorHead();
    const head = this.s.eventHead();
    if (anchor !== null && (BigInt(anchor.seq) > BigInt(head.seq) || (anchor.seq === head.seq && anchor.hash !== head.hash))) {
      const priorEpoch = this.epoch();
      this.s.tx(() => {
        const { actor, requestId } = this.auto();
        this.emit({ kind: "HostChanged", state: "FENCED", epoch: priorEpoch, boot_id: this.d.bootId, reason: "RESTART" }, actor, requestId, now);
      });
      return;
    }
    const priorEpoch = this.epoch();
    this.s.tx(() => {
      const { actor, requestId } = this.auto();
      this.emit({ kind: "HostChanged", state: "RECOVERING", epoch: priorEpoch, boot_id: this.d.bootId, reason: "RESTART" }, actor, requestId, now);

      // import guard emergency slots: group by kill_id
      const gapRuns: string[] = [];
      if (this.d.emergency) {
        const slots = this.d.emergency.readAll();
        const groups = new Map<string, import("./schema.js").EmergencyPayload[]>();
        let torn = 0;
        for (const s of slots) {
          if (!s.ok) {
            torn++;
            continue;
          }
          const g = groups.get(s.payload.kill_id) ?? [];
          g.push(s.payload);
          groups.set(s.payload.kill_id, g);
        }
        for (const [killId, payloads] of groups) {
          const first = payloads[0]!;
          const consistent = payloads.every((p) =>
            p.scope_kind === first.scope_kind && p.scope_id === first.scope_id && p.reason === first.reason &&
            p.actor === first.actor && p.request_id === first.request_id && p.requested_ms === first.requested_ms);
          if (!consistent) {
            const { actor: a2, requestId: r2 } = this.auto();
            this.emit({ kind: "RecoveryGap", emergency_hash: null, affected_runs: payloads.map((p) => p.run_id) }, a2, r2, now);
            continue;
          }
          const stop: Stop = {
            kill_id: killId, scope: { kind: first.scope_kind, id: first.scope_id }, reason: first.reason,
            requested_ms: first.requested_ms, actor: first.actor, request_id: first.request_id,
            durable: false, signal_id: null, evidence: [],
            results: payloads.map((p) => ({ run_id: p.run_id, signal_sent: p.signal_sent, empty_observed: p.empty_observed, observed_ms: null })),
          };
          if (!this.s.stop(killId)) {
            const { actor: a2, requestId: r2 } = this.auto();
            this.emit({ kind: "StopLatched", stop }, a2, r2, now);
          }
        }
        if (torn > 0) {
          const { actor: a2, requestId: r2 } = this.auto();
          this.emit({ kind: "RecoveryGap", emergency_hash: this.d.emergency.digest(), affected_runs: [] }, a2, r2, now);
        }
      }

      for (const run of this.s.liveRuns()) {
        for (const a of this.s.reservedActions(run.run_id)) {
          const { actor: a2, requestId: r2 } = this.auto();
          this.emit({ kind: "ActionReleased", action_id: a.action_id, state: "EXPIRED", reason: "EXPIRY" }, a2, r2, now);
        }
        for (const a of this.s.actionsByState("DISPATCHED")) {
          if (a.intent.run_id !== run.run_id) continue;
          const { actor: a2, requestId: r2 } = this.auto();
          this.emit({ kind: "ActionObserved", action_id: a.action_id, outcome: { status: "UNKNOWN", actual: null, result_hash: null, evidence: [] } }, a2, r2, now);
        }
        // convert outbox MARKED/ATTEMPTED → UNKNOWN handled via ActionObserved above
        const killId = this.newKillId();
        const stop: Stop = {
          kill_id: killId, scope: { kind: "run", id: run.run_id }, reason: "RESTART",
          requested_ms: now.toString(), actor, request_id: requestId, durable: true, signal_id: null, evidence: [],
          results: [{ run_id: run.run_id, signal_sent: false, empty_observed: false, observed_ms: null }],
        };
        this.emit({ kind: "StopLatched", stop }, actor, requestId, now);
        // tree must be observed empty before STOPPED; the kernel reports it
        const tree = this.pendingTrees.get(run.run_id);
        let empty = true;
        try {
          empty = tree ? !tree.sample().populated && tree.reaped() : true;
        } catch {
          empty = false;
        }
        if (empty) {
          this.emit({ kind: "StopObserved", stop: { ...stop, results: [{ run_id: run.run_id, signal_sent: false, empty_observed: true, observed_ms: now.toString() }] } }, actor, requestId, now);
          this.emit({ kind: "RunEnded", run_id: run.run_id, state: "STOPPED", exit_code: null }, actor, requestId, now);
        } else {
          gapRuns.push(run.run_id);
        }
      }
      if (gapRuns.length > 0) {
        const { actor: a2, requestId: r2 } = this.auto();
        this.emit({ kind: "RecoveryGap", emergency_hash: null, affected_runs: gapRuns }, a2, r2, now);
      }
      const newEpoch = (BigInt(priorEpoch) + 1n).toString();
      this.emit({ kind: "HostChanged", state: "READY", epoch: newEpoch, boot_id: this.d.bootId, reason: "RESTART" }, actor, requestId, now);
    });
  }
}

// ---------- small helpers ----------

const METHOD_LIST = [
  "host.status", "host.stop", "host.recover", "policy.apply",
  "budget.create", "budget.get", "budget.tighten", "budget.close",
  "run.start", "run.get", "run.heartbeat", "run.stop",
  "action.reserve", "action.dispatch", "action.cancel", "action.get", "action.reconcile",
  "breaker.get", "breaker.reset", "watch.stop",
  "events.read", "evidence.export", "metrics.read",
] as const;

function ok(result: unknown): Outcome2 {
  return { ok: true, result };
}
function bad(fault: Fault): Outcome2 {
  return { ok: false, fault };
}
function extractRequestId(raw: unknown): string {
  if (typeof raw === "object" && raw !== null) {
    const r = (raw as { request_id?: unknown }).request_id;
    if (typeof r === "string" && /^[a-z][a-z0-9_-]{0,63}$/.test(r)) return r;
  }
  return "q_invalid";
}
function hexToBytes(h: string): Uint8Array {
  return new Uint8Array(Buffer.from(h, "hex"));
}
function minBig(a: bigint, b: bigint): bigint {
  return a < b ? a : b;
}
function capsLe(a: ResourceCaps, b: ResourceCaps): boolean {
  return BigInt(a.cpu_ms) <= BigInt(b.cpu_ms) && BigInt(a.wall_ms) <= BigInt(b.wall_ms)
    && BigInt(a.memory_bytes) <= BigInt(b.memory_bytes) && BigInt(a.scratch_bytes) <= BigInt(b.scratch_bytes)
    && BigInt(a.tasks) <= BigInt(b.tasks) && BigInt(a.cpu_quota_us) <= BigInt(b.cpu_quota_us)
    && a.cpu_period_us === b.cpu_period_us;
}
function mergeStop(a: Stop, b: Stop): Stop {
  const results = [...a.results];
  for (const r of b.results) {
    const i = results.findIndex((x) => x.run_id === r.run_id);
    if (i === -1) results.push(r);
    else {
      results[i] = {
        run_id: r.run_id,
        signal_sent: results[i]!.signal_sent || r.signal_sent,
        empty_observed: results[i]!.empty_observed || r.empty_observed,
        observed_ms: results[i]!.observed_ms ?? r.observed_ms,
      };
    }
  }
  return { ...a, durable: a.durable || b.durable, results };
}
function adapterExeHash(adapter: AdapterPort): string | null {
  const a = adapter as { exeHash?: () => string };
  return typeof a.exeHash === "function" ? a.exeHash() : null;
}
function launchPreflightOk(launch: { image: string; executable: string; argv: string[] }, d: EngineDeps): boolean {
  // executable must be absolute inside the image; argv entries and the
  // executable must not reference host control-plane paths (the control
  // socket, the seatbelt run dir, or foreign-zone paths).
  if (!launch.executable.startsWith("/")) return false;
  const forbidden = ["/run/seatbelt", "/var/lib/seatbelt", "\x00", "/proc/", "/sys/"];
  const socketDir = d.imageStore ? null : null;
  void socketDir;
  const check = (s: string) => !forbidden.some((f) => s.startsWith(f) || s.includes(f));
  if (!check(launch.executable)) return false;
  return launch.argv.every(check);
}
function imagePresent(dir: string, image: string): boolean {
  try {
    return existsSync(join(dir, image));
  } catch {
    return false;
  }
}
