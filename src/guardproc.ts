// Guard process port + entry point (spec §2.6). The guard is a separate
// process holding kernel handles; the daemon relays arm/renew/stop/get over a
// dedicated framed socket with a per-run command sequence. Daemon channel EOF
// means control loss: the guard latches and kills every run it supervises.

import { spawn } from "node:child_process";
import { createServer, Socket } from "node:net";
import type { Server } from "node:net";
import { existsSync, unlinkSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { jcsBytes, parseJsonStrict } from "./canon.js";
import type { Json } from "./canon.js";
import type { HostConfig, Run, ResourceCaps, Reason, Sample, GuardInput, GuardReply } from "./schema.js";
import { validateGuardInput } from "./schema.js";
import type { KernelBackend } from "./kernel.js";
import { LinuxKernel } from "./kernel.js";
import type { GuardTickEvent } from "./guard.js";
import { GuardCore } from "./guard.js";
import { EmergencyFile } from "./emergency.js";
import type { GuardPort } from "./engine.js";
import { frame } from "./server.js";

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));

/**
 * Daemon-side port to the guard subprocess. arm/renew/stop are GuardInput
 * frames with a per-run seq; the guard's replies carry lease/latch state and
 * its tick pushes bound-firings and samples back to the daemon.
 */
export class GuardProcessPort implements GuardPort {
  private socket: Socket | null = null;
  private server: Server | null = null;
  private queue: GuardTickEvent[] = [];
  private seqs = new Map<string, bigint>();
  private replies = new Map<string, GuardReply>();
  private samples = new Map<string, Sample>();
  private sockPath: string;
  private alive = false;

  constructor(private config: HostConfig, private kernel: KernelBackend) {
    this.sockPath = join(dirname(config.socket), `guard-${process.pid}.sock`);
  }

  async start(): Promise<void> {
    if (existsSync(this.sockPath)) unlinkSync(this.sockPath);
    const entry = join(MODULE_DIR, "guard-entry.js");
    this.server = createServer((s) => {
      this.socket = s;
      let buf = Buffer.alloc(0);
      s.on("data", (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        for (;;) {
          if (buf.length < 4) break;
          const len = buf.readUInt32BE(0);
          if (len > 65536 || buf.length < 4 + len) {
            if (len > 65536) s.destroy();
            break;
          }
          const payload = buf.subarray(4, 4 + len);
          buf = buf.subarray(4 + len);
          this.onFrame(payload);
        }
      });
      s.on("error", () => this.onDeath());
      s.on("close", () => this.onDeath());
    });
    await new Promise<void>((res, rej) => {
      this.server!.once("error", rej);
      this.server!.listen(this.sockPath, () => res());
    });
    const child = spawn(process.execPath, [entry, this.sockPath, this.config.cgroup_root, this.config.emergency_file], {
      stdio: ["ignore", "inherit", "inherit"],
    });
    child.on("exit", () => this.onDeath());
    await this.waitForSocket(5000);
    this.alive = true;
  }

  private waitForSocket(ms: number): Promise<void> {
    return new Promise((res, rej) => {
      const deadline = Date.now() + ms;
      const check = () => {
        if (this.socket) return res();
        if (Date.now() > deadline) return rej(new Error("guard channel timeout"));
        setTimeout(check, 10);
      };
      check();
    });
  }

  private onDeath(): void {
    this.alive = false;
  }

  private onFrame(payload: Buffer): void {
    let msg: Json;
    try {
      msg = parseJsonStrict(payload.toString("utf8"));
    } catch {
      return;
    }
    const m = msg as Record<string, Json>;
    if (m["kind"] === "reply") {
      this.replies.set(m["run_id"] as string, m as unknown as GuardReply);
      if (m["sample"]) this.samples.set(m["run_id"] as string, m["sample"] as unknown as Sample);
      return;
    }
    if (m["kind"] === "tick") {
      for (const e of (m["events"] as unknown as GuardTickEvent[]) ?? []) {
        this.queue.push(e);
        if (e.sample) this.samples.set(e.runId, e.sample);
      }
    }
  }

  private send(runId: string, input: Omit<GuardInput, "seq" | "run_id"> & { run_id?: string }): void {
    const seq = (this.seqs.get(runId) ?? 0n) + 1n;
    this.seqs.set(runId, seq);
    const msg = { ...input, seq: seq.toString(), run_id: runId } as unknown as Json;
    this.socket?.write(frame(jcsBytes(msg)));
  }

  arm(run: Run, resources: ResourceCaps, deadlineMs: bigint): { containmentId: string } | null {
    if (!this.alive) return null;
    const containmentId = `tree_${run.run_id}`;
    this.send(run.run_id, {
      op: "arm", epoch: run.epoch, containment_id: containmentId,
      deadline_ms: deadlineMs.toString(), resources,
    } as Omit<GuardInput, "seq" | "run_id">);
    return { containmentId };
  }

  renew(runId: string, epoch: string, heartbeatDeadlineMs: bigint): void {
    if (!this.alive) return;
    this.send(runId, { op: "renew", epoch, heartbeat_deadline_ms: heartbeatDeadlineMs.toString() } as Omit<GuardInput, "seq" | "run_id">);
  }

  relayStop(msg: {
    runId: string; epoch: string; killId: string; reason: Reason;
    scopeKind: "run" | "budget" | "host"; scopeId: string; actor: string; requestId: string;
  }): void {
    if (!this.alive) return;
    this.send(msg.runId, {
      op: "stop", epoch: msg.epoch, kill_id: msg.killId, reason: msg.reason,
      scope_kind: msg.scopeKind, scope_id: msg.scopeId, actor: msg.actor, request_id: msg.requestId,
    } as Omit<GuardInput, "seq" | "run_id">);
  }

  drive(_now: bigint): GuardTickEvent[] {
    const out = this.queue;
    this.queue = [];
    return out;
  }

  isStopped(runId: string): boolean {
    return this.replies.get(runId)?.stopped ?? false;
  }

  latestSample(runId: string): Sample | null {
    return this.samples.get(runId) ?? null;
  }

  guardAlive(): boolean {
    return this.alive;
  }

  async close(): Promise<void> {
    this.alive = false;
    try {
      this.socket?.destroy();
    } catch { /* ignore */ }
    await new Promise<void>((r) => (this.server ? this.server.close(() => r()) : r()));
    if (existsSync(this.sockPath)) unlinkSync(this.sockPath);
  }
}

// ---------------- guard subprocess entry ----------------

/**
 * Guard subprocess main loop. It attaches to the daemon-created cgroup trees
 * by convention (<cgroup_root>/<run_id>), drives GuardCore on the real
 * monotonic clock, and pushes tick events upstream. On channel EOF it calls
 * daemonEof — control loss latches and kills everything.
 */
export function runGuardEntry(sockPath: string, cgroupRoot: string, emergencyPath: string): void {
  const kernel = new LinuxKernel(cgroupRoot);
  const emergency = new EmergencyFile(emergencyPath);
  const guard = new GuardCore(kernel, emergency, kernel.bootId());
  const trees = new Map<string, ReturnType<KernelBackend["createRunTree"]>>();

  void import("node:net").then(({ connect }) => {
    const socket = connect(sockPath);
    const send = (m: Json) => socket.write(frame(jcsBytes(m)));

    socket.on("connect", () => {
      const timer = setInterval(() => {
        const events = guard.tick(kernel.nowMs());
        if (events.length > 0) send({ kind: "tick", events } as unknown as Json);
      }, 50);
      socket.on("close", () => {
        clearInterval(timer);
        guard.daemonEof(kernel.nowMs());
        const flushed = guard.tick(kernel.nowMs());
        if (flushed.length > 0) {
          try {
            socket.end(frame(jcsBytes({ kind: "tick", events: flushed } as unknown as Json)));
          } catch { /* channel already gone */ }
        }
        process.exit(0);
      });
    });

    let buf = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      for (;;) {
        if (buf.length < 4) break;
        const len = buf.readUInt32BE(0);
        if (len > 65536 || buf.length < 4 + len) break;
        const payload = buf.subarray(4, 4 + len);
        buf = buf.subarray(4 + len);
        let raw: Json;
        try {
          raw = parseJsonStrict(payload.toString("utf8"));
        } catch {
          continue;
        }
        const now = kernel.nowMs();
        try {
          const input = validateGuardInput(raw);
          const reply = handleInput(guard, kernel, trees, input, now);
          send({ kind: "reply", ...(reply as unknown as Record<string, Json>) } as Json);
        } catch {
          /* malformed guard input is dropped; the run stays under its latch */
        }
      }
    });
  });
}

function handleInput(
  guard: GuardCore, kernel: KernelBackend,
  trees: Map<string, ReturnType<KernelBackend["createRunTree"]>>,
  input: GuardInput, now: bigint,
): GuardReply {
  if (input.op === "arm") {
    // guard attaches to the tree the daemon created at <cgroup_root>/<run_id>
    const k = kernel as LinuxKernel;
    const tree = k.openRunTree(input.run_id);
    trees.set(input.run_id, tree);
    return guard.arm(input.run_id, input.epoch, input.containment_id, tree, input.resources, BigInt(input.deadline_ms), now, now);
  }
  return guard.handle(input, now);
}
