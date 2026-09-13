// Kernel containment backend (spec §2.5). The daemon core talks to an abstract
// owned run tree; the real backend maps it to cgroup v2 files beneath an owned
// domain root, and the harness backend simulates the same contract
// deterministically. There is deliberately no degraded fallback backend: where
// containment cannot be created, run.start fails UNSUPPORTED_HOST.

import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync, rmdirSync, statfsSync } from "node:fs";
import { join } from "node:path";
import { platform, arch } from "node:os";
import type { ResourceCaps } from "./schema.js";

export interface RawSample {
  populated: boolean;
  usageUsec: bigint;       // cpu.stat usage_usec (microseconds)
  memoryCurrent: bigint;   // memory.current bytes
  memoryMaxEvents: bigint; // memory.events "max" counter
  oomEvents: bigint;       // memory.events "oom_kill" counter
  pidsMaxEvents: bigint;   // pids.events "max" counter
}

export interface RunTree {
  readonly containmentId: string;
  /** write 1 to cgroup.kill (or the simulated equivalent) */
  kill(): void;
  sample(): RawSample;
  /** all pidfds reaped; only meaningful once populated === false */
  reaped(): boolean;
  cleanup(): void;
}

export interface KernelBackend {
  readonly kind: string;
  bootId(): string;
  nowMs(): bigint;
  containmentSupported(): { ok: boolean; reason?: string };
  createRunTree(runId: string, resources: ResourceCaps): RunTree;
  /** release a workload UID back to the pool after empty+reaped */
  releaseUid?(uid: number): void;
  allocateUid?(): number | null;
}

// ---------------- Simulated kernel (conformance harness only) ----------------

export class SimRunTree implements RunTree {
  readonly containmentId: string;
  populated = true;
  killed = false;
  dstate = false; // simulated unkillable task: populated stays true after kill
  killCount = 0;
  usageUsec = 0n;
  memoryCurrent = 0n;
  memoryMaxEvents = 0n;
  oomEvents = 0n;
  pidsMaxEvents = 0n;
  reapedFlag = true;
  removed = false;
  constructor(id: string) {
    this.containmentId = id;
  }
  kill(): void {
    this.killed = true;
    this.killCount++;
    if (!this.dstate) this.populated = false;
  }
  sample(): RawSample {
    return {
      populated: this.populated,
      usageUsec: this.usageUsec,
      memoryCurrent: this.memoryCurrent,
      memoryMaxEvents: this.memoryMaxEvents,
      oomEvents: this.oomEvents,
      pidsMaxEvents: this.pidsMaxEvents,
    };
  }
  reaped(): boolean {
    return this.reapedFlag && !this.populated;
  }
  cleanup(): void {
    this.removed = true;
  }
}

export class SimKernel implements KernelBackend {
  readonly kind = "sim";
  now = 1000n;
  readonly boot: string;
  trees = new Map<string, SimRunTree>();
  supported = true;
  private uidPool: number[];
  constructor(bootId = "00000000-0000-4000-8000-000000000001", uidFirst = 62000, uidCount = 64) {
    this.boot = bootId;
    this.uidPool = Array.from({ length: uidCount }, (_, i) => uidFirst + i);
  }
  bootId(): string {
    return this.boot;
  }
  nowMs(): bigint {
    return this.now;
  }
  setNow(t: bigint): void {
    if (t >= this.now) this.now = t;
  }
  containmentSupported(): { ok: boolean; reason?: string } {
    return this.supported ? { ok: true } : { ok: false, reason: "simulated containment unsupported" };
  }
  allocateUid(): number | null {
    return this.uidPool.shift() ?? null;
  }
  releaseUid(uid: number): void {
    this.uidPool.push(uid);
  }
  createRunTree(runId: string, _resources: ResourceCaps): RunTree {
    const t = new SimRunTree(`tree_${runId}`);
    this.trees.set(runId, t);
    return t;
  }
}

// ---------------- Linux cgroup v2 backend ----------------

function readBig(path: string): bigint {
  return BigInt(readFileSync(path, "utf8").trim());
}
function readKey(path: string, key: string): bigint {
  const txt = readFileSync(path, "utf8");
  for (const line of txt.split("\n")) {
    const [k, v] = line.split(/\s+/);
    if (k === key) return BigInt(v ?? "0");
  }
  return 0n;
}

class LinuxRunTree implements RunTree {
  readonly containmentId: string;
  private dir: string;
  constructor(dir: string, containmentId: string) {
    this.dir = dir;
    this.containmentId = containmentId;
  }
  kill(): void {
    writeFileSync(join(this.dir, "cgroup.kill"), "1");
  }
  sample(): RawSample {
    const populated = readKey(join(this.dir, "cgroup.events"), "populated") !== 0n;
    let usageUsec = 0n;
    try {
      usageUsec = readKey(join(this.dir, "cpu.stat"), "usage_usec");
    } catch {
      /* cpu controller may be absent until enabled */
    }
    return {
      populated,
      usageUsec,
      memoryCurrent: readBig(join(this.dir, "memory.current")),
      memoryMaxEvents: readKey(join(this.dir, "memory.events"), "max"),
      oomEvents: readKey(join(this.dir, "memory.events"), "oom_kill"),
      pidsMaxEvents: readKey(join(this.dir, "pids.events"), "max"),
    };
  }
  reaped(): boolean {
    try {
      return readKey(join(this.dir, "cgroup.events"), "populated") === 0n;
    } catch {
      return false;
    }
  }
  cleanup(): void {
    for (const child of ["guest", "effects"]) {
      try {
        rmdirSync(join(this.dir, child));
      } catch {
        /* still populated or already gone */
      }
    }
    try {
      rmdirSync(this.dir);
    } catch {
      /* populated */
    }
  }
}

export class LinuxKernel implements KernelBackend {
  readonly kind = "linux";
  private cgroupRoot: string;
  private boot: string;
  /** CLOCK_BOOTTIME - CLOCK_MONOTONIC offset sampled at startup, ms. */
  private bootOffsetMs: bigint;
  private uidFirst: number;
  private uidCount: number;
  private uidUsed = new Set<number>();
  constructor(cgroupRoot: string, uidFirst = 0, uidCount = 0) {
    this.cgroupRoot = cgroupRoot;
    this.uidFirst = uidFirst;
    this.uidCount = uidCount;
    this.boot = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
    this.bootOffsetMs = 0n;
  }
  allocateUid(): number | null {
    for (let i = 0; i < this.uidCount; i++) {
      const u = this.uidFirst + i;
      if (!this.uidUsed.has(u)) {
        this.uidUsed.add(u);
        return u;
      }
    }
    return null;
  }
  releaseUid(uid: number): void {
    this.uidUsed.delete(uid);
  }
  /** Attach to an already-created run tree (guard process side). */
  openRunTree(runId: string): RunTree {
    return new LinuxRunTree(join(this.cgroupRoot, runId), `tree_${runId}`);
  }
  /** Install the boot-time offset (from native/boottime at daemon start). */
  setBootOffsetMs(off: bigint): void {
    this.bootOffsetMs = off;
  }
  bootId(): string {
    return this.boot;
  }
  /** CLOCK_BOOTTIME milliseconds (MONOTONIC + suspend offset sampled at start). */
  nowMs(): bigint {
    return process.hrtime.bigint() / 1000000n + this.bootOffsetMs;
  }
  containmentSupported(): { ok: boolean; reason?: string } {
    if (platform() !== "linux") return { ok: false, reason: "not linux" };
    if (arch() !== "x64") return { ok: false, reason: "not x86_64" };
    try {
      const st = statfsSync(this.cgroupRoot);
      if (String((st as unknown as { type?: number }).type) !== "0x27e0eb" && (st as unknown as { type?: number }).type !== 0x27e0eb) {
        return { ok: false, reason: "cgroup_root is not cgroup2" };
      }
    } catch {
      return { ok: false, reason: "cgroup_root missing" };
    }
    try {
      const ctrls = readFileSync(join(this.cgroupRoot, "cgroup.controllers"), "utf8");
      for (const c of ["cpu", "memory", "pids"]) {
        if (!ctrls.split(/\s+/).includes(c)) return { ok: false, reason: `controller ${c} unavailable` };
      }
      const test = join(this.cgroupRoot, ".seatbelt-probe");
      mkdirSync(test);
      rmdirSync(test);
    } catch {
      return { ok: false, reason: "cgroup_root not writable/controllable" };
    }
    return { ok: true };
  }
  createRunTree(runId: string, resources: ResourceCaps): RunTree {
    const dir = join(this.cgroupRoot, runId);
    mkdirSync(dir);
    // enable controllers for children
    writeFileSync(join(this.cgroupRoot, "cgroup.subtree_control"), "+cpu +memory +pids");
    writeFileSync(join(dir, "cgroup.subtree_control"), "+cpu +memory +pids");
    for (const child of ["guest", "effects"]) mkdirSync(join(dir, child));
    writeFileSync(join(dir, "memory.max"), resources.memory_bytes);
    writeFileSync(join(dir, "memory.swap.max"), "0");
    writeFileSync(join(dir, "memory.oom.group"), "1");
    writeFileSync(join(dir, "pids.max"), resources.tasks);
    writeFileSync(join(dir, "cpu.max"), `${resources.cpu_quota_us} ${resources.cpu_period_us}`);
    return new LinuxRunTree(dir, `tree_${runId}`);
  }
}
