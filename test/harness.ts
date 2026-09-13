// Conformance harness (spec §11.1): deterministic clock, simulated kernel,
// in-process guard bound through the engine's GuardPort, and the exact §3.3
// fixture constants (RFC 8032 public test keys — rejected by live
// provisioning; used only here and in offline test profiles).

import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import { Engine, type Caller, type GuardPort, type ExecutorPort } from "../src/engine.js";
import { GuardCore, type GuardTickEvent } from "../src/guard.js";
import { SimKernel, type SimRunTree } from "../src/kernel.js";
import type { KernelBackend } from "../src/kernel.js";
import { Store } from "../src/store.js";
import { ObjectStore } from "../src/objects.js";
import { EmergencyFile } from "../src/emergency.js";
import { TestAdapter, RecordV1Adapter, actionHashOf } from "../src/adapter.js";
import { D, HASH_DOMAINS, SIGN_DOMAINS, sha256Hex, signDigest, privateKeyFromSeed } from "../src/crypto.js";
import { jcs, jcsBytes } from "../src/canon.js";
import type { Json } from "../src/canon.js";
import type { Response } from "../src/errors.js";
import type {
  Intent, Policy, PolicyBundle, Trust, Head, SignedEvent, Outcome, Spend,
  Launch, ResourceCaps, Reason, Sample, Run,
} from "../src/schema.js";
import { verifyBundle, type VerifyResult } from "../src/verify.js";

// ---------- §3.3 exact constants ----------

export const B = "00000000-0000-4000-8000-000000000001";
export const Z = "0".repeat(64);
export const SEED1 = hexBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
export const SEED2 = hexBytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
export const SEED3 = hexBytes("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
export const KEY_A = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
export const KEY_B = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
export const KEY_C = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";

export const V = (m = "0", i = "0", o = "0", c = "0"): Spend => ({ microusd: m, input_tokens: i, output_tokens: o, calls: c });
export const R: ResourceCaps = {
  cpu_ms: "1000", wall_ms: "10000", memory_bytes: "268435456", scratch_bytes: "16777216",
  tasks: "32", cpu_quota_us: "100000", cpu_period_us: "100000",
};
export const PIN = {
  adapter: "record_v1",
  executable_hash: D("fixture", { exe: "record-v1" } as unknown as Json),
  tariff: D("fixture", { tariff: "free-call" } as unknown as Json),
  operation: "record" as const,
  max_payload_bytes: "16384", max_response_bytes: "16384", max_duration_ms: "1000", live: false,
};
export const P: Policy = {
  v: 1, policy_id: "policy_one", revision: "1", previous: null,
  root_budget: "root", root_limit: V("1000000", "1000", "1000", "100"),
  max_run_limit: V("1000000", "1000", "1000", "100"), max_resources: R,
  admin_uids: [1000], observer_uids: [1001], killer_uids: [1002], watch_uids: [1003],
  adapters: [PIN],
  breaker: { window_ms: "1000", max_admissions: "10", consecutive_errors: "3", cooldown_ms: "30000", probe_timeout_ms: "1000" },
  max_runs: "32", reservation_ms: "5000", heartbeat_ms: "1000", guard_lease_ms: "750", sample_ms: "100",
};
export const PH = D(HASH_DOMAINS.POLICY, P as unknown as Json);
export const TRUST: Trust = {
  v: 1, installation_id: "seatbelt_test", threshold: 2,
  principals: [
    { principal_id: "alice", key_id: "key_a", public_key: KEY_A },
    { principal_id: "bob", key_id: "key_b", public_key: KEY_B },
    { principal_id: "carol", key_id: "key_c", public_key: KEY_C },
  ],
  event_key: { key_id: "event_a", public_key: KEY_A },
};
export const PB: PolicyBundle = {
  body: P,
  signatures: [
    { key_id: "key_a", sig: signDigest(SIGN_DOMAINS.POLICY, PH, privateKeyFromSeed(SEED1)) },
    { key_id: "key_b", sig: signDigest(SIGN_DOMAINS.POLICY, PH, privateKeyFromSeed(SEED2)) },
  ],
};
export const L: Launch = { image: D("fixture", { image: "agent-v1" } as unknown as Json), executable: "/usr/bin/python3", argv: ["/work/agent.py"] };
export const HEAD0: Head = { seq: "0", hash: Z };

export function makeIntent(runId = "run_one", operationId = "operation_one", value = "hello", ceiling: Spend = V("1000000", "1000", "1000", "100")): Intent {
  return {
    v: 1, operation_id: operationId, run_id: runId, adapter: "record_v1", operation: "record",
    payload: { kind: "record", value }, ceiling, evidence: [],
  };
}

function hexBytes(h: string): Uint8Array {
  return new Uint8Array(Buffer.from(h, "hex"));
}

// ---------- harness guard (GuardPort over GuardCore) ----------

export class HarnessGuard implements GuardPort {
  readonly core: GuardCore;
  /** when false the daemon's renewal cannot reach the guard (control loss) */
  liveness = true;
  private seqs = new Map<string, bigint>();
  private kernel: SimKernel;
  private clock: () => bigint;
  constructor(kernel: SimKernel, clock: () => bigint, bootId: string, emergency: EmergencyFile | null = null) {
    this.kernel = kernel;
    this.clock = clock;
    this.core = new GuardCore(kernel, emergency, bootId);
  }
  private next(runId: string): string {
    const s = (this.seqs.get(runId) ?? 0n) + 1n;
    this.seqs.set(runId, s);
    return s.toString();
  }
  arm(run: Run, resources: ResourceCaps, deadlineMs: bigint): { containmentId: string } | null {
    const tree = this.kernel.trees.get(run.run_id);
    if (!tree) return null;
    const now = this.clock();
    const reply = this.core.arm(run.run_id, run.epoch, `tree_${run.run_id}`, tree, resources, deadlineMs, now, now);
    this.seqs.set(run.run_id, 1n); // arm consumed seq 1
    return reply.ok ? { containmentId: `tree_${run.run_id}` } : null;
  }
  renew(runId: string, epoch: string, heartbeatDeadlineMs: bigint): void {
    if (!this.liveness) return; // renewal cannot reach the guard
    this.core.handle({ op: "renew", seq: this.next(runId), run_id: runId, epoch, heartbeat_deadline_ms: heartbeatDeadlineMs.toString() }, this.clock());
  }
  relayStop(msg: { runId: string; epoch: string; killId: string; reason: Reason; scopeKind: "run" | "budget" | "host"; scopeId: string; actor: string; requestId: string }): void {
    this.core.handle({
      op: "stop", seq: this.next(msg.runId), run_id: msg.runId, epoch: msg.epoch, kill_id: msg.killId,
      reason: msg.reason, scope_kind: msg.scopeKind, scope_id: msg.scopeId, actor: msg.actor, request_id: msg.requestId,
    }, this.clock());
  }
  drive(now: bigint): GuardTickEvent[] {
    return this.core.tick(now);
  }
  isStopped(runId: string): boolean {
    return this.core.isStopped(runId);
  }
  latestSample(runId: string): Sample | null {
    return this.core.sampleOf(runId);
  }
  daemonEof(): void {
    this.core.daemonEof(this.clock());
  }
}

// ---------- executor (test) ----------

export class TestExecutor implements ExecutorPort {
  sends: { actionId: string; intent: Intent }[] = [];
  constructor(private engine: Engine, private adapter: TestAdapter) {}
  startExecution(input: { actionId: string; operationKey: string; intent: Intent; dispatchSeq: string; deadlineMs: bigint }): void {
    this.sends.push({ actionId: input.actionId, intent: input.intent });
    const res = this.adapter.pending.get(input.actionId);
    if (res !== undefined) {
      this.adapter.pending.delete(input.actionId);
      this.engine.deliverOutcome(input.actionId, res.outcome, res.resultBytes, "execute");
      return;
    }
    if (this.adapter.nextOutcome !== null) {
      const o = this.adapter.nextOutcome;
      this.adapter.nextOutcome = null;
      this.engine.deliverOutcome(input.actionId, o.outcome, o.resultBytes, "execute");
      return;
    }
    if (this.adapter.autoComplete) {
      const ra = new RecordV1Adapter(this.adapter.tariff);
      const out = ra.execute({ intent: input.intent });
      this.engine.deliverOutcome(input.actionId, out.outcome, out.resultBytes, "execute");
      return;
    }
  }
}

// ---------- harness ----------

export interface Harness {
  engine: Engine;
  store: Store;
  kernel: SimKernel;
  guard: HarnessGuard;
  adapter: TestAdapter;
  executor: TestExecutor;
  objects: ObjectStore;
  dir: string;
  now: bigint;
  setNow(t: bigint): void;
  tick(): void;
  admin: Caller;
  observer: Caller;
  killer: Caller;
  watch: Caller;
  guest(runId: string): Caller;
  call(caller: Caller, method: string, params: unknown, requestId?: string): Response;
  bootstrap(): void;
  startRun(runId?: string, budgetId?: string, requestId?: string, limit?: Spend): void;
  reserve(runId?: string, actionId?: string, intent?: Intent, requestId?: string): Response;
  dispatch(actionId?: string, runId?: string, requestId?: string): Response;
  cancel(actionId?: string, runId?: string, requestId?: string): Response;
  head(): Head;
  exportBundle(from: Head, to: Head, disclosure: "FULL" | "METADATA"): { body: Record<string, unknown>; hash: string; key_id: string; sig: string };
  exportBytes(from: Head, to: Head, disclosure: "FULL" | "METADATA"): Uint8Array;
  verify(bytes: Uint8Array, expected: Head, trust?: Trust): VerifyResult;
  restart(): void;
  tree(runId: string): SimRunTree;
  sends(): number;
  killRequests(runId: string): number;
}

export function makeHarness(opts: {
  policy?: Policy; bundle?: PolicyBundle; trust?: Trust;
  profile?: "linux-contained-v1" | "offline-v1";
  liveAdapters?: boolean;
  startNow?: bigint;
  failpoints?: Set<string>;
  withObjects?: boolean;
  dir?: string;
} = {}): Harness {
  const kernel = new SimKernel(B);
  let now = opts.startNow ?? 1000n;
  const dir = opts.dir ?? join(tmpdir(), `seatbelt-test-${randomBytes(6).toString("hex")}`);
  mkdirSync(dir, { recursive: true });
  const store = new Store(join(dir, "seatbelt.db"));
  const trust = opts.trust ?? TRUST;
  const objects = new ObjectStore(join(dir, "objects"), SEED1.slice(0, 32), trust.installation_id, store);
  const emergency = new EmergencyFile(join(dir, "emergency.bin"));
  const adapter = new TestAdapter("record_v1", PIN.tariff);
  store.metaSet("trust", trust as unknown as Json);
  const guard = new HarnessGuard(kernel, () => now, B, emergency);
  const policy = opts.policy ?? P;

  function buildEngine(): Engine {
    const e = new Engine({
      store,
      installationId: trust.installation_id,
      clock: () => now,
      bootId: B,
      sign: (domain, hashHex) => ({ key_id: "event_a", sig: signDigest(domain, hashHex, privateKeyFromSeed(SEED1)) }),
      kernel,
      guard,
      adapters: new Map([["record_v1", adapter]]),
      executor: null,
      objects: opts.withObjects === false ? null : objects,
      emergency,
      profile: opts.profile ?? "linux-contained-v1",
      watchScopes: [{ uid: 1003, budgets: ["project"] }],
      liveAdapters: opts.liveAdapters ?? false,
      imageStore: null,
      ...(opts.failpoints !== undefined ? { failpoints: opts.failpoints } : {}),
    });
    e.setExecutor(new TestExecutor(e, adapter));
    return e;
  }

  const engine = buildEngine();
  const executor = () => (h.engine as unknown as { d: { executor: ExecutorPort | null } }).d.executor as TestExecutor;

  const admin: Caller = { surface: "control", principal: "uid_1000", uid: 1000, capabilityId: null };
  const observer: Caller = { surface: "control", principal: "uid_1001", uid: 1001, capabilityId: null };
  const killer: Caller = { surface: "control", principal: "uid_1002", uid: 1002, capabilityId: null };
  const watch: Caller = { surface: "control", principal: "uid_1003", uid: 1003, capabilityId: null };

  let seq = 0;
  const call = (caller: Caller, method: string, params: unknown, requestId?: string): Response => {
    const r = h.engine.handle(caller, { v: 1, request_id: requestId ?? `q_${++seq}`, method, params });
    const pending = h.engine.takePendingDispatch();
    if (pending) {
      const ex = (h.engine as unknown as { d: { executor: ExecutorPort | null } }).d.executor;
      ex?.startExecution({
        actionId: pending.action.action_id,
        operationKey: `seatbelt:${trust.installation_id}:${pending.intent.operation_id}`,
        intent: pending.intent, dispatchSeq: pending.action.dispatch_seq ?? "0", deadlineMs: pending.deadline,
      });
    }
    return r;
  };

  const h: Harness = {
    engine, store, kernel, guard, adapter,
    get executor() { return executor(); },
    objects, dir,
    get now() { return now; },
    setNow(t: bigint) {
      if (t >= now) now = t;
      kernel.setNow(t);
    },
    tick() { h.engine.tick(now); },
    admin, observer, killer, watch,
    guest(runId: string) {
      return { surface: "fd3", principal: `cap_cap_${runId}`, uid: null, capabilityId: `cap_${runId}` };
    },
    call,
    bootstrap() {
      // daemon boot: recovery reaches READY on a fresh log, then provisioning
      h.engine.recover(now);
      const r = call(admin, "policy.apply", { bundle: opts.bundle ?? PB, expected_revision: "0" }, "q_policy");
      if (!r.ok) throw new Error(`bootstrap policy.apply failed: ${jcs(r as unknown as Json)}`);
      const r2 = call(admin, "budget.create", { budget_id: "project", parent: "root", limit: V("1000000", "1000", "1000", "100") }, "q_create");
      if (!r2.ok) throw new Error(`bootstrap budget.create failed: ${jcs(r2 as unknown as Json)}`);
    },
    startRun(runId = "run_one", budgetId = "project", requestId?: string, limit?: Spend) {
      const r = call(admin, "run.start", {
        run_id: runId, budget_id: budgetId, limit: limit ?? V("1000000", "1000", "1000", "100"),
        resources: R, launch: L,
      }, requestId ?? `q_start_${runId}`);
      if (!r.ok) throw new Error(`run.start failed: ${jcs(r as unknown as Json)}`);
    },
    reserve(runId = "run_one", actionId = "action_one", intent?: Intent, requestId?: string) {
      return call(h.guest(runId), "action.reserve", { action_id: actionId, intent: intent ?? makeIntent(runId) }, requestId);
    },
    dispatch(actionId = "action_one", runId = "run_one", requestId?: string) {
      return call(h.guest(runId), "action.dispatch", { action_id: actionId }, requestId);
    },
    cancel(actionId = "action_one", runId = "run_one", requestId?: string) {
      return call(h.guest(runId), "action.cancel", { action_id: actionId }, requestId);
    },
    head() { return store.eventHead(); },
    exportBundle(from: Head, to: Head, disclosure: "FULL" | "METADATA") {
      const r = call(admin, "evidence.export", { from, to, disclosure });
      if (!r.ok) throw new Error(`export failed: ${jcs(r as unknown as Json)}`);
      return r.result as { body: Record<string, unknown>; hash: string; key_id: string; sig: string };
    },
    exportBytes(from: Head, to: Head, disclosure: "FULL" | "METADATA") {
      return jcsBytes(h.exportBundle(from, to, disclosure) as unknown as Json);
    },
    verify(bytes: Uint8Array, expected: Head, trustArg?: Trust) {
      return verifyBundle(bytes, trustArg ?? trust, expected);
    },
    restart() {
      const e2 = buildEngine();
      e2.recover(now);
      h.engine = e2;
    },
    tree(runId: string) {
      const t = kernel.trees.get(runId);
      if (!t) throw new Error(`no tree ${runId}`);
      return t;
    },
    sends() { return executor().sends.length; },
    killRequests(runId: string) {
      return kernel.trees.get(runId)?.killCount ?? 0;
    },
  };
  return h;
}
