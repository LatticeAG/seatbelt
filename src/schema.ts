// Closed-record schema validation (spec §1.2, §1.5, §3.2, §3.4, §5.1).
// Every declared property is required; unknown members are rejected.

import { SchemaError, jcsBytes, MAX_ACTION_PAYLOAD_BYTES, MAX_LAUNCH_BYTES, MAX_POLICY_BODY_BYTES } from "./canon.js";
import type { Json } from "./canon.js";
import {
  checkU, checkId, checkHash, checkSig, checkBootId, checkEvidenceSchema,
  checkUint, isId, isHash, isSig, isU, isBootId,
} from "./scalars.js";
import {
  FIXED_BREAKER, FIXED_TIMINGS, CPU_PERIOD_US, RESOURCE_BOUNDS, MAX_RUNS_MIN,
  MAX_RUNS_MAX, MAX_UID_SET, MAX_ADAPTERS, MAX_EVIDENCE, MAX_ARGV, MAX_ARGV_BYTES,
} from "./profile.js";
import type { Spend } from "./spend.js";

export type { Spend };

export type ResourceCaps = {
  cpu_ms: string; wall_ms: string; memory_bytes: string; scratch_bytes: string;
  tasks: string; cpu_quota_us: string; cpu_period_us: string;
};
export type Signature = { key_id: string; sig: string };
export type EvidenceRef = { zone: string; schema: string; hash: string };
export type BudgetState = "ACTIVE" | "CLOSED";
export type RunState = "ARMING" | "ACTIVE" | "STOPPING" | "STOPPED" | "FINISHED" | "FAILED";
export type ActionState = "RESERVED" | "DISPATCHED" | "SUCCEEDED" | "FAILED" | "UNKNOWN" | "CANCELED" | "EXPIRED";
export type BreakerState = "CLOSED" | "OPEN" | "HALF_OPEN";
export type HostState = "RECOVERING" | "READY" | "FENCED";
export type Reason =
  | "OPERATOR" | "SELF_STOP" | "WATCH" | "CAP" | "CPU" | "WALL" | "MEMORY"
  | "TASKS" | "HEARTBEAT" | "CONTROL_LOST" | "PROVIDER_ERRORS" | "RATE" | "AUDIT"
  | "CONTAINMENT" | "RESTART" | "POLICY" | "PRICE" | "NORMAL_EXIT" | "EXPIRY" | "COUNTER";

export type AdapterPin = {
  adapter: string; executable_hash: string; tariff: string; operation: "record" | "bounded_call";
  max_payload_bytes: string; max_response_bytes: string; max_duration_ms: string; live: boolean;
};
export type BreakerPolicy = {
  window_ms: string; max_admissions: string; consecutive_errors: string; cooldown_ms: string; probe_timeout_ms: string;
};
export type Policy = {
  v: 1; policy_id: string; revision: string; previous: string | null;
  root_budget: string; root_limit: Spend; max_run_limit: Spend; max_resources: ResourceCaps;
  admin_uids: number[]; observer_uids: number[]; killer_uids: number[]; watch_uids: number[];
  adapters: AdapterPin[]; breaker: BreakerPolicy; max_runs: string;
  reservation_ms: string; heartbeat_ms: string; guard_lease_ms: string; sample_ms: string;
};
export type PolicyBundle = { body: Policy; signatures: Signature[] };
export type Budget = {
  budget_id: string; parent: string | null; limit: Spend; held: Spend; charged: Spend;
  state: BudgetState; revision: string;
};
export type Launch = { image: string; executable: string; argv: string[] };
export type Run = {
  run_id: string; budget_id: string; owner_uid: number; policy: string; capability_id: string;
  epoch: string; boot_id: string; state: RunState; revision: string; limit: Spend;
  held: Spend; charged: Spend; resources: ResourceCaps;
  start_ms: string; deadline_ms: string; last_beat: string; heartbeat_deadline_ms: string; kill_id: string | null;
};
export type Payload =
  | { kind: "record"; value: string }
  | { kind: "bounded_call"; request: string; max_input_tokens: string; max_output_tokens: string };
export type Intent = {
  v: 1; operation_id: string; run_id: string; adapter: string; operation: "record" | "bounded_call";
  payload: Payload; ceiling: Spend; evidence: EvidenceRef[];
};
export type Quote = {
  action_hash: string; adapter: string; tariff: string; upper: Spend; duration_ms: string; response_bytes: string;
};
export type SealedIntent = Omit<Intent, "payload"> & { payload_hash: string };
export type Action = {
  action_id: string; intent: SealedIntent; hash: string; quote: Quote; quote_hash: string;
  state: ActionState; reserve_seq: string; dispatch_seq: string | null; expires_ms: string;
  actual: Spend | null; result_hash: string | null; evidence: EvidenceRef[];
};
export const CAPABILITY_METHODS = [
  "run.heartbeat", "run.get", "run.stop", "action.reserve", "action.dispatch", "action.cancel", "action.get",
] as const;
export type CapabilityMethod = (typeof CAPABILITY_METHODS)[number];
export type Capability = {
  capability_id: string; run_id: string; epoch: string; boot_id: string; channel_id: string;
  methods: CapabilityMethod[]; revoked: boolean;
};
export type Breaker = {
  budget_id: string; state: BreakerState; revision: string; reason: Reason | null;
  opened_ms: string | null; probe_id: string | null; errors: string; admission_times_ms: string[];
};
export type StopScope = { kind: "run" | "budget" | "host"; id: string };
export type Stop = {
  kill_id: string; scope: StopScope; reason: Reason; requested_ms: string; actor: string; request_id: string;
  durable: boolean; signal_id: string | null; evidence: EvidenceRef[];
  results: { run_id: string; signal_sent: boolean; empty_observed: boolean; observed_ms: string | null }[];
};
export type Sample = {
  run_id: string; boot_id: string; sample_no: string; at_ms: string; cpu_ms: string;
  memory_bytes: string; memory_max_events: string; oom_events: string; task_max_events: string;
  populated: boolean;
};
export type Outcome = {
  status: "SUCCEEDED" | "FAILED" | "UNKNOWN"; actual: Spend | null;
  result_hash: string | null; evidence: EvidenceRef[];
};

// ---------- Event model ----------

export type EventData =
  | { kind: "PolicyActivated"; policy: PolicyBundle }
  | { kind: "BudgetCreated"; budget: Budget }
  | { kind: "BudgetTightened"; budget_id: string; before: Spend; after: Spend; revision: string }
  | { kind: "BudgetClosed"; budget_id: string; revision: string }
  | { kind: "RunCreated"; run: Run; launch_hash: string; capability: Capability }
  | { kind: "RunArmed"; run_id: string; containment_id: string }
  | { kind: "HeartbeatAccepted"; run_id: string; beat: string; deadline_ms: string }
  | { kind: "UsageObserved"; sample: Sample }
  | { kind: "RunEnded"; run_id: string; state: "STOPPED" | "FINISHED" | "FAILED"; exit_code: number | null }
  | { kind: "ActionReserved"; action: Action }
  | { kind: "ActionDispatched"; action_id: string; upper: Spend }
  | { kind: "ActionReleased"; action_id: string; state: "CANCELED" | "EXPIRED"; reason: Reason }
  | { kind: "ActionObserved"; action_id: string; outcome: Outcome }
  | { kind: "AdmissionDenied"; run_id: string; operation_id: string; code: string; budgets: string[] }
  | { kind: "StopLatched"; stop: Stop }
  | { kind: "StopObserved"; stop: Stop }
  | { kind: "BreakerChanged"; breaker: Breaker }
  | { kind: "ProbeObserved"; budget_id: string; probe_id: string; success: boolean }
  | { kind: "HostChanged"; state: HostState; epoch: string; boot_id: string; reason: Reason }
  | { kind: "RecoveryGap"; emergency_hash: string | null; affected_runs: string[] }
  | { kind: "MigrationApplied"; from: string; to: string; old_head: string; reducer: string };

export type EventBody = {
  v: 1; installation_id: string; epoch: string; boot_id: string; seq: string; prev: string;
  at_ms: string; actor: string; request_id: string; policy: string | null; data: EventData;
};
export type SignedEvent = { body: EventBody; hash: string; key_id: string; sig: string };
export type Head = { seq: string; hash: string };
export const GENESIS_PREV = "0".repeat(64);

export type Trust = {
  v: 1; installation_id: string; threshold: 2;
  principals: { principal_id: string; key_id: string; public_key: string }[];
  event_key: { key_id: string; public_key: string };
};
export type BundleBody = {
  schema: "seatbelt-evidence/1"; installation_id: string; from: Head; to: Head;
  events: SignedEvent[]; policies: PolicyBundle[]; trust: Trust;
  objects: { hash: string; bytes_b64: string }[];
  disclosure: "FULL" | "METADATA"; missing: string[];
};
export type Bundle = { body: BundleBody; hash: string; key_id: string; sig: string };
export type Verification = {
  integrity: "VALID" | "INVALID"; replay: "VALID" | "INCOMPLETE" | "INVALID";
  completeness: "ANCHORED" | "UNANCHORED" | "INCOMPLETE";
  execution: "HOST_ATTESTED"; freshness: "UNKNOWN";
  code: "OK" | "UNANCHORED" | "HEAD_MISMATCH" | "HASH_MISMATCH" | "UNTRUSTED_KEY"
    | "MISSING_OBJECT" | "MISSING_EVENTS" | "SIGNATURE_INVALID" | "REPLAY_MISMATCH" | "SCHEMA_INVALID";
};

export type HostConfig = {
  v: 1; installation_id: string; profile: "linux-contained-v1" | "offline-v1";
  database: string; socket: string; cgroup_root: string; image_store: string;
  event_key_file: string; object_key_file: string; emergency_file: string; uid_first: number; uid_count: number;
  controller_memory_bytes: string; guard_memory_bytes: string; audit_reserve_bytes: string;
  live_adapters: boolean; watch_scopes: { uid: number; budgets: string[] }[];
};
export type EmergencyPayload = {
  v: 1; run_id: string; epoch: string; boot_id: string; kill_id: string; reason: Reason;
  scope_kind: "run" | "budget" | "host"; scope_id: string; actor: string; request_id: string;
  requested_ms: string; signal_sent: boolean; empty_observed: boolean;
};
export type EncryptedObject = { v: 1; hash: string; nonce_b64: string; ciphertext_b64: string; tag_b64: string };
export type MigrationManifest = {
  v: 1; installation_id: string; from: string; to: string; expected_head: Head;
  old_reducer: string; new_reducer: string; tool_hash: string;
  old_trust: string; new_trust: string; preserve_charged: true;
  signatures: Signature[];
};

// ---------- Guard / adapter private protocols (§3.4) ----------

export type GuardInput =
  | { op: "arm"; seq: string; run_id: string; epoch: string; containment_id: string; deadline_ms: string; resources: ResourceCaps }
  | { op: "renew"; seq: string; run_id: string; epoch: string; heartbeat_deadline_ms: string }
  | { op: "stop"; seq: string; run_id: string; epoch: string; kill_id: string; reason: Reason; scope_kind: "run" | "budget" | "host"; scope_id: string; actor: string; request_id: string }
  | { op: "get"; seq: string; run_id: string; epoch: string };
export type GuardReply = {
  seq: string; ok: boolean; code: "OK" | "LATCHED" | "BAD_SEQUENCE" | "BAD_HANDLE";
  lease_until_ms: string; stopped: boolean; sample: Sample | null;
};
export type AdapterInput =
  | { op: "quote"; intent: Intent; tariff: string }
  | { op: "execute"; action_id: string; operation_key: string; intent: Intent; quote: Quote; dispatch_seq: string; deadline_ms: string }
  | { op: "lookup"; action_id: string; operation_key: string; action_hash: string }
  | { op: "probe"; probe_id: string; tariff: string };
export type AdapterReply =
  | { op: "quote"; quote: Quote }
  | { op: "execute" | "lookup"; outcome: Outcome; result_b64: string | null }
  | { op: "probe"; success: boolean }
  | { op: "quote" | "execute" | "lookup" | "probe"; error: "UNBOUNDED_COST" | "PRICE_CHANGED" | "ADAPTER_UNAVAILABLE" };

// ---------- validation helpers ----------

type Obj = { [k: string]: Json };

function isObj(v: unknown): v is Obj {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
/** Require exact closed member set. */
function closed(v: unknown, keys: string[], what: string): Obj {
  if (!isObj(v)) throw new SchemaError(`${what}: expected object`);
  for (const k of keys) {
    if (!(k in v)) throw new SchemaError(`${what}: missing member ${k}`);
  }
  for (const k of Object.keys(v)) {
    if (!keys.includes(k)) throw new SchemaError(`${what}: unknown member ${k}`);
  }
  return v;
}
function enumOf<T extends string>(v: unknown, set: readonly T[], what: string): T {
  if (typeof v !== "string" || !set.includes(v as T)) throw new SchemaError(`${what}: bad enum value`);
  return v as T;
}
function uidList(v: unknown, what: string): number[] {
  if (!Array.isArray(v) || v.length > MAX_UID_SET) throw new SchemaError(`${what}: bad uid set`);
  const out = v.map((x, i) => checkUint(x, `${what}[${i}]`));
  const sorted = [...out].sort((a, b) => a - b);
  if (!out.every((x, i) => x === sorted[i]) || new Set(out).size !== out.length) {
    throw new SchemaError(`${what}: uid set must be sorted and unique`);
  }
  return out;
}
function evidenceList(v: unknown, what: string): EvidenceRef[] {
  if (!Array.isArray(v) || v.length > MAX_EVIDENCE) throw new SchemaError(`${what}: bad evidence list`);
  return v.map((e, i) => validateEvidenceRef(e, `${what}[${i}]`));
}
/** Sets: ASCII-sorted and unique. */
function sortedUniqueStrings(v: unknown, what: string, check: (x: unknown, f: string) => string): string[] {
  if (!Array.isArray(v)) throw new SchemaError(`${what}: expected array`);
  const out = v.map((x, i) => check(x, `${what}[${i}]`));
  const sorted = [...out].sort();
  if (!out.every((x, i) => x === sorted[i]) || new Set(out).size !== out.length) {
    throw new SchemaError(`${what}: set must be ASCII-sorted and unique`);
  }
  return out;
}
function absPath(v: unknown, what: string): string {
  if (typeof v !== "string" || v.length === 0 || !v.startsWith("/") || v.includes("//") || v.includes("/../") || v.endsWith("/..")) {
    throw new SchemaError(`${what}: invalid absolute path`);
  }
  return v;
}

// ---------- public validators ----------

export function validateSpend(v: unknown, what = "spend"): Spend {
  const o = closed(v, ["microusd", "input_tokens", "output_tokens", "calls"], what);
  return {
    microusd: checkU(o.microusd, `${what}.microusd`),
    input_tokens: checkU(o.input_tokens, `${what}.input_tokens`),
    output_tokens: checkU(o.output_tokens, `${what}.output_tokens`),
    calls: checkU(o.calls, `${what}.calls`),
  };
}

export function validateResourceCaps(v: unknown, what = "resources"): ResourceCaps {
  const o = closed(v, ["cpu_ms", "wall_ms", "memory_bytes", "scratch_bytes", "tasks", "cpu_quota_us", "cpu_period_us"], what);
  const r: ResourceCaps = {
    cpu_ms: checkU(o.cpu_ms, `${what}.cpu_ms`),
    wall_ms: checkU(o.wall_ms, `${what}.wall_ms`),
    memory_bytes: checkU(o.memory_bytes, `${what}.memory_bytes`),
    scratch_bytes: checkU(o.scratch_bytes, `${what}.scratch_bytes`),
    tasks: checkU(o.tasks, `${what}.tasks`),
    cpu_quota_us: checkU(o.cpu_quota_us, `${what}.cpu_quota_us`),
    cpu_period_us: checkU(o.cpu_period_us, `${what}.cpu_period_us`),
  };
  for (const k of Object.keys(RESOURCE_BOUNDS) as (keyof typeof RESOURCE_BOUNDS)[]) {
    const b = RESOURCE_BOUNDS[k];
    const val = BigInt(r[k]);
    if (val < b.min || val > b.max) throw new SchemaError(`${what}.${k}: out of profile range`);
  }
  if (r.cpu_period_us !== CPU_PERIOD_US) throw new SchemaError(`${what}.cpu_period_us: must equal ${CPU_PERIOD_US}`);
  return r;
}

export function validateEvidenceRef(v: unknown, what = "evidence"): EvidenceRef {
  const o = closed(v, ["zone", "schema", "hash"], what);
  return {
    zone: checkId(o.zone, `${what}.zone`),
    schema: checkEvidenceSchema(o.schema, `${what}.schema`),
    hash: checkHash(o.hash, `${what}.hash`),
  };
}

export function validateSignature(v: unknown, what = "signature"): Signature {
  const o = closed(v, ["key_id", "sig"], what);
  return { key_id: checkId(o.key_id, `${what}.key_id`), sig: checkSig(o.sig, `${what}.sig`) };
}

export function validateAdapterPin(v: unknown, what = "adapter"): AdapterPin {
  const o = closed(v, ["adapter", "executable_hash", "tariff", "operation", "max_payload_bytes", "max_response_bytes", "max_duration_ms", "live"], what);
  const p: AdapterPin = {
    adapter: checkId(o.adapter, `${what}.adapter`),
    executable_hash: checkHash(o.executable_hash, `${what}.executable_hash`),
    tariff: checkHash(o.tariff, `${what}.tariff`),
    operation: enumOf(o.operation, ["record", "bounded_call"], `${what}.operation`),
    max_payload_bytes: checkU(o.max_payload_bytes, `${what}.max_payload_bytes`),
    max_response_bytes: checkU(o.max_response_bytes, `${what}.max_response_bytes`),
    max_duration_ms: checkU(o.max_duration_ms, `${what}.max_duration_ms`),
    live: (() => { if (typeof o.live !== "boolean") throw new SchemaError(`${what}.live`); return o.live; })(),
  };
  for (const f of ["max_payload_bytes", "max_response_bytes"] as const) {
    const n = BigInt(p[f]);
    if (n < 1n || n > 16384n) throw new SchemaError(`${what}.${f}: out of range 1..16384`);
  }
  const d = BigInt(p.max_duration_ms);
  if (d < 1n || d > 30000n) throw new SchemaError(`${what}.max_duration_ms: out of range 1..30000`);
  return p;
}

export function validateBreakerPolicy(v: unknown, what = "breaker"): BreakerPolicy {
  const o = closed(v, ["window_ms", "max_admissions", "consecutive_errors", "cooldown_ms", "probe_timeout_ms"], what);
  const b: BreakerPolicy = {
    window_ms: checkU(o.window_ms, `${what}.window_ms`),
    max_admissions: checkU(o.max_admissions, `${what}.max_admissions`),
    consecutive_errors: checkU(o.consecutive_errors, `${what}.consecutive_errors`),
    cooldown_ms: checkU(o.cooldown_ms, `${what}.cooldown_ms`),
    probe_timeout_ms: checkU(o.probe_timeout_ms, `${what}.probe_timeout_ms`),
  };
  for (const k of Object.keys(FIXED_BREAKER) as (keyof typeof FIXED_BREAKER)[]) {
    if (b[k] !== FIXED_BREAKER[k]) throw new SchemaError(`${what}.${k}: fixed profile violation`);
  }
  return b;
}

export function validatePolicy(v: unknown, what = "policy"): Policy {
  const o = closed(v, [
    "v", "policy_id", "revision", "previous", "root_budget", "root_limit", "max_run_limit",
    "max_resources", "admin_uids", "observer_uids", "killer_uids", "watch_uids",
    "adapters", "breaker", "max_runs", "reservation_ms", "heartbeat_ms", "guard_lease_ms", "sample_ms",
  ], what);
  if (o.v !== 1) throw new SchemaError(`${what}.v: must be 1`);
  const p: Policy = {
    v: 1,
    policy_id: checkId(o.policy_id, `${what}.policy_id`),
    revision: checkU(o.revision, `${what}.revision`),
    previous: o.previous === null ? null : checkHash(o.previous, `${what}.previous`),
    root_budget: checkId(o.root_budget, `${what}.root_budget`),
    root_limit: validateSpend(o.root_limit, `${what}.root_limit`),
    max_run_limit: validateSpend(o.max_run_limit, `${what}.max_run_limit`),
    max_resources: validateResourceCaps(o.max_resources, `${what}.max_resources`),
    admin_uids: uidList(o.admin_uids, `${what}.admin_uids`),
    observer_uids: uidList(o.observer_uids, `${what}.observer_uids`),
    killer_uids: uidList(o.killer_uids, `${what}.killer_uids`),
    watch_uids: uidList(o.watch_uids, `${what}.watch_uids`),
    adapters: (() => {
      if (!Array.isArray(o.adapters) || o.adapters.length > MAX_ADAPTERS) throw new SchemaError(`${what}.adapters`);
      return o.adapters.map((a, i) => validateAdapterPin(a, `${what}.adapters[${i}]`));
    })(),
    breaker: validateBreakerPolicy(o.breaker, `${what}.breaker`),
    max_runs: checkU(o.max_runs, `${what}.max_runs`),
    reservation_ms: checkU(o.reservation_ms, `${what}.reservation_ms`),
    heartbeat_ms: checkU(o.heartbeat_ms, `${what}.heartbeat_ms`),
    guard_lease_ms: checkU(o.guard_lease_ms, `${what}.guard_lease_ms`),
    sample_ms: checkU(o.sample_ms, `${what}.sample_ms`),
  };
  const mr = BigInt(p.max_runs);
  if (mr < MAX_RUNS_MIN || mr > MAX_RUNS_MAX) throw new SchemaError(`${what}.max_runs: out of range`);
  for (const k of Object.keys(FIXED_TIMINGS) as (keyof typeof FIXED_TIMINGS)[]) {
    if (p[k] !== FIXED_TIMINGS[k]) throw new SchemaError(`${what}.${k}: fixed profile violation`);
  }
  const ids = new Set(p.adapters.map((a) => a.adapter));
  if (ids.size !== p.adapters.length) throw new SchemaError(`${what}.adapters: duplicate adapter id`);
  return p;
}

export function validatePolicyBundle(v: unknown, what = "bundle"): PolicyBundle {
  const o = closed(v, ["body", "signatures"], what);
  const sigs = (() => {
    if (!Array.isArray(o.signatures) || o.signatures.length < 2 || o.signatures.length > 3) {
      throw new SchemaError(`${what}.signatures: need 2..3`);
    }
    return o.signatures.map((s, i) => validateSignature(s, `${what}.signatures[${i}]`));
  })();
  const body = validatePolicy(o.body, `${what}.body`);
  if (jcsBytes(body).length > MAX_POLICY_BODY_BYTES) throw new SchemaError(`${what}.body: exceeds ${MAX_POLICY_BODY_BYTES}`);
  return { body, signatures: sigs };
}

export function validateBudget(v: unknown, what = "budget"): Budget {
  const o = closed(v, ["budget_id", "parent", "limit", "held", "charged", "state", "revision"], what);
  return {
    budget_id: checkId(o.budget_id, `${what}.budget_id`),
    parent: o.parent === null ? null : checkId(o.parent, `${what}.parent`),
    limit: validateSpend(o.limit, `${what}.limit`),
    held: validateSpend(o.held, `${what}.held`),
    charged: validateSpend(o.charged, `${what}.charged`),
    state: enumOf(o.state, ["ACTIVE", "CLOSED"], `${what}.state`),
    revision: checkU(o.revision, `${what}.revision`),
  };
}

export function validateLaunch(v: unknown, what = "launch"): Launch {
  const o = closed(v, ["image", "executable", "argv"], what);
  const l: Launch = {
    image: checkHash(o.image, `${what}.image`),
    executable: absPath(o.executable, `${what}.executable`),
    argv: (() => {
      if (!Array.isArray(o.argv) || o.argv.length > MAX_ARGV) throw new SchemaError(`${what}.argv`);
      return o.argv.map((a, i) => {
        if (typeof a !== "string") throw new SchemaError(`${what}.argv[${i}]`);
        if (new TextEncoder().encode(a).length > MAX_ARGV_BYTES) throw new SchemaError(`${what}.argv[${i}]: too long`);
        return a;
      });
    })(),
  };
  if (jcsBytes(l).length > MAX_LAUNCH_BYTES) throw new SchemaError(`${what}: exceeds ${MAX_LAUNCH_BYTES}`);
  return l;
}

export function validateRun(v: unknown, what = "run"): Run {
  const o = closed(v, [
    "run_id", "budget_id", "owner_uid", "policy", "capability_id", "epoch", "boot_id",
    "state", "revision", "limit", "held", "charged", "resources",
    "start_ms", "deadline_ms", "last_beat", "heartbeat_deadline_ms", "kill_id",
  ], what);
  return {
    run_id: checkId(o.run_id, `${what}.run_id`),
    budget_id: checkId(o.budget_id, `${what}.budget_id`),
    owner_uid: checkUint(o.owner_uid, `${what}.owner_uid`),
    policy: checkHash(o.policy, `${what}.policy`),
    capability_id: checkId(o.capability_id, `${what}.capability_id`),
    epoch: checkU(o.epoch, `${what}.epoch`),
    boot_id: checkBootId(o.boot_id, `${what}.boot_id`),
    state: enumOf(o.state, ["ARMING", "ACTIVE", "STOPPING", "STOPPED", "FINISHED", "FAILED"], `${what}.state`),
    revision: checkU(o.revision, `${what}.revision`),
    limit: validateSpend(o.limit, `${what}.limit`),
    held: validateSpend(o.held, `${what}.held`),
    charged: validateSpend(o.charged, `${what}.charged`),
    resources: validateResourceCaps(o.resources, `${what}.resources`),
    start_ms: checkU(o.start_ms, `${what}.start_ms`),
    deadline_ms: checkU(o.deadline_ms, `${what}.deadline_ms`),
    last_beat: checkU(o.last_beat, `${what}.last_beat`),
    heartbeat_deadline_ms: checkU(o.heartbeat_deadline_ms, `${what}.heartbeat_deadline_ms`),
    kill_id: o.kill_id === null ? null : checkId(o.kill_id, `${what}.kill_id`),
  };
}

export function validatePayload(v: unknown, what = "payload"): Payload {
  if (!isObj(v)) throw new SchemaError(`${what}: expected object`);
  if (!("kind" in v)) throw new SchemaError(`${what}: missing member kind`);
  const kind = enumOf(v.kind, ["record", "bounded_call"], `${what}.kind`);
  let p: Payload;
  if (kind === "record") {
    const oo = closed(v, ["kind", "value"], what);
    if (typeof oo.value !== "string") throw new SchemaError(`${what}.value`);
    p = { kind: "record", value: oo.value };
  } else {
    const oo = closed(v, ["kind", "request", "max_input_tokens", "max_output_tokens"], what);
    if (typeof oo.request !== "string") throw new SchemaError(`${what}.request`);
    p = { kind: "bounded_call", request: oo.request, max_input_tokens: checkU(oo.max_input_tokens, `${what}.max_input_tokens`), max_output_tokens: checkU(oo.max_output_tokens, `${what}.max_output_tokens`) };
  }
  if (jcsBytes(p).length > MAX_ACTION_PAYLOAD_BYTES) throw new SchemaError(`${what}: exceeds ${MAX_ACTION_PAYLOAD_BYTES}`);
  return p;
}

export function validateIntent(v: unknown, what = "intent"): Intent {
  const o = closed(v, ["v", "operation_id", "run_id", "adapter", "operation", "payload", "ceiling", "evidence"], what);
  if (o.v !== 1) throw new SchemaError(`${what}.v: must be 1`);
  const intent: Intent = {
    v: 1,
    operation_id: checkId(o.operation_id, `${what}.operation_id`),
    run_id: checkId(o.run_id, `${what}.run_id`),
    adapter: checkId(o.adapter, `${what}.adapter`),
    operation: enumOf(o.operation, ["record", "bounded_call"], `${what}.operation`),
    payload: validatePayload(o.payload, `${what}.payload`),
    ceiling: validateSpend(o.ceiling, `${what}.ceiling`),
    evidence: evidenceList(o.evidence, `${what}.evidence`),
  };
  if (intent.operation !== intent.payload.kind) throw new SchemaError(`${what}: operation/payload.kind mismatch`);
  return intent;
}

export function validateQuote(v: unknown, what = "quote"): Quote {
  const o = closed(v, ["action_hash", "adapter", "tariff", "upper", "duration_ms", "response_bytes"], what);
  return {
    action_hash: checkHash(o.action_hash, `${what}.action_hash`),
    adapter: checkId(o.adapter, `${what}.adapter`),
    tariff: checkHash(o.tariff, `${what}.tariff`),
    upper: validateSpend(o.upper, `${what}.upper`),
    duration_ms: checkU(o.duration_ms, `${what}.duration_ms`),
    response_bytes: checkU(o.response_bytes, `${what}.response_bytes`),
  };
}

export function validateSealedIntent(v: unknown, what = "intent"): SealedIntent {
  const o = closed(v, ["v", "operation_id", "run_id", "adapter", "operation", "payload_hash", "ceiling", "evidence"], what);
  if (o.v !== 1) throw new SchemaError(`${what}.v: must be 1`);
  return {
    v: 1,
    operation_id: checkId(o.operation_id, `${what}.operation_id`),
    run_id: checkId(o.run_id, `${what}.run_id`),
    adapter: checkId(o.adapter, `${what}.adapter`),
    operation: enumOf(o.operation, ["record", "bounded_call"], `${what}.operation`),
    payload_hash: checkHash(o.payload_hash, `${what}.payload_hash`),
    ceiling: validateSpend(o.ceiling, `${what}.ceiling`),
    evidence: evidenceList(o.evidence, `${what}.evidence`),
  };
}

export function validateAction(v: unknown, what = "action"): Action {
  const o = closed(v, [
    "action_id", "intent", "hash", "quote", "quote_hash", "state", "reserve_seq",
    "dispatch_seq", "expires_ms", "actual", "result_hash", "evidence",
  ], what);
  return {
    action_id: checkId(o.action_id, `${what}.action_id`),
    intent: validateSealedIntent(o.intent, `${what}.intent`),
    hash: checkHash(o.hash, `${what}.hash`),
    quote: validateQuote(o.quote, `${what}.quote`),
    quote_hash: checkHash(o.quote_hash, `${what}.quote_hash`),
    state: enumOf(o.state, ["RESERVED", "DISPATCHED", "SUCCEEDED", "FAILED", "UNKNOWN", "CANCELED", "EXPIRED"], `${what}.state`),
    reserve_seq: checkU(o.reserve_seq, `${what}.reserve_seq`),
    dispatch_seq: o.dispatch_seq === null ? null : checkU(o.dispatch_seq, `${what}.dispatch_seq`),
    expires_ms: checkU(o.expires_ms, `${what}.expires_ms`),
    actual: o.actual === null ? null : validateSpend(o.actual, `${what}.actual`),
    result_hash: o.result_hash === null ? null : checkHash(o.result_hash, `${what}.result_hash`),
    evidence: evidenceList(o.evidence, `${what}.evidence`),
  };
}

export function validateCapability(v: unknown, what = "capability"): Capability {
  const o = closed(v, ["capability_id", "run_id", "epoch", "boot_id", "channel_id", "methods", "revoked"], what);
  const methods = sortedUniqueStrings(o.methods, `${what}.methods`, (x, f) => {
    if (typeof x !== "string" || !(CAPABILITY_METHODS as readonly string[]).includes(x)) throw new SchemaError(f);
    return x;
  }) as CapabilityMethod[];
  if (typeof o.revoked !== "boolean") throw new SchemaError(`${what}.revoked`);
  return {
    capability_id: checkId(o.capability_id, `${what}.capability_id`),
    run_id: checkId(o.run_id, `${what}.run_id`),
    epoch: checkU(o.epoch, `${what}.epoch`),
    boot_id: checkBootId(o.boot_id, `${what}.boot_id`),
    channel_id: checkId(o.channel_id, `${what}.channel_id`),
    methods,
    revoked: o.revoked,
  };
}

const REASONS: readonly Reason[] = [
  "OPERATOR", "SELF_STOP", "WATCH", "CAP", "CPU", "WALL", "MEMORY", "TASKS",
  "HEARTBEAT", "CONTROL_LOST", "PROVIDER_ERRORS", "RATE", "AUDIT", "CONTAINMENT",
  "RESTART", "POLICY", "PRICE", "NORMAL_EXIT", "EXPIRY", "COUNTER",
];
export function validateReason(v: unknown, what = "reason"): Reason {
  return enumOf(v, REASONS, what);
}

export function validateBreaker(v: unknown, what = "breaker"): Breaker {
  const o = closed(v, ["budget_id", "state", "revision", "reason", "opened_ms", "probe_id", "errors", "admission_times_ms"], what);
  return {
    budget_id: checkId(o.budget_id, `${what}.budget_id`),
    state: enumOf(o.state, ["CLOSED", "OPEN", "HALF_OPEN"], `${what}.state`),
    revision: checkU(o.revision, `${what}.revision`),
    reason: o.reason === null ? null : validateReason(o.reason, `${what}.reason`),
    opened_ms: o.opened_ms === null ? null : checkU(o.opened_ms, `${what}.opened_ms`),
    probe_id: o.probe_id === null ? null : checkId(o.probe_id, `${what}.probe_id`),
    errors: checkU(o.errors, `${what}.errors`),
    admission_times_ms: (() => {
      if (!Array.isArray(o.admission_times_ms)) throw new SchemaError(`${what}.admission_times_ms`);
      return o.admission_times_ms.map((t, i) => checkU(t, `${what}.admission_times_ms[${i}]`));
    })(),
  };
}

export function validateStopScope(v: unknown, what = "scope"): StopScope {
  const o = closed(v, ["kind", "id"], what);
  return { kind: enumOf(o.kind, ["run", "budget", "host"], `${what}.kind`), id: checkId(o.id, `${what}.id`) };
}

export function validateStop(v: unknown, what = "stop"): Stop {
  const o = closed(v, ["kill_id", "scope", "reason", "requested_ms", "actor", "request_id", "durable", "signal_id", "evidence", "results"], what);
  if (typeof o.durable !== "boolean") throw new SchemaError(`${what}.durable`);
  if (!Array.isArray(o.results)) throw new SchemaError(`${what}.results`);
  return {
    kill_id: checkId(o.kill_id, `${what}.kill_id`),
    scope: validateStopScope(o.scope, `${what}.scope`),
    reason: validateReason(o.reason, `${what}.reason`),
    requested_ms: checkU(o.requested_ms, `${what}.requested_ms`),
    actor: checkId(o.actor, `${what}.actor`),
    request_id: checkId(o.request_id, `${what}.request_id`),
    durable: o.durable,
    signal_id: o.signal_id === null ? null : checkId(o.signal_id, `${what}.signal_id`),
    evidence: evidenceList(o.evidence, `${what}.evidence`),
    results: o.results.map((r, i) => {
      const rr = closed(r, ["run_id", "signal_sent", "empty_observed", "observed_ms"], `${what}.results[${i}]`);
      if (typeof rr.signal_sent !== "boolean" || typeof rr.empty_observed !== "boolean") throw new SchemaError(`${what}.results[${i}]`);
      return {
        run_id: checkId(rr.run_id, `${what}.results[${i}].run_id`),
        signal_sent: rr.signal_sent,
        empty_observed: rr.empty_observed,
        observed_ms: rr.observed_ms === null ? null : checkU(rr.observed_ms, `${what}.results[${i}].observed_ms`),
      };
    }),
  };
}

export function validateSample(v: unknown, what = "sample"): Sample {
  const o = closed(v, ["run_id", "boot_id", "sample_no", "at_ms", "cpu_ms", "memory_bytes", "memory_max_events", "oom_events", "task_max_events", "populated"], what);
  if (typeof o.populated !== "boolean") throw new SchemaError(`${what}.populated`);
  return {
    run_id: checkId(o.run_id, `${what}.run_id`),
    boot_id: checkBootId(o.boot_id, `${what}.boot_id`),
    sample_no: checkU(o.sample_no, `${what}.sample_no`),
    at_ms: checkU(o.at_ms, `${what}.at_ms`),
    cpu_ms: checkU(o.cpu_ms, `${what}.cpu_ms`),
    memory_bytes: checkU(o.memory_bytes, `${what}.memory_bytes`),
    memory_max_events: checkU(o.memory_max_events, `${what}.memory_max_events`),
    oom_events: checkU(o.oom_events, `${what}.oom_events`),
    task_max_events: checkU(o.task_max_events, `${what}.task_max_events`),
    populated: o.populated,
  };
}

export function validateOutcome(v: unknown, what = "outcome"): Outcome {
  const o = closed(v, ["status", "actual", "result_hash", "evidence"], what);
  return {
    status: enumOf(o.status, ["SUCCEEDED", "FAILED", "UNKNOWN"], `${what}.status`),
    actual: o.actual === null ? null : validateSpend(o.actual, `${what}.actual`),
    result_hash: o.result_hash === null ? null : checkHash(o.result_hash, `${what}.result_hash`),
    evidence: evidenceList(o.evidence, `${what}.evidence`),
  };
}

export function validateHead(v: unknown, what = "head"): Head {
  const o = closed(v, ["seq", "hash"], what);
  return { seq: checkU(o.seq, `${what}.seq`), hash: checkHash(o.hash, `${what}.hash`) };
}

export function validateTrust(v: unknown, what = "trust"): Trust {
  const o = closed(v, ["v", "installation_id", "threshold", "principals", "event_key"], what);
  if (o.v !== 1) throw new SchemaError(`${what}.v`);
  if (o.threshold !== 2) throw new SchemaError(`${what}.threshold: must be 2`);
  if (!Array.isArray(o.principals) || o.principals.length !== 3) throw new SchemaError(`${what}.principals: need exactly 3`);
  const principals = o.principals.map((p, i) => {
    const pp = closed(p, ["principal_id", "key_id", "public_key"], `${what}.principals[${i}]`);
    return {
      principal_id: checkId(pp.principal_id, `${what}.principals[${i}].principal_id`),
      key_id: checkId(pp.key_id, `${what}.principals[${i}].key_id`),
      public_key: checkHash(pp.public_key, `${what}.principals[${i}].public_key`),
    };
  });
  if (new Set(principals.map((p) => p.principal_id)).size !== 3) throw new SchemaError(`${what}.principals: duplicate principal`);
  if (new Set(principals.map((p) => p.key_id)).size !== 3) throw new SchemaError(`${what}.principals: duplicate key_id`);
  if (new Set(principals.map((p) => p.public_key)).size !== 3) throw new SchemaError(`${what}.principals: duplicate key`);
  const ek = closed(o.event_key, ["key_id", "public_key"], `${what}.event_key`);
  return {
    v: 1,
    installation_id: checkId(o.installation_id, `${what}.installation_id`),
    threshold: 2,
    principals,
    event_key: { key_id: checkId(ek.key_id, `${what}.event_key.key_id`), public_key: checkHash(ek.public_key, `${what}.event_key.public_key`) },
  };
}

export function validateHostConfig(v: unknown, what = "config"): HostConfig {
  const o = closed(v, [
    "v", "installation_id", "profile", "database", "socket", "cgroup_root", "image_store",
    "event_key_file", "object_key_file", "emergency_file", "uid_first", "uid_count",
    "controller_memory_bytes", "guard_memory_bytes", "audit_reserve_bytes",
    "live_adapters", "watch_scopes",
  ], what);
  if (o.v !== 1) throw new SchemaError(`${what}.v`);
  if (typeof o.live_adapters !== "boolean") throw new SchemaError(`${what}.live_adapters`);
  const uidFirst = checkUint(o.uid_first, `${what}.uid_first`);
  const uidCount = checkUint(o.uid_count, `${what}.uid_count`);
  if (uidCount < 2) throw new SchemaError(`${what}.uid_count: too small`);
  if (!Array.isArray(o.watch_scopes)) throw new SchemaError(`${what}.watch_scopes`);
  return {
    v: 1,
    installation_id: checkId(o.installation_id, `${what}.installation_id`),
    profile: enumOf(o.profile, ["linux-contained-v1", "offline-v1"], `${what}.profile`),
    database: absPath(o.database, `${what}.database`),
    socket: absPath(o.socket, `${what}.socket`),
    cgroup_root: absPath(o.cgroup_root, `${what}.cgroup_root`),
    image_store: absPath(o.image_store, `${what}.image_store`),
    event_key_file: absPath(o.event_key_file, `${what}.event_key_file`),
    object_key_file: absPath(o.object_key_file, `${what}.object_key_file`),
    emergency_file: absPath(o.emergency_file, `${what}.emergency_file`),
    uid_first: uidFirst,
    uid_count: uidCount,
    controller_memory_bytes: checkU(o.controller_memory_bytes, `${what}.controller_memory_bytes`),
    guard_memory_bytes: checkU(o.guard_memory_bytes, `${what}.guard_memory_bytes`),
    audit_reserve_bytes: checkU(o.audit_reserve_bytes, `${what}.audit_reserve_bytes`),
    live_adapters: o.live_adapters,
    watch_scopes: o.watch_scopes.map((s, i) => {
      const ss = closed(s, ["uid", "budgets"], `${what}.watch_scopes[${i}]`);
      return {
        uid: checkUint(ss.uid, `${what}.watch_scopes[${i}].uid`),
        budgets: sortedUniqueStrings(ss.budgets, `${what}.watch_scopes[${i}].budgets`, (x, f) => checkId(x, f)),
      };
    }),
  };
}

// ---------- Input/Output method map (§3.2) ----------

export type Input = {
  "host.status": Record<string, never>;
  "host.stop": { reason: "OPERATOR" };
  "host.recover": { expected_epoch: string };
  "policy.apply": { bundle: PolicyBundle; expected_revision: string };
  "budget.create": { budget_id: string; parent: string; limit: Spend };
  "budget.get": { budget_id: string };
  "budget.tighten": { budget_id: string; limit: Spend; expected_revision: string };
  "budget.close": { budget_id: string; expected_revision: string };
  "run.start": { run_id: string; budget_id: string; limit: Spend; resources: ResourceCaps; launch: Launch };
  "run.get": { run_id: string };
  "run.heartbeat": { run_id: string; beat: string };
  "run.stop": { run_id: string; reason: "OPERATOR" | "SELF_STOP" };
  "action.reserve": { action_id: string; intent: Intent };
  "action.dispatch": { action_id: string };
  "action.cancel": { action_id: string };
  "action.get": { action_id: string };
  "action.reconcile": { action_id: string };
  "breaker.get": { budget_id: string };
  "breaker.reset": { budget_id: string; expected_revision: string };
  "watch.stop": { budget_id: string; signal_id: string; evidence: EvidenceRef };
  "events.read": { after: string; limit: string };
  "evidence.export": { from: Head; to: Head; disclosure: "FULL" | "METADATA" };
  "metrics.read": Record<string, never>;
};

export const METHODS = [
  "host.status", "host.stop", "host.recover", "policy.apply",
  "budget.create", "budget.get", "budget.tighten", "budget.close",
  "run.start", "run.get", "run.heartbeat", "run.stop",
  "action.reserve", "action.dispatch", "action.cancel", "action.get", "action.reconcile",
  "breaker.get", "breaker.reset", "watch.stop",
  "events.read", "evidence.export", "metrics.read",
] as const;
export type Method = (typeof METHODS)[number];

export const GUEST_ONLY_METHODS: readonly Method[] = ["run.heartbeat", "action.reserve", "action.dispatch", "action.cancel"];
export const READONLY_METHODS: readonly Method[] = [
  "host.status", "budget.get", "run.get", "action.get", "breaker.get", "events.read", "evidence.export", "metrics.read",
];
export const GUEST_CHANNEL_METHODS: readonly Method[] = [...GUEST_ONLY_METHODS, "run.get", "run.stop", "action.get"];

const ERROR_CODES = new Set([
  "INVALID_FRAME", "INVALID_SCHEMA", "VERSION_UNSUPPORTED", "UNAUTHENTICATED",
  "FORBIDDEN", "NOT_FOUND", "CONFLICT", "IDEMPOTENCY_CONFLICT", "STALE_REVISION",
  "CAP_EXCEEDED", "CEILING_TOO_LOW", "UNBOUNDED_COST", "PRICE_CHANGED", "EXPIRED",
  "STOPPED", "BREAKER_OPEN", "RATE_LIMIT", "BUSY", "UNSUPPORTED_HOST",
  "ADAPTER_UNAVAILABLE", "AUDIT_UNAVAILABLE", "HOST_FENCED", "COUNTER_EXHAUSTED",
  "BOUND_BREACH", "EVIDENCE_INVALID",
]);

export function validateParams<M extends Method>(method: M, v: unknown): Input[M] {
  switch (method) {
    case "host.status":
    case "metrics.read":
      closed(v, [], `params.${method}`);
      return {} as Input[M];
    case "host.stop": {
      const o = closed(v, ["reason"], `params.${method}`);
      if (o.reason !== "OPERATOR") throw new SchemaError("params.host.stop.reason");
      return { reason: "OPERATOR" } as Input[M];
    }
    case "host.recover": {
      const o = closed(v, ["expected_epoch"], `params.${method}`);
      return { expected_epoch: checkU(o.expected_epoch, "expected_epoch") } as Input[M];
    }
    case "policy.apply": {
      const o = closed(v, ["bundle", "expected_revision"], `params.${method}`);
      return { bundle: validatePolicyBundle(o.bundle, "bundle"), expected_revision: checkU(o.expected_revision, "expected_revision") } as Input[M];
    }
    case "budget.create": {
      const o = closed(v, ["budget_id", "parent", "limit"], `params.${method}`);
      return { budget_id: checkId(o.budget_id, "budget_id"), parent: checkId(o.parent, "parent"), limit: validateSpend(o.limit, "limit") } as Input[M];
    }
    case "budget.get":
    case "breaker.get": {
      const o = closed(v, ["budget_id"], `params.${method}`);
      return { budget_id: checkId(o.budget_id, "budget_id") } as Input[M];
    }
    case "budget.tighten": {
      const o = closed(v, ["budget_id", "limit", "expected_revision"], `params.${method}`);
      return { budget_id: checkId(o.budget_id, "budget_id"), limit: validateSpend(o.limit, "limit"), expected_revision: checkU(o.expected_revision, "expected_revision") } as Input[M];
    }
    case "budget.close": {
      const o = closed(v, ["budget_id", "expected_revision"], `params.${method}`);
      return { budget_id: checkId(o.budget_id, "budget_id"), expected_revision: checkU(o.expected_revision, "expected_revision") } as Input[M];
    }
    case "run.start": {
      const o = closed(v, ["run_id", "budget_id", "limit", "resources", "launch"], `params.${method}`);
      return {
        run_id: checkId(o.run_id, "run_id"),
        budget_id: checkId(o.budget_id, "budget_id"),
        limit: validateSpend(o.limit, "limit"),
        resources: validateResourceCaps(o.resources, "resources"),
        launch: validateLaunch(o.launch, "launch"),
      } as Input[M];
    }
    case "run.get": {
      const o = closed(v, ["run_id"], `params.${method}`);
      return { run_id: checkId(o.run_id, "run_id") } as Input[M];
    }
    case "run.heartbeat": {
      const o = closed(v, ["run_id", "beat"], `params.${method}`);
      return { run_id: checkId(o.run_id, "run_id"), beat: checkU(o.beat, "beat") } as Input[M];
    }
    case "run.stop": {
      const o = closed(v, ["run_id", "reason"], `params.${method}`);
      return { run_id: checkId(o.run_id, "run_id"), reason: enumOf(o.reason, ["OPERATOR", "SELF_STOP"], "reason") } as Input[M];
    }
    case "action.reserve": {
      const o = closed(v, ["action_id", "intent"], `params.${method}`);
      return { action_id: checkId(o.action_id, "action_id"), intent: validateIntent(o.intent, "intent") } as Input[M];
    }
    case "action.dispatch":
    case "action.cancel":
    case "action.get":
    case "action.reconcile": {
      const o = closed(v, ["action_id"], `params.${method}`);
      return { action_id: checkId(o.action_id, "action_id") } as Input[M];
    }
    case "breaker.reset": {
      const o = closed(v, ["budget_id", "expected_revision"], `params.${method}`);
      return { budget_id: checkId(o.budget_id, "budget_id"), expected_revision: checkU(o.expected_revision, "expected_revision") } as Input[M];
    }
    case "watch.stop": {
      const o = closed(v, ["budget_id", "signal_id", "evidence"], `params.${method}`);
      return {
        budget_id: checkId(o.budget_id, "budget_id"),
        signal_id: checkId(o.signal_id, "signal_id"),
        evidence: validateEvidenceRef(o.evidence, "evidence"),
      } as Input[M];
    }
    case "events.read": {
      const o = closed(v, ["after", "limit"], `params.${method}`);
      const after = checkU(o.after, "after");
      const limit = checkU(o.limit, "limit");
      const l = BigInt(limit);
      if (l < 1n || l > BigInt(128)) throw new SchemaError("events.read.limit: out of range 1..128");
      return { after, limit } as Input[M];
    }
    case "evidence.export": {
      const o = closed(v, ["from", "to", "disclosure"], `params.${method}`);
      return {
        from: validateHead(o.from, "from"),
        to: validateHead(o.to, "to"),
        disclosure: enumOf(o.disclosure, ["FULL", "METADATA"], "disclosure"),
      } as Input[M];
    }
  }
}

export function validateRequest(v: unknown): { v: 1; request_id: string; method: Method; params: unknown } {
  const o = closed(v, ["v", "request_id", "method", "params"], "request");
  if (o.v !== 1) {
    if (typeof o.v === "number" && Number.isSafeInteger(o.v) && o.v >= 2) {
      // distinguishable version error handled by caller via marker
      throw new VersionError();
    }
    throw new SchemaError("request.v");
  }
  if (typeof o.method !== "string" || !(METHODS as readonly string[]).includes(o.method)) {
    throw new SchemaError("request.method");
  }
  return { v: 1, request_id: checkId(o.request_id, "request_id"), method: o.method as Method, params: o.params };
}

export class VersionError extends Error {
  constructor() {
    super("unsupported version");
    this.name = "VersionError";
  }
}

export function isErrorCode(v: unknown): v is string {
  return typeof v === "string" && ERROR_CODES.has(v);
}

// ---------- EventData validation ----------

export function validateEventData(v: unknown, what = "data"): EventData {
  const kind = (typeof v === "object" && v !== null && typeof (v as { kind?: unknown }).kind === "string")
    ? (v as { kind: string }).kind : "";
  switch (kind) {
    case "PolicyActivated": {
      const o = closed(v, ["kind", "policy"], what);
      return { kind, policy: validatePolicyBundle(o.policy, `${what}.policy`) };
    }
    case "BudgetCreated": {
      const o = closed(v, ["kind", "budget"], what);
      return { kind, budget: validateBudget(o.budget, `${what}.budget`) };
    }
    case "BudgetTightened": {
      const o = closed(v, ["kind", "budget_id", "before", "after", "revision"], what);
      return { kind, budget_id: checkId(o.budget_id, `${what}.budget_id`), before: validateSpend(o.before, `${what}.before`), after: validateSpend(o.after, `${what}.after`), revision: checkU(o.revision, `${what}.revision`) };
    }
    case "BudgetClosed": {
      const o = closed(v, ["kind", "budget_id", "revision"], what);
      return { kind, budget_id: checkId(o.budget_id, `${what}.budget_id`), revision: checkU(o.revision, `${what}.revision`) };
    }
    case "RunCreated": {
      const o = closed(v, ["kind", "run", "launch_hash", "capability"], what);
      return { kind, run: validateRun(o.run, `${what}.run`), launch_hash: checkHash(o.launch_hash, `${what}.launch_hash`), capability: validateCapability(o.capability, `${what}.capability`) };
    }
    case "RunArmed": {
      const o = closed(v, ["kind", "run_id", "containment_id"], what);
      return { kind, run_id: checkId(o.run_id, `${what}.run_id`), containment_id: checkId(o.containment_id, `${what}.containment_id`) };
    }
    case "HeartbeatAccepted": {
      const o = closed(v, ["kind", "run_id", "beat", "deadline_ms"], what);
      return { kind, run_id: checkId(o.run_id, `${what}.run_id`), beat: checkU(o.beat, `${what}.beat`), deadline_ms: checkU(o.deadline_ms, `${what}.deadline_ms`) };
    }
    case "UsageObserved": {
      const o = closed(v, ["kind", "sample"], what);
      return { kind, sample: validateSample(o.sample, `${what}.sample`) };
    }
    case "RunEnded": {
      const o = closed(v, ["kind", "run_id", "state", "exit_code"], what);
      const st = enumOf(o.state, ["STOPPED", "FINISHED", "FAILED"], `${what}.state`);
      if (o.exit_code !== null) checkUint(o.exit_code, `${what}.exit_code`);
      return { kind, run_id: checkId(o.run_id, `${what}.run_id`), state: st, exit_code: o.exit_code as number | null };
    }
    case "ActionReserved": {
      const o = closed(v, ["kind", "action"], what);
      return { kind, action: validateAction(o.action, `${what}.action`) };
    }
    case "ActionDispatched": {
      const o = closed(v, ["kind", "action_id", "upper"], what);
      return { kind, action_id: checkId(o.action_id, `${what}.action_id`), upper: validateSpend(o.upper, `${what}.upper`) };
    }
    case "ActionReleased": {
      const o = closed(v, ["kind", "action_id", "state", "reason"], what);
      return { kind, action_id: checkId(o.action_id, `${what}.action_id`), state: enumOf(o.state, ["CANCELED", "EXPIRED"], `${what}.state`), reason: validateReason(o.reason, `${what}.reason`) };
    }
    case "ActionObserved": {
      const o = closed(v, ["kind", "action_id", "outcome"], what);
      return { kind, action_id: checkId(o.action_id, `${what}.action_id`), outcome: validateOutcome(o.outcome, `${what}.outcome`) };
    }
    case "AdmissionDenied": {
      const o = closed(v, ["kind", "run_id", "operation_id", "code", "budgets"], what);
      if (!isErrorCode(o.code)) throw new SchemaError(`${what}.code`);
      if (!Array.isArray(o.budgets)) throw new SchemaError(`${what}.budgets`);
      return { kind, run_id: checkId(o.run_id, `${what}.run_id`), operation_id: checkId(o.operation_id, `${what}.operation_id`), code: o.code, budgets: o.budgets.map((b, i) => checkId(b, `${what}.budgets[${i}]`)) };
    }
    case "StopLatched":
    case "StopObserved": {
      const o = closed(v, ["kind", "stop"], what);
      return { kind, stop: validateStop(o.stop, `${what}.stop`) };
    }
    case "BreakerChanged": {
      const o = closed(v, ["kind", "breaker"], what);
      return { kind, breaker: validateBreaker(o.breaker, `${what}.breaker`) };
    }
    case "ProbeObserved": {
      const o = closed(v, ["kind", "budget_id", "probe_id", "success"], what);
      if (typeof o.success !== "boolean") throw new SchemaError(`${what}.success`);
      return { kind, budget_id: checkId(o.budget_id, `${what}.budget_id`), probe_id: checkId(o.probe_id, `${what}.probe_id`), success: o.success };
    }
    case "HostChanged": {
      const o = closed(v, ["kind", "state", "epoch", "boot_id", "reason"], what);
      return { kind, state: enumOf(o.state, ["RECOVERING", "READY", "FENCED"], `${what}.state`), epoch: checkU(o.epoch, `${what}.epoch`), boot_id: checkBootId(o.boot_id, `${what}.boot_id`), reason: validateReason(o.reason, `${what}.reason`) };
    }
    case "RecoveryGap": {
      const o = closed(v, ["kind", "emergency_hash", "affected_runs"], what);
      if (!Array.isArray(o.affected_runs)) throw new SchemaError(`${what}.affected_runs`);
      return { kind, emergency_hash: o.emergency_hash === null ? null : checkHash(o.emergency_hash, `${what}.emergency_hash`), affected_runs: o.affected_runs.map((r, i) => checkId(r, `${what}.affected_runs[${i}]`)) };
    }
    case "MigrationApplied": {
      const o = closed(v, ["kind", "from", "to", "old_head", "reducer"], what);
      return { kind, from: checkU(o.from, `${what}.from`), to: checkU(o.to, `${what}.to`), old_head: checkHash(o.old_head, `${what}.old_head`), reducer: checkHash(o.reducer, `${what}.reducer`) };
    }
    default:
      throw new SchemaError(`${what}.kind: unknown event kind`);
  }
}

export function validateEventBody(v: unknown, what = "body"): EventBody {
  const o = closed(v, ["v", "installation_id", "epoch", "boot_id", "seq", "prev", "at_ms", "actor", "request_id", "policy", "data"], what);
  if (o.v !== 1) throw new SchemaError(`${what}.v`);
  return {
    v: 1,
    installation_id: checkId(o.installation_id, `${what}.installation_id`),
    epoch: checkU(o.epoch, `${what}.epoch`),
    boot_id: checkBootId(o.boot_id, `${what}.boot_id`),
    seq: checkU(o.seq, `${what}.seq`),
    prev: checkHash(o.prev, `${what}.prev`),
    at_ms: checkU(o.at_ms, `${what}.at_ms`),
    actor: checkId(o.actor, `${what}.actor`),
    request_id: checkId(o.request_id, `${what}.request_id`),
    policy: o.policy === null ? null : checkHash(o.policy, `${what}.policy`),
    data: validateEventData(o.data, `${what}.data`),
  };
}

export function validateSignedEvent(v: unknown, what = "event"): SignedEvent {
  const o = closed(v, ["body", "hash", "key_id", "sig"], what);
  return {
    body: validateEventBody(o.body, `${what}.body`),
    hash: checkHash(o.hash, `${what}.hash`),
    key_id: checkId(o.key_id, `${what}.key_id`),
    sig: checkSig(o.sig, `${what}.sig`),
  };
}

export function validateBundleBody(v: unknown, what = "bundle.body"): BundleBody {
  const o = closed(v, ["schema", "installation_id", "from", "to", "events", "policies", "trust", "objects", "disclosure", "missing"], what);
  if (o.schema !== "seatbelt-evidence/1") throw new SchemaError(`${what}.schema`);
  if (!Array.isArray(o.events)) throw new SchemaError(`${what}.events`);
  if (!Array.isArray(o.policies)) throw new SchemaError(`${what}.policies`);
  if (!Array.isArray(o.objects)) throw new SchemaError(`${what}.objects`);
  if (!Array.isArray(o.missing)) throw new SchemaError(`${what}.missing`);
  const disclosure = enumOf(o.disclosure, ["FULL", "METADATA"], `${what}.disclosure`);
  return {
    schema: "seatbelt-evidence/1",
    installation_id: checkId(o.installation_id, `${what}.installation_id`),
    from: validateHead(o.from, `${what}.from`),
    to: validateHead(o.to, `${what}.to`),
    events: o.events.map((e, i) => validateSignedEvent(e, `${what}.events[${i}]`)),
    policies: o.policies.map((p, i) => validatePolicyBundle(p, `${what}.policies[${i}]`)),
    trust: validateTrust(o.trust, `${what}.trust`),
    objects: o.objects.map((ob, i) => {
      const oo = closed(ob, ["hash", "bytes_b64"], `${what}.objects[${i}]`);
      if (typeof oo.bytes_b64 !== "string" || !/^[A-Za-z0-9_-]*$/.test(oo.bytes_b64)) throw new SchemaError(`${what}.objects[${i}].bytes_b64`);
      return { hash: checkHash(oo.hash, `${what}.objects[${i}].hash`), bytes_b64: oo.bytes_b64 };
    }),
    disclosure,
    missing: o.missing.map((m, i) => checkHash(m, `${what}.missing[${i}]`)),
  };
}

export function validateBundle(v: unknown, what = "bundle"): Bundle {
  const o = closed(v, ["body", "hash", "key_id", "sig"], what);
  return { body: validateBundleBody(o.body, `${what}.body`), hash: checkHash(o.hash, `${what}.hash`), key_id: checkId(o.key_id, `${what}.key_id`), sig: checkSig(o.sig, `${what}.sig`) };
}

export function validateEmergencyPayload(v: unknown, what = "emergency"): EmergencyPayload {
  const o = closed(v, ["v", "run_id", "epoch", "boot_id", "kill_id", "reason", "scope_kind", "scope_id", "actor", "request_id", "requested_ms", "signal_sent", "empty_observed"], what);
  if (o.v !== 1) throw new SchemaError(`${what}.v`);
  if (typeof o.signal_sent !== "boolean" || typeof o.empty_observed !== "boolean") throw new SchemaError(`${what}.flags`);
  return {
    v: 1,
    run_id: checkId(o.run_id, `${what}.run_id`),
    epoch: checkU(o.epoch, `${what}.epoch`),
    boot_id: checkBootId(o.boot_id, `${what}.boot_id`),
    kill_id: checkId(o.kill_id, `${what}.kill_id`),
    reason: validateReason(o.reason, `${what}.reason`),
    scope_kind: enumOf(o.scope_kind, ["run", "budget", "host"], `${what}.scope_kind`),
    scope_id: checkId(o.scope_id, `${what}.scope_id`),
    actor: checkId(o.actor, `${what}.actor`),
    request_id: checkId(o.request_id, `${what}.request_id`),
    requested_ms: checkU(o.requested_ms, `${what}.requested_ms`),
    signal_sent: o.signal_sent,
    empty_observed: o.empty_observed,
  };
}

export function validateEncryptedObject(v: unknown, what = "object"): EncryptedObject {
  const o = closed(v, ["v", "hash", "nonce_b64", "ciphertext_b64", "tag_b64"], what);
  if (o.v !== 1) throw new SchemaError(`${what}.v`);
  for (const k of ["nonce_b64", "ciphertext_b64", "tag_b64"] as const) {
    if (typeof o[k] !== "string" || !/^[A-Za-z0-9_-]*$/.test(o[k] as string)) throw new SchemaError(`${what}.${k}`);
  }
  return { v: 1, hash: checkHash(o.hash, `${what}.hash`), nonce_b64: o.nonce_b64 as string, ciphertext_b64: o.ciphertext_b64 as string, tag_b64: o.tag_b64 as string };
}

// ---------- guard / adapter protocol validators ----------

export function validateGuardInput(v: unknown): GuardInput {
  const head = closed(v, ["op"], "guard");
  const op = typeof head.op === "string" ? head.op : "";
  switch (op) {
    case "arm": {
      const o = closed(v, ["op", "seq", "run_id", "epoch", "containment_id", "deadline_ms", "resources"], "guard.arm");
      return { op, seq: checkU(o.seq, "seq"), run_id: checkId(o.run_id, "run_id"), epoch: checkU(o.epoch, "epoch"), containment_id: checkId(o.containment_id, "containment_id"), deadline_ms: checkU(o.deadline_ms, "deadline_ms"), resources: validateResourceCaps(o.resources, "resources") };
    }
    case "renew": {
      const o = closed(v, ["op", "seq", "run_id", "epoch", "heartbeat_deadline_ms"], "guard.renew");
      return { op, seq: checkU(o.seq, "seq"), run_id: checkId(o.run_id, "run_id"), epoch: checkU(o.epoch, "epoch"), heartbeat_deadline_ms: checkU(o.heartbeat_deadline_ms, "heartbeat_deadline_ms") };
    }
    case "stop": {
      const o = closed(v, ["op", "seq", "run_id", "epoch", "kill_id", "reason", "scope_kind", "scope_id", "actor", "request_id"], "guard.stop");
      return {
        op, seq: checkU(o.seq, "seq"), run_id: checkId(o.run_id, "run_id"), epoch: checkU(o.epoch, "epoch"),
        kill_id: checkId(o.kill_id, "kill_id"), reason: validateReason(o.reason, "reason"),
        scope_kind: enumOf(o.scope_kind, ["run", "budget", "host"], "scope_kind"), scope_id: checkId(o.scope_id, "scope_id"),
        actor: checkId(o.actor, "actor"), request_id: checkId(o.request_id, "request_id"),
      };
    }
    case "get": {
      const o = closed(v, ["op", "seq", "run_id", "epoch"], "guard.get");
      return { op, seq: checkU(o.seq, "seq"), run_id: checkId(o.run_id, "run_id"), epoch: checkU(o.epoch, "epoch") };
    }
    default:
      throw new SchemaError("guard.op");
  }
}

export function validateGuardReply(v: unknown): GuardReply {
  const o = closed(v, ["seq", "ok", "code", "lease_until_ms", "stopped", "sample"], "guard.reply");
  if (typeof o.ok !== "boolean" || typeof o.stopped !== "boolean") throw new SchemaError("guard.reply flags");
  return {
    seq: checkU(o.seq, "seq"), ok: o.ok,
    code: enumOf(o.code, ["OK", "LATCHED", "BAD_SEQUENCE", "BAD_HANDLE"], "code"),
    lease_until_ms: checkU(o.lease_until_ms, "lease_until_ms"),
    stopped: o.stopped,
    sample: o.sample === null ? null : validateSample(o.sample, "sample"),
  };
}

export function validateAdapterInput(v: unknown): AdapterInput {
  const head = closed(v, ["op"], "adapter");
  const op = typeof head.op === "string" ? head.op : "";
  switch (op) {
    case "quote": {
      const o = closed(v, ["op", "intent", "tariff"], "adapter.quote");
      return { op, intent: validateIntent(o.intent, "intent"), tariff: checkHash(o.tariff, "tariff") };
    }
    case "execute": {
      const o = closed(v, ["op", "action_id", "operation_key", "intent", "quote", "dispatch_seq", "deadline_ms"], "adapter.execute");
      if (typeof o.operation_key !== "string") throw new SchemaError("operation_key");
      return { op, action_id: checkId(o.action_id, "action_id"), operation_key: o.operation_key, intent: validateIntent(o.intent, "intent"), quote: validateQuote(o.quote, "quote"), dispatch_seq: checkU(o.dispatch_seq, "dispatch_seq"), deadline_ms: checkU(o.deadline_ms, "deadline_ms") };
    }
    case "lookup": {
      const o = closed(v, ["op", "action_id", "operation_key", "action_hash"], "adapter.lookup");
      if (typeof o.operation_key !== "string") throw new SchemaError("operation_key");
      return { op, action_id: checkId(o.action_id, "action_id"), operation_key: o.operation_key, action_hash: checkHash(o.action_hash, "action_hash") };
    }
    case "probe": {
      const o = closed(v, ["op", "probe_id", "tariff"], "adapter.probe");
      return { op, probe_id: checkId(o.probe_id, "probe_id"), tariff: checkHash(o.tariff, "tariff") };
    }
    default:
      throw new SchemaError("adapter.op");
  }
}

export function validateAdapterReply(v: unknown): AdapterReply {
  const head = closed(v, ["op"], "adapter.reply");
  const op = typeof head.op === "string" ? head.op : "";
  if ("error" in head) {
    const o = closed(v, ["op", "error"], "adapter.reply");
    return { op: op as "quote", error: enumOf(o.error, ["UNBOUNDED_COST", "PRICE_CHANGED", "ADAPTER_UNAVAILABLE"], "error") };
  }
  switch (op) {
    case "quote": {
      const o = closed(v, ["op", "quote"], "adapter.reply.quote");
      return { op, quote: validateQuote(o.quote, "quote") };
    }
    case "execute":
    case "lookup": {
      const o = closed(v, ["op", "outcome", "result_b64"], "adapter.reply");
      const rb = o.result_b64;
      if (rb !== null && (typeof rb !== "string" || !/^[A-Za-z0-9_-]*$/.test(rb))) throw new SchemaError("result_b64");
      return { op, outcome: validateOutcome(o.outcome, "outcome"), result_b64: rb as string | null };
    }
    case "probe": {
      const o = closed(v, ["op", "success"], "adapter.reply");
      if (typeof o.success !== "boolean") throw new SchemaError("success");
      return { op, success: o.success };
    }
    default:
      throw new SchemaError("adapter.reply.op");
  }
}

export function validateMigrationManifest(v: unknown): MigrationManifest {
  const o = closed(v, ["v", "installation_id", "from", "to", "expected_head", "old_reducer", "new_reducer", "tool_hash", "old_trust", "new_trust", "preserve_charged", "signatures"], "manifest");
  if (o.v !== 1) throw new SchemaError("manifest.v");
  if (o.preserve_charged !== true) throw new SchemaError("manifest.preserve_charged");
  if (!Array.isArray(o.signatures)) throw new SchemaError("manifest.signatures");
  return {
    v: 1,
    installation_id: checkId(o.installation_id, "installation_id"),
    from: checkU(o.from, "from"), to: checkU(o.to, "to"),
    expected_head: validateHead(o.expected_head, "expected_head"),
    old_reducer: checkHash(o.old_reducer, "old_reducer"),
    new_reducer: checkHash(o.new_reducer, "new_reducer"),
    tool_hash: checkHash(o.tool_hash, "tool_hash"),
    old_trust: checkHash(o.old_trust, "old_trust"),
    new_trust: checkHash(o.new_trust, "new_trust"),
    preserve_charged: true,
    signatures: o.signatures.map((s, i) => validateSignature(s, `signatures[${i}]`)),
  };
}

// fixture-type helpers used across modules
export function isSpend(v: unknown): v is Spend {
  try {
    validateSpend(v);
    return true;
  } catch {
    return false;
  }
}
export { isId, isHash, isSig, isU, isBootId };
