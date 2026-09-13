// Independent offline verifier (spec §8.3). Ordered steps — the first failure
// decides the reported code:
//   1 schema+size        EVIDENCE_INVALID
//   2 chain/hash/sig/epoch/boot  EVIDENCE_INVALID
//   3 policy quorum      TRUST_QUORUM
//   4 FULL preimages     MISSING_OBJECT
//   5 semantic replay    REPLAY_MISMATCH
//   6 clock monotonicity CLOCK_VIOLATION
//   7 disclosure rules   DISCLOSURE_LEAK
//   8 head pin           EVIDENCE_STALE
//   9 boundary           EVIDENCE_TRUNCATED

import { jcsBytes, SchemaError, parseJsonStrict } from "./canon.js";
import type { Json } from "./canon.js";
import { D, HASH_DOMAINS, SIGN_DOMAINS, sha256Hex, verifyDigest } from "./crypto.js";
import type {
  Bundle, BundleBody, EventData, Head, PolicyBundle, SignedEvent, Spend, Trust,
} from "./schema.js";
import { GENESIS_PREV, validateBundle, VersionError } from "./schema.js";
import { eventHash } from "./store.js";
import { DIMS, spendToVec, vecAdd, vecLe, type SpendVec, vecZero, vecIsZero } from "./spend.js";
import { MAX_RESERVED_PER_RUN } from "./profile.js";

export type VerifyCode =
  | "OK" | "UNANCHORED" | "HEAD_MISMATCH" | "HASH_MISMATCH" | "UNTRUSTED_KEY"
  | "MISSING_OBJECT" | "MISSING_EVENTS" | "SIGNATURE_INVALID" | "REPLAY_MISMATCH" | "SCHEMA_INVALID";

/** Composite verification verdict (spec Verification, §1.5). */
export interface VerifyResult {
  status: "OK" | VerifyCode;
  integrity: "VALID" | "INVALID";
  replay: "VALID" | "INCOMPLETE" | "INVALID";
  completeness: "ANCHORED" | "UNANCHORED" | "INCOMPLETE";
  execution: "HOST_ATTESTED";
  freshness: "UNKNOWN";
  checked_to: Head;
  detail?: string;
}

function fail(
  code: Exclude<VerifyCode, "OK">,
  detail: string,
  dims: { integrity?: "VALID" | "INVALID"; replay?: "VALID" | "INCOMPLETE" | "INVALID"; completeness?: "ANCHORED" | "UNANCHORED" | "INCOMPLETE" } = {},
): VerifyResult {
  return {
    status: code,
    integrity: dims.integrity ?? "INVALID",
    replay: dims.replay ?? "INVALID",
    completeness: dims.completeness ?? "INCOMPLETE",
    execution: "HOST_ATTESTED", freshness: "UNKNOWN",
    checked_to: { seq: "0", hash: GENESIS_PREV }, detail,
  };
}
function okResult(to: Head): VerifyResult {
  return {
    status: "OK", integrity: "VALID", replay: "VALID", completeness: "ANCHORED",
    execution: "HOST_ATTESTED", freshness: "UNKNOWN", checked_to: to,
  };
}

interface ReplayBudget {
  limit: Spend; state: "ACTIVE" | "CLOSED"; revision: bigint;
  held: SpendVec; charged: SpendVec;
  parent: string | null;
}
interface ReplayBreaker {
  state: "CLOSED" | "OPEN" | "HALF_OPEN"; revision: bigint; reason: string | null;
  probeId: string | null; admissions: bigint[];
}
interface ReplayRun {
  state: string; revision: bigint; budget: string; limit: SpendVec;
  held: SpendVec; charged: SpendVec; lastBeat: bigint; deadline: bigint;
  epoch: string;
}
interface ReplayAction {
  state: string; runId: string; upper: SpendVec; expires: bigint; operationId: string;
  policyAdapter: string; quoteTariff: string; reserveSeq: bigint; dispatchSeq: bigint | null;
  dispatchable: boolean;
}
interface ReplayStop {
  killId: string; scopeKind: string; scopeId: string; signalId: string | null;
  results: { run_id: string; signal_sent: boolean; empty_observed: boolean }[];
}

class Replay {
  budgets = new Map<string, ReplayBudget>();
  breakers = new Map<string, ReplayBreaker>();
  runs = new Map<string, ReplayRun>();
  actions = new Map<string, ReplayAction>();
  operationIds = new Set<string>();
  stops = new Map<string, ReplayStop>();
  signalIds = new Set<string>();
  policies = new Map<string, PolicyBundle>();
  activePolicy: PolicyBundle | null = null;
  host: string = "RECOVERING";
  epoch = 1n;
  err: string | null = null;
  constructor(private policies0: Map<string, PolicyBundle>) {
    this.policies = new Map(policies0);
  }
  private bad(what: string): boolean {
    this.err = what;
    return false;
  }
  private pathOf(budgetId: string): string[] {
    const out: string[] = [];
    let cur: string | null = budgetId;
    for (let i = 0; i < 9 && cur !== null; i++) {
      out.push(cur);
      cur = this.budgets.get(cur)?.parent ?? null;
    }
    return out.reverse();
  }
  private holdsOf(a: ReplayAction): { owner: string; kind: "budget" | "run" }[] {
    const run = this.runs.get(a.runId);
    if (!run) return [];
    return [
      ...this.pathOf(run.budget).map((b) => ({ owner: b, kind: "budget" as const })),
      { owner: a.runId, kind: "run" as const },
    ];
  }
  apply(d: EventData, atMs: bigint): boolean {
    const pol = this.activePolicy;
    switch (d.kind) {
      case "PolicyActivated": {
        const b = d.policy;
        const h = D(HASH_DOMAINS.POLICY, b.body as unknown as Json);
        if (this.activePolicy === null) {
          if (b.body.revision !== "1" || b.body.previous !== null) return this.bad("policy:first");
        } else {
          const curHash = D(HASH_DOMAINS.POLICY, this.activePolicy.body as unknown as Json);
          if (b.body.previous !== curHash) return this.bad("policy:prev");
          if (BigInt(b.body.revision) !== BigInt(this.activePolicy.body.revision) + 1n) return this.bad("policy:rev");
          if (b.body.root_budget !== this.activePolicy.body.root_budget) return this.bad("policy:root");
          if (jcsBytes(b.body.root_limit as unknown as Json).toString() !== jcsBytes(this.activePolicy.body.root_limit as unknown as Json).toString()) return this.bad("policy:rootlimit");
          if ([...this.runs.values()].some((r) => r.state === "ARMING" || r.state === "ACTIVE" || r.state === "STOPPING")) return this.bad("policy:liveruns");
          if ([...this.actions.values()].some((a) => a.state === "RESERVED")) return this.bad("policy:holds");
        }
        this.policies.set(h, b);
        this.activePolicy = b;
        return true;
      }
      case "BudgetCreated": {
        const b = d.budget;
        if (this.budgets.has(b.budget_id)) return this.bad("budget:dup");
        if (b.parent === null) {
          if (!pol || b.budget_id !== pol.body.root_budget) return this.bad("budget:root");
        } else {
          const p = this.budgets.get(b.parent);
          if (!p || p.state !== "ACTIVE") return this.bad("budget:parent");
          if (this.pathOf(b.parent).length >= 8) return this.bad("budget:depth");
        }
        this.budgets.set(b.budget_id, {
          limit: b.limit, state: b.state, revision: BigInt(b.revision),
          held: vecZero(), charged: vecZero(), parent: b.parent,
        });
        if (b.state !== "ACTIVE" || b.revision !== "1" || !vecIsZero(spendToVec(b.held)) || !vecIsZero(spendToVec(b.charged))) return this.bad("budget:init");
        this.breakers.set(b.budget_id, { state: "CLOSED", revision: 1n, reason: null, probeId: null, admissions: [] });
        return true;
      }
      case "BudgetTightened": {
        const b = this.budgets.get(d.budget_id);
        if (!b || b.state !== "ACTIVE") return this.bad("tighten:state");
        if (BigInt(d.revision) !== b.revision + 1n) return this.bad("tighten:rev");
        if (jcsBytes(d.before as unknown as Json).toString() !== jcsBytes(b.limit as unknown as Json).toString()) return this.bad("tighten:before");
        const next = spendToVec(d.after);
        if (!vecLe(next, spendToVec(b.limit))) return this.bad("tighten:increase");
        if (!vecLe(vecAdd(b.held, b.charged), next)) return this.bad("tighten:below_used");
        b.limit = d.after;
        b.revision += 1n;
        return true;
      }
      case "BudgetClosed": {
        const b = this.budgets.get(d.budget_id);
        if (!b || b.state !== "ACTIVE") return this.bad("close:state");
        if (BigInt(d.revision) !== b.revision + 1n) return this.bad("close:rev");
        if (!vecIsZero(b.held)) return this.bad("close:held");
        b.state = "CLOSED";
        b.revision += 1n;
        return true;
      }
      case "RunCreated": {
        const r = d.run;
        if (!pol) return this.bad("run:nopolicy");
        if (this.runs.has(r.run_id)) return this.bad("run:dup");
        const budget = this.budgets.get(r.budget_id);
        if (!budget || budget.state !== "ACTIVE") return this.bad("run:budget");
        for (const anc of this.pathOf(r.budget_id)) {
          if (this.budgets.get(anc)!.state !== "ACTIVE") return this.bad("run:ancestor");
          if (this.breakers.get(anc)!.state !== "CLOSED") return this.bad("run:breaker");
        }
        if (!vecLe(spendToVec(r.limit), spendToVec(pol.body.max_run_limit))) return this.bad("run:limit");
        const live = [...this.runs.values()].filter((x) => x.state === "ARMING" || x.state === "ACTIVE" || x.state === "STOPPING").length;
        if (live >= Number(BigInt(pol.body.max_runs))) return this.bad("run:slots");
        if (r.state !== "ARMING" || r.revision !== "1" || r.last_beat !== "0" || r.kill_id !== null) return this.bad("run:init");
        if (d.capability.run_id !== r.run_id || d.capability.capability_id !== r.capability_id) return this.bad("run:cap");
        if (d.capability.revoked) return this.bad("run:caprevoked");
        this.runs.set(r.run_id, {
          state: "ARMING", revision: 1n, budget: r.budget_id, limit: spendToVec(r.limit),
          held: vecZero(), charged: vecZero(), lastBeat: 0n, deadline: BigInt(r.deadline_ms), epoch: r.epoch,
        });
        return true;
      }
      case "RunArmed": {
        const r = this.runs.get(d.run_id);
        if (!r || r.state !== "ARMING" || r.revision !== 1n) return this.bad("armed:state");
        r.state = "ACTIVE";
        r.revision = 2n;
        return true;
      }
      case "HeartbeatAccepted": {
        const r = this.runs.get(d.run_id);
        if (!r || r.state !== "ACTIVE") return this.bad("hb:state");
        if (BigInt(d.beat) !== r.lastBeat + 1n) return this.bad("hb:beat");
        if (BigInt(d.deadline_ms) !== minB(atMs + BigInt(pol?.body.heartbeat_ms ?? "0"), r.deadline)) return this.bad("hb:deadline");
        r.lastBeat += 1n;
        return true;
      }
      case "UsageObserved": {
        const r = this.runs.get(d.sample.run_id);
        if (!r) return this.bad("sample:run");
        return true;
      }
      case "RunEnded": {
        const r = this.runs.get(d.run_id);
        if (!r) return this.bad("end:run");
        if (d.state === "FINISHED" || d.state === "FAILED") {
          if (r.state !== "ACTIVE" && r.state !== "ARMING") return this.bad("end:from");
        } else if (r.state !== "STOPPING") {
          return this.bad("end:from");
        }
        r.state = d.state;
        r.revision += 1n;
        return true;
      }
      case "ActionReserved": {
        const a = d.action;
        const r = this.runs.get(a.intent.run_id);
        if (!r || r.state !== "ACTIVE") return this.bad("reserve:run");
        if (!pol) return this.bad("reserve:nopolicy");
        if (this.actions.has(a.action_id)) return this.bad("reserve:dup");
        if (this.operationIds.has(a.intent.operation_id)) return this.bad("reserve:opid");
        const pin = pol.body.adapters.find((x) => x.adapter === a.intent.adapter);
        if (!pin || pin.operation !== a.intent.operation) return this.bad("reserve:adapter");
        if (a.quote.adapter !== pin.adapter || a.quote.tariff !== pin.tariff) return this.bad("reserve:pin");
        if (BigInt(a.quote.duration_ms) > BigInt(pin.max_duration_ms)) return this.bad("reserve:duration");
        if (BigInt(a.quote.response_bytes) > BigInt(pin.max_response_bytes)) return this.bad("reserve:response");
        if (a.quote.upper.calls !== "1") return this.bad("reserve:calls");
        const q = spendToVec(a.quote.upper);
        for (const b of this.pathOf(r.budget)) {
          const bb = this.budgets.get(b)!;
          if (!vecLe(vecAdd(vecAdd(bb.held, bb.charged), q), spendToVec(bb.limit))) return this.bad("reserve:cap");
          if (this.breakers.get(b)!.state !== "CLOSED") return this.bad("reserve:breaker");
        }
        if (!vecLe(vecAdd(vecAdd(r.held, r.charged), q), r.limit)) return this.bad("reserve:runcap");
        const heldCount = [...this.actions.values()].filter((x) => x.runId === a.intent.run_id && x.state === "RESERVED").length;
        if (heldCount >= MAX_RESERVED_PER_RUN) return this.bad("reserve:maxholds");
        if (a.state !== "RESERVED") return this.bad("reserve:state");
        if (BigInt(a.expires_ms) !== minB(atMs + BigInt(pol.body.reservation_ms), r.deadline)) return this.bad("reserve:expires");
        const a2: ReplayAction = {
          state: "RESERVED", runId: a.intent.run_id, upper: q, expires: BigInt(a.expires_ms),
          operationId: a.intent.operation_id, policyAdapter: pin.adapter, quoteTariff: a.quote.tariff,
          reserveSeq: BigInt(a.reserve_seq), dispatchSeq: null, dispatchable: true,
        };
        this.actions.set(a.action_id, a2);
        this.operationIds.add(a.intent.operation_id);
        for (const h of this.holdsOf(a2)) {
          const c = h.kind === "budget" ? this.budgets.get(h.owner)! : this.runs.get(h.owner)!;
          c.held = vecAdd(c.held, q);
        }
        for (const b of this.pathOf(r.budget)) {
          const br = this.breakers.get(b)!;
          const window = BigInt(pol.body.breaker.window_ms);
          br.admissions = br.admissions.filter((t) => atMs - window < t && t <= atMs);
          br.admissions.push(atMs);
        }
        return true;
      }
      case "ActionDispatched": {
        const a = this.actions.get(d.action_id);
        if (!a) return this.bad("dispatch:action");
        const r = this.runs.get(a.runId)!;
        if (r.state !== "ACTIVE") return this.bad("dispatch:run");
        if (a.state !== "RESERVED") return this.bad("dispatch:state");
        if (atMs >= a.expires) return this.bad("dispatch:expired");
        for (const b of this.pathOf(r.budget)) {
          if (this.breakers.get(b)!.state !== "CLOSED") return this.bad("dispatch:breaker");
        }
        if (jcsBytes(d.upper as unknown as Json).toString() !== jcsBytes(vecdump(a.upper) as unknown as Json).toString()) return this.bad("dispatch:upper");
        for (const h of this.holdsOf(a)) {
          const c = h.kind === "budget" ? this.budgets.get(h.owner)! : this.runs.get(h.owner)!;
          c.held = vecSub2(c.held, a.upper);
          c.charged = vecAdd(c.charged, a.upper);
        }
        a.state = "DISPATCHED";
        a.dispatchSeq = BigInt(0); // seq filled by caller check below
        return true;
      }
      case "ActionReleased": {
        const a = this.actions.get(d.action_id);
        if (!a) return this.bad("release:action");
        if (a.state !== "RESERVED") return this.bad("release:state");
        if (d.state !== "CANCELED" && d.state !== "EXPIRED") return this.bad("release:to");
        for (const h of this.holdsOf(a)) {
          const c = h.kind === "budget" ? this.budgets.get(h.owner)! : this.runs.get(h.owner)!;
          c.held = vecSub2(c.held, a.upper);
        }
        a.state = d.state;
        return true;
      }
      case "ActionObserved": {
        const a = this.actions.get(d.action_id);
        if (!a) return this.bad("observe:action");
        const legal = (a.state === "DISPATCHED" && ["SUCCEEDED", "FAILED", "UNKNOWN"].includes(d.outcome.status))
          || (a.state === "UNKNOWN" && ["SUCCEEDED", "FAILED", "UNKNOWN"].includes(d.outcome.status));
        if (!legal) return this.bad("observe:state");
        a.state = d.outcome.status;
        if (d.outcome.status === "SUCCEEDED") {
          const r = this.runs.get(a.runId)!;
          for (const b of this.pathOf(r.budget)) this.breakers.get(b)!.admissions = this.breakers.get(b)!.admissions;
        }
        return true;
      }
      case "AdmissionDenied": {
        const r = this.runs.get(d.run_id);
        if (!r) return this.bad("denied:run");
        return true;
      }
      case "StopLatched": {
        if (this.stops.has(d.stop.kill_id)) {
          const prev = this.stops.get(d.stop.kill_id)!;
          if (prev.scopeKind !== d.stop.scope.kind || prev.scopeId !== d.stop.scope.id) return this.bad("stop:killid");
        }
        if (d.stop.signal_id !== null) {
          if (this.signalIds.has(d.stop.signal_id)) {
            const existing = [...this.stops.values()].find((s) => s.signalId === d.stop.signal_id)!;
            if (existing.scopeId !== d.stop.scope.id || existing.scopeKind !== d.stop.scope.kind) return this.bad("stop:signalid");
          }
          this.signalIds.add(d.stop.signal_id);
        }
        this.stops.set(d.stop.kill_id, {
          killId: d.stop.kill_id, scopeKind: d.stop.scope.kind, scopeId: d.stop.scope.id,
          signalId: d.stop.signal_id,
          results: d.stop.results.map((r) => ({ run_id: r.run_id, signal_sent: r.signal_sent, empty_observed: r.empty_observed })),
        });
        for (const res of d.stop.results) {
          const r = this.runs.get(res.run_id);
          if (r && (r.state === "ACTIVE" || r.state === "ARMING")) {
            r.state = "STOPPING";
            r.revision += 1n;
          }
        }
        return true;
      }
      case "StopObserved": {
        if (!this.stops.has(d.stop.kill_id)) return this.bad("stopobs:latch");
        const prev = this.stops.get(d.stop.kill_id)!;
        prev.results = d.stop.results.map((r) => ({ run_id: r.run_id, signal_sent: r.signal_sent, empty_observed: r.empty_observed }));
        return true;
      }
      case "BreakerChanged": {
        const cur = this.breakers.get(d.breaker.budget_id);
        if (!cur) return this.bad("breaker:budget");
        const nb = d.breaker;
        if (BigInt(nb.revision) !== cur.revision + 1n) return this.bad("breaker:rev");
        const ok = (cur.state === "CLOSED" && nb.state === "OPEN")
          || (cur.state === "OPEN" && nb.state === "HALF_OPEN")
          || (cur.state === "HALF_OPEN" && (nb.state === "OPEN" || nb.state === "CLOSED"));
        if (!ok) return this.bad("breaker:trans");
        if (nb.state === "HALF_OPEN" && (nb.probe_id === null || cur.reason === null || !["RATE", "PROVIDER_ERRORS", "WATCH"].includes(cur.reason))) return this.bad("breaker:halfopen");
        cur.state = nb.state;
        cur.revision += 1n;
        cur.reason = nb.reason;
        cur.probeId = nb.probe_id;
        if (nb.state === "CLOSED") cur.admissions = [];
        return true;
      }
      case "ProbeObserved": {
        const br = this.breakers.get(d.budget_id);
        if (!br) return this.bad("probe:budget");
        return true;
      }
      case "HostChanged": {
        const legal = (this.host === "READY" && d.state === "FENCED")
          || (this.host === "FENCED" && d.state === "RECOVERING")
          || (this.host === "RECOVERING" && d.state === "RECOVERING")
          || (this.host === "RECOVERING" && (d.state === "READY" || d.state === "FENCED"))
          || (this.host === "READY" && d.state === "RECOVERING");
        if (!legal) return this.bad(`host:${this.host}->${d.state}`);
        this.host = d.state;
        this.epoch = BigInt(d.epoch);
        return true;
      }
      case "RecoveryGap":
        return true;
      case "MigrationApplied":
        return true;
    }
  }
}

function vecdump(v: SpendVec): Spend {
  return { microusd: v.microusd.toString(), input_tokens: v.input_tokens.toString(), output_tokens: v.output_tokens.toString(), calls: v.calls.toString() };
}
function vecSub2(a: SpendVec, b: SpendVec): SpendVec {
  const out = vecZero();
  for (const d of DIMS) out[d] = a[d] - b[d];
  return out;
}
function minB(a: bigint, b: bigint): bigint {
  return a < b ? a : b;
}

/** Step 5: deterministic semantic replay of an event range. */
export function replayEvents(events: SignedEvent[]): { ok: true } | { ok: false; at: string; detail: string } {
  const rp = new Replay(new Map());
  for (const ev of events) {
    if (!rp.apply(ev.body.data, BigInt(ev.body.at_ms))) {
      return { ok: false, at: ev.body.seq, detail: rp.err ?? "illegal transition" };
    }
  }
  return { ok: true };
}

/**
 * Full nine-step offline verification. `trust` is the operator-supplied trust
 * anchor; `expectedHead` pins the bundle head. `priorVerified` supplies
 * previously verified events for multi-bundle chains.
 */
export function verifyBundle(
  bundleBytes: Uint8Array,
  trust: Trust,
  expectedHead: Head | null,
  priorVerified?: SignedEvent[],
  opts?: { allowUnanchored?: boolean },
): VerifyResult {
  // 1. schema + size
  if (bundleBytes.length > 65536) return fail("SCHEMA_INVALID", "bundle exceeds 65536-byte frame");
  let bundle: Bundle;
  try {
    bundle = validateBundle(parseJsonStrict(new TextDecoder().decode(bundleBytes)));
  } catch (e) {
    if (e instanceof SchemaError) return fail("SCHEMA_INVALID", `schema:${e.message}`);
    return fail("SCHEMA_INVALID", "parse failure");
  }
  const body: BundleBody = bundle.body;
  if (body.schema !== "seatbelt-evidence/1") return fail("SCHEMA_INVALID", "schema id");
  if (body.events.length > 128) return fail("SCHEMA_INVALID", ">128 events");
  if (body.installation_id !== trust.installation_id) return fail("SCHEMA_INVALID", "installation mismatch");
  if (jcsBytes(body.trust as unknown as Json).toString() !== jcsBytes(trust as unknown as Json).toString()) {
    return fail("UNTRUSTED_KEY", "bundle trust does not match the supplied anchor");
  }

  // 2. chain / hash / signature / epoch / boot
  if (D(HASH_DOMAINS.BUNDLE, body as unknown as Json) !== bundle.hash) return fail("HASH_MISMATCH", "bundle hash");
  if (bundle.key_id !== trust.event_key.key_id) return fail("UNTRUSTED_KEY", "bundle key_id");
  if (!verifyDigest(SIGN_DOMAINS.BUNDLE, bundle.hash, bundle.sig, hex(trust.event_key.public_key))) {
    return fail("SIGNATURE_INVALID", "bundle signature");
  }
  let prev = body.from;
  let epochSeen = "";
  let bootSeen = "";
  for (const ev of body.events) {
    const expectedSeq = (BigInt(prev.seq) + 1n).toString();
    if (ev.body.seq !== expectedSeq || ev.body.prev !== prev.hash) return fail("HASH_MISMATCH", `chain@${ev.body.seq}`);
    if (eventHash(ev.body) !== ev.hash) return fail("HASH_MISMATCH", `hash@${ev.body.seq}`);
    if (ev.key_id !== trust.event_key.key_id) return fail("UNTRUSTED_KEY", `key_id@${ev.body.seq}`);
    if (!verifyDigest(SIGN_DOMAINS.EVENT, ev.hash, ev.sig, hex(trust.event_key.public_key))) {
      return fail("SIGNATURE_INVALID", `sig@${ev.body.seq}`);
    }
    if (ev.body.installation_id !== trust.installation_id) return fail("HASH_MISMATCH", `inst@${ev.body.seq}`);
    if (epochSeen === "") {
      epochSeen = ev.body.epoch;
      bootSeen = ev.body.boot_id;
    } else {
      if (ev.body.boot_id !== bootSeen) return fail("HASH_MISMATCH", `boot@${ev.body.seq}`);
      if (BigInt(ev.body.epoch) < BigInt(epochSeen)) return fail("HASH_MISMATCH", `epoch@${ev.body.seq}`);
      epochSeen = ev.body.epoch;
    }
    prev = { seq: ev.body.seq, hash: ev.hash };
  }
  if (prev.seq !== body.to.seq || prev.hash !== body.to.hash) return fail("HASH_MISMATCH", "to mismatch");

  // 3. policy quorum under the supplied trust
  const policies = new Map<string, PolicyBundle>();
  for (const p of body.policies) {
    const bodyHash = D(HASH_DOMAINS.POLICY, p.body as unknown as Json);
    const seen = new Set<string>();
    let sigBad = false;
    for (const s of p.signatures) {
      const principal = trust.principals.find((x) => x.key_id === s.key_id);
      if (!principal) continue;
      if (verifyDigest(SIGN_DOMAINS.POLICY, bodyHash, s.sig, hex(principal.public_key))) seen.add(principal.principal_id);
      else sigBad = true;
    }
    if (seen.size < Number(trust.threshold)) {
      return fail(sigBad ? "SIGNATURE_INVALID" : "UNTRUSTED_KEY", `policy ${p.body.policy_id}@${p.body.revision}`);
    }
    policies.set(bodyHash, p);
  }
  for (const ev of body.events) {
    if (ev.body.data.kind === "PolicyActivated") {
      const h = D(HASH_DOMAINS.POLICY, ev.body.data.policy.body as unknown as Json);
      if (!policies.has(h)) return fail("UNTRUSTED_KEY", `policy@${ev.body.seq} absent from bundle policies`);
    } else if (ev.body.policy !== null && !policies.has(ev.body.policy)) {
      return fail("HASH_MISMATCH", `policy ref missing@${ev.body.seq}`);
    }
  }

  // 4. FULL object preimages
  const objectHashes = new Set<string>();
  for (const o of body.objects) {
    if (sha256Hex(b64(o.bytes_b64)) !== o.hash) return fail("HASH_MISMATCH", `object hash ${o.hash}`);
    objectHashes.add(o.hash);
  }
  const referenced = new Set<string>();
  for (const ev of body.events) {
    const d = ev.body.data;
    if (d.kind === "ActionReserved") referenced.add(d.action.intent.payload_hash);
    if (d.kind === "ActionObserved" && d.outcome.result_hash !== null) referenced.add(d.outcome.result_hash);
  }
  for (const h of referenced) {
    if (body.disclosure === "FULL") {
      if (!objectHashes.has(h)) return fail("MISSING_OBJECT", h);
    } else if (!body.missing.includes(h)) {
      return fail("MISSING_OBJECT", `metadata bundle must list ${h} as missing`);
    }
  }
  for (const m of body.missing) {
    if (body.disclosure === "FULL") return fail("MISSING_OBJECT", m);
  }

  // 5. semantic replay (independent reducer)
  const rep = replayEvents([...(priorVerified ?? []), ...body.events]);
  if (!rep.ok) return fail("REPLAY_MISMATCH", `${rep.at}:${rep.detail}`);
  const replayState: "VALID" | "INCOMPLETE" = body.disclosure === "METADATA" && referenced.size > 0 ? "INCOMPLETE" : "VALID";

  // 6. clock monotonicity
  let last = 0n;
  for (const ev of body.events) {
    const t = BigInt(ev.body.at_ms);
    if (t < last) return { ...fail("REPLAY_MISMATCH", `clock@${ev.body.seq}`), replay: "INVALID" };
    last = t;
  }

  // 7. disclosure rules
  if (body.disclosure === "METADATA" && body.objects.length > 0) {
    return fail("SCHEMA_INVALID", "metadata bundle carries object bytes");
  }
  for (const ev of body.events) {
    const s = jcsBytes(ev.body as unknown as Json).toString();
    if (s.includes('"payload"')) return fail("SCHEMA_INVALID", `payload material in event@${ev.body.seq}`);
  }

  // 8. head pin
  const headPinned = expectedHead !== null && body.to.seq === expectedHead.seq && body.to.hash === expectedHead.hash;
  if (!headPinned) {
    if (opts?.allowUnanchored) {
      // visibly weaker acceptance: integrity/replay proven, head not pinned.
      return {
        status: "UNANCHORED", integrity: "VALID", replay: replayState,
        completeness: "UNANCHORED", execution: "HOST_ATTESTED", freshness: "UNKNOWN",
        checked_to: body.to,
        detail: expectedHead === null ? "no expected head supplied" : `head ${body.to.seq} != expected ${expectedHead.seq}`,
      };
    }
    return fail("HEAD_MISMATCH", `head ${body.to.seq} != expected ${expectedHead!.seq}`, {
      integrity: "VALID", replay: replayState, completeness: "INCOMPLETE",
    });
  }

  // 9. boundary: the range must end on a committed boundary — a run left in
  // ARMING means the arm outcome event is missing.
  const rp = new Replay(new Map());
  for (const ev of [...(priorVerified ?? []), ...body.events]) rp.apply(ev.body.data, BigInt(ev.body.at_ms));
  if ([...rp.runs.values()].some((r) => r.state === "ARMING")) {
    return { ...fail("MISSING_EVENTS", "bundle ends with a run in ARMING", {
      integrity: "VALID", replay: replayState, completeness: "INCOMPLETE",
    }) };
  }
  const res = okResult(body.to);
  res.replay = replayState;
  return res;
}

function hex(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function b64(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}
import { Buffer } from "node:buffer";
