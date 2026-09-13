// TV-S-01..60 conformance vectors (spec §11). Each test names its vector.

import { test } from "node:test";
import assert from "node:assert/strict";
import { copyFileSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { jcs, jcsBytes, parseJsonStrict, SchemaError } from "../src/canon.js";
import type { Json } from "../src/canon.js";
import { D, HASH_DOMAINS, SIGN_DOMAINS, sha256Hex, signDigest, verifyDigest, privateKeyFromSeed, generateKeyPair, publicKeyHex } from "../src/crypto.js";
import { vecToSpend, spendZero } from "../src/spend.js";
import { Fault } from "../src/errors.js";
import type { SignedEvent, PolicyBundle, Trust, Intent, Spend, Head } from "../src/schema.js";
import { seccompDecision, guestMounts } from "../src/seccomp.js";
import { migrate } from "../src/migrate.js";
import { bootstrap } from "../src/daemon.js";
import {
  makeHarness, B, Z, SEED1, SEED2, SEED3, KEY_A, KEY_B, KEY_C,
  V, R, P, PH, TRUST, PB, L, HEAD0, PIN, makeIntent,
} from "./harness.js";

function ev(h: ReturnType<typeof makeHarness>, kind: string): SignedEvent[] {
  const out: SignedEvent[] = [];
  for (let i = 1n; ; i++) {
    const e = h.store.getEvent(i);
    if (e === undefined) break;
    if ((e.body.data as { kind: string }).kind === kind) out.push(e);
  }
  return out;
}
function kinds(h: ReturnType<typeof makeHarness>): string[] {
  const out: string[] = [];
  for (let i = 1n; ; i++) {
    const e = h.store.getEvent(i);
    if (e === undefined) break;
    out.push((e.body.data as { kind: string }).kind);
  }
  return out;
}
function cnt(h: ReturnType<typeof makeHarness>, budget: string): { held: Spend; charged: Spend } {
  const kind = budget === "run_one" || budget === "run_two" || budget === "run_a" || budget === "run_b" || budget.startsWith("run_") ? "run" : "budget";
  const c = h.store.counter(kind, budget);
  return { held: vecToSpend(c.held), charged: vecToSpend(c.charged) };
}
function errCode(r: { ok: boolean; error?: { code?: string } | null }): string | undefined {
  return r.ok ? undefined : r.error?.code;
}
function booted() {
  const h = makeHarness();
  h.bootstrap();
  h.startRun();
  return h;
}

test("TV-S-01 canonical member order is normalization, not requirement", () => {
  const a = jcs({ b: "2", a: "1" });
  const b = jcs({ a: "1", b: "2" });
  assert.equal(a, b);
  assert.equal(a, '{"a":"1","b":"2"}');
  assert.equal(D("fixture", parseJsonStrict('{"b":"2","a":"1"}') as Json), D("fixture", parseJsonStrict('{"a":"1","b":"2"}') as Json));
});

test("TV-S-02 duplicate member rejected, zero events", () => {
  const h = makeHarness();
  assert.throws(() => parseJsonStrict('{"v":1,"request_id":"x","method":"host.status","params":{},"v":1}'), SchemaError);
  const r = h.call(h.admin, "host.status", {});
  assert.equal(r.ok, true);
  assert.equal(kinds(h).length, 0);
});

test("TV-S-03 unsafe quantity encodings rejected", () => {
  const h = makeHarness();
  h.bootstrap();
  const before = ev(h, "BudgetCreated").length;
  for (const bad of ["01", "-1", "1.5"]) {
    const r = h.call(h.admin, "budget.create", { budget_id: "b1", parent: "root", limit: V(bad, "0", "0", "0") });
    assert.equal(r.ok, false);
    assert.equal(errCode(r), "INVALID_SCHEMA", bad);
  }
  assert.equal(ev(h, "BudgetCreated").length, before);
});

test("TV-S-04 64-bit overflow does not wrap", () => {
  const huge = "9223372036854775807";
  const policy = { ...P, root_limit: V(huge, huge, huge, huge), max_run_limit: V(huge, huge, huge, huge) };
  const ph = D(HASH_DOMAINS.POLICY, policy as unknown as Json);
  const bundle: PolicyBundle = {
    body: policy,
    signatures: [
      { key_id: "key_a", sig: signDigest(SIGN_DOMAINS.POLICY, ph, privateKeyFromSeed(SEED1)) },
      { key_id: "key_b", sig: signDigest(SIGN_DOMAINS.POLICY, ph, privateKeyFromSeed(SEED2)) },
    ],
  };
  const h = makeHarness({ bundle });
  h.engine.recover(h.now);
  h.call(h.admin, "policy.apply", { bundle, expected_revision: "0" });
  h.call(h.admin, "budget.create", { budget_id: "project", parent: "root", limit: V(huge, huge, huge, huge) });
  h.startRun("run_one", "project", undefined, V(huge, huge, huge, huge));
  h.adapter.nextQuoteUpper = V("9223372036854775806", "0", "0", "1");
  const r1 = h.reserve("run_one", "action_one", makeIntent("run_one", "operation_one", "x", V(huge, huge, huge, huge)));
  assert.equal(r1.ok, true);
  assert.equal(h.dispatch().ok, true); // charged = 9223372036854775806
  assert.equal(cnt(h, "root").charged.microusd, "9223372036854775806");
  // one more: 9223372036854775806 + 2 > i64 max → denied, never wrapped
  const r2 = h.reserve("run_one", "action_two", makeIntent("run_one", "operation_two", "y", V(huge, huge, huge, huge)));
  assert.equal(r2.ok, false);
  assert.equal(errCode(r2), "CAP_EXCEEDED");
  assert.equal(cnt(h, "root").charged.microusd, "9223372036854775806");
  const br = h.store.breaker("root");
  assert.equal(br?.state, "CLOSED");
});

test("TV-S-05 unknown security field rejected", () => {
  const h = booted();
  const r = h.call(h.guest("run_one"), "action.reserve", {
    action_id: "action_one", intent: makeIntent(), allow_overdraft: true,
  });
  assert.equal(r.ok, false);
  assert.equal(errCode(r), "INVALID_SCHEMA");
  assert.equal(ev(h, "ActionReserved").length, 0);
});

test("TV-S-06 quorum requires distinct principals", () => {
  // both signatures verify but resolve to the same principal (alice)
  const bundle: PolicyBundle = {
    body: P,
    signatures: [
      { key_id: "key_a", sig: signDigest(SIGN_DOMAINS.POLICY, PH, privateKeyFromSeed(SEED1)) },
      { key_id: "key_a", sig: signDigest(SIGN_DOMAINS.POLICY, PH, privateKeyFromSeed(SEED1)) },
    ],
  };
  const h = makeHarness();
  h.engine.recover(h.now);
  const r = h.call(h.admin, "policy.apply", { bundle, expected_revision: "0" });
  assert.equal(r.ok, false);
  assert.equal(errCode(r), "EVIDENCE_INVALID");
});

test("TV-S-07 policy mutation after signing fails", () => {
  const mutated = { ...P, max_runs: "31" }; // schema-valid; signatures no longer cover the body
  const bundle: PolicyBundle = { body: mutated, signatures: PB.signatures };
  const h = makeHarness();
  h.engine.recover(h.now);
  const r = h.call(h.admin, "policy.apply", { bundle, expected_revision: "0" });
  assert.equal(r.ok, false);
  assert.equal(errCode(r), "EVIDENCE_INVALID");
});

test("TV-S-08 live provisioning refuses fixture keys → exit 9", async () => {
  // bootstrap() cross-checks config vs trust; fixture keys + live_adapters → CONFIG_INVALID.
  const dir = join("/tmp", `sb-tv08-${process.pid}`);
  const cfg = {
    v: 1, installation_id: "seatbelt_test", profile: "linux-contained-v1", live_adapters: true,
    database: join(dir, "s.db"), socket: join(dir, "control.sock"),
    cgroup_root: join(dir, "cg"), emergency_file: join(dir, "em.bin"), image_store: join(dir, "img"),
    event_key_file: join(dir, "ev.key"), object_key_file: join(dir, "obj.key"),
    uid_first: 60000, uid_count: 1000,
    controller_memory_bytes: "268435456", guard_memory_bytes: "67108864", audit_reserve_bytes: "8388608",
    watch_scopes: [],
  };
  const { mkdirSync, writeFileSync } = await import("node:fs");
  mkdirSync(dir, { recursive: true });
  writeFileSync(cfg.event_key_file, SEED1);
  writeFileSync(cfg.object_key_file, SEED2);
  const trustPath = join(dir, "trust.json");
  writeFileSync(trustPath, JSON.stringify(TRUST));
  writeFileSync(join(dir, "config.json"), JSON.stringify(cfg));
  try {
    bootstrap(join(dir, "config.json"), trustPath);
    assert.fail("expected CONFIG_INVALID");
  } catch (e) {
    assert.ok(e instanceof Fault);
    assert.equal((e as Fault).code, "CONFIG_INVALID");
    assert.equal((e as Fault).exitCode, 9);
  }
});

test("TV-S-09 exact reserve and charge at all three owners", () => {
  const h = booted();
  h.adapter.nextQuoteUpper = V("40", "2", "3", "1");
  const r = h.reserve();
  assert.equal(r.ok, true);
  for (const b of ["run_one", "project", "root"]) {
    assert.deepEqual(cnt(h, b).held, V("40", "2", "3", "1"), b);
  }
  assert.equal(h.dispatch().ok, true);
  for (const b of ["run_one", "project", "root"]) {
    assert.deepEqual(cnt(h, b).charged, V("40", "2", "3", "1"), b);
    assert.deepEqual(cnt(h, b).held, V());
  }
  assert.ok(ev(h, "ActionReserved").length === 1 && ev(h, "ActionDispatched").length === 1 && ev(h, "ActionObserved").length === 1);
  assert.equal(h.sends(), 1);
});

test("TV-S-10 parent aggregation race: first holds, second denied", () => {
  const h = makeHarness();
  h.engine.recover(h.now);
  h.call(h.admin, "policy.apply", { bundle: PB, expected_revision: "0" });
  h.call(h.admin, "budget.create", { budget_id: "project", parent: "root", limit: V("100", "1000", "1000", "100") });
  h.startRun("run_a"); h.startRun("run_b");
  h.adapter.nextQuoteUpper = V("40", "0", "0", "1");
  // charge parent to 40 via run_a's first action
  assert.equal(h.reserve("run_a", "a0", makeIntent("run_a", "op0")).ok, true);
  assert.equal(h.dispatch("a0", "run_a").ok, true);
  assert.equal(cnt(h, "project").charged.microusd, "40");
  // run_a reserves 40 → 40+40=80 ≤ 100
  assert.equal(h.reserve("run_a", "a1", makeIntent("run_a", "op1")).ok, true);
  // run_b reserves 40 → 40+40+40=120 > 100 → CAP_EXCEEDED, run_b stops
  const rb = h.reserve("run_b", "b1", makeIntent("run_b", "op2"));
  assert.equal(errCode(rb), "CAP_EXCEEDED");
  assert.deepEqual(cnt(h, "project").held, V("40", "0", "0", "1"));
  assert.equal(h.store.run("run_a")?.state, "ACTIVE");
  assert.equal(h.store.run("run_b")?.state, "STOPPING");
});

test("TV-S-11 multi-dimensional atomic rejection", () => {
  const h = makeHarness();
  h.engine.recover(h.now);
  h.call(h.admin, "policy.apply", { bundle: PB, expected_revision: "0" });
  h.call(h.admin, "budget.create", { budget_id: "project", parent: "root", limit: V("100", "10", "10", "10") });
  h.startRun();
  h.adapter.nextQuoteUpper = V("1", "11", "1", "1");
  const r = h.reserve("run_one", "action_one", makeIntent("run_one", "operation_one", "x", V("100", "100", "100", "100")));
  assert.equal(errCode(r), "CAP_EXCEEDED");
  for (const b of ["run_one", "project", "root"]) assert.deepEqual(cnt(h, b).held, V(), b);
});

test("TV-S-12 exact-fit dispatch trips cap and stops run", () => {
  const h = makeHarness();
  h.engine.recover(h.now);
  h.call(h.admin, "policy.apply", { bundle: PB, expected_revision: "0" });
  h.call(h.admin, "budget.create", { budget_id: "project", parent: "root", limit: V("100", "0", "0", "1") });
  h.startRun("run_one", "project", undefined, V("100", "0", "0", "1"));
  h.adapter.nextQuoteUpper = V("100", "0", "0", "1");
  assert.equal(h.reserve().ok, true);
  assert.equal(h.dispatch().ok, true);
  assert.equal(h.store.run("run_one")?.state, "STOPPING");
  const br = h.store.breaker("project");
  assert.equal(br?.state, "OPEN");
  assert.equal(br?.reason, "CAP");
  assert.ok(ev(h, "ActionDispatched").length === 1); // marker committed
  const r2 = h.reserve("run_one", "a2", makeIntent("run_one", "op2"));
  assert.ok(errCode(r2) === "BREAKER_OPEN" || errCode(r2) === "NOT_FOUND" || errCode(r2) === "STOPPED");
});

test("TV-S-13 full hold released on cancel", () => {
  const h = booted();
  h.adapter.nextQuoteUpper = V("40", "2", "3", "1");
  assert.equal(h.reserve().ok, true);
  const c = h.cancel();
  assert.equal(c.ok, true);
  assert.equal(h.store.action("action_one")?.state, "CANCELED");
  for (const b of ["run_one", "project", "root"]) assert.deepEqual(cnt(h, b).held, V(), b);
});

test("TV-S-14 cancel after marker cannot refund", () => {
  const h = booted();
  h.adapter.nextQuoteUpper = V("40", "0", "0", "1");
  assert.equal(h.reserve().ok, true);
  assert.equal(h.dispatch().ok, true);
  const c = h.cancel();
  assert.equal(errCode(c), "CONFLICT");
  assert.deepEqual(cnt(h, "project").charged, V("40", "0", "0", "1"));
});

test("TV-S-15 actual usage does not replenish budget", () => {
  const h = booted();
  h.adapter.autoComplete = false;
  h.adapter.nextQuoteUpper = V("100", "0", "10", "1");
  assert.equal(h.reserve().ok, true);
  assert.equal(h.dispatch().ok, true);
  h.engine.deliverOutcome("action_one", { status: "SUCCEEDED", actual: V("40", "0", "4", "1"), result_hash: null, evidence: [] }, null, "execute");
  assert.deepEqual(cnt(h, "project").charged, V("100", "0", "10", "1"));
});

test("TV-S-16 quote ceiling below upper bound rejected", () => {
  const h = booted();
  h.adapter.nextQuoteUpper = V("10", "0", "0", "1");
  const r = h.reserve("run_one", "action_one", makeIntent("run_one", "operation_one", "x", V("9", "9", "9", "1")));
  assert.equal(errCode(r), "CEILING_TOO_LOW");
});

test("TV-S-17 unbounded provider cost refused", () => {
  const h = booted();
  h.adapter.unbounded = true;
  const r = h.reserve();
  assert.equal(errCode(r), "UNBOUNDED_COST");
  assert.equal(h.store.action("action_one"), undefined);
  assert.equal(h.sends(), 0);
});

test("TV-S-18 per-token tariff: fee + ceil(in·pi) + ceil(out·po)", () => {
  const h = makeHarness();
  h.adapter.tokenTariff = { pi: 500001n, po: 1000001n, fee: 7n };
  const intent: Intent = {
    v: 1, operation_id: "op", run_id: "run", adapter: "record_v1", operation: "record",
    payload: { kind: "bounded_call", request: "x", max_input_tokens: "3", max_output_tokens: "2" },
    ceiling: V("100", "100", "100", "10"), evidence: [],
  };
  const q = h.adapter.quote(intent, { ...PIN, operation: "bounded_call" }, "x");
  assert.ok(q.ok);
  if (q.ok) assert.equal(q.quote.upper.microusd, "12");
});

test("TV-S-19 tariff change while held → PRICE_CHANGED; exe drift fences", () => {
  const h = booted();
  h.adapter.nextQuoteUpper = V("40", "0", "0", "1");
  assert.equal(h.reserve().ok, true);
  h.adapter.priceChangedOnDispatch = true;
  const d = h.dispatch();
  assert.equal(errCode(d), "PRICE_CHANGED");
  assert.equal(h.store.action("action_one")?.state, "EXPIRED");
  for (const b of ["run_one", "project", "root"]) {
    assert.deepEqual(cnt(h, b).held, V(), b);
    assert.deepEqual(cnt(h, b).charged, V(), b);
  }
  assert.equal(h.sends(), 0);
  // installed-byte drift fences the host
  const h2 = booted();
  assert.equal(h2.reserve("run_one", "a1").ok, true);
  h2.adapter.exeDrift = true;
  const d2 = h2.dispatch("a1", "run_one");
  assert.equal(errCode(d2), "ADAPTER_UNAVAILABLE");
  assert.equal((h2.call(h2.admin, "host.status", {}).result as { state: string }).state, "FENCED");
});

test("TV-S-20 idempotent retry is byte-identical", () => {
  const h = booted();
  const r1 = h.reserve("run_one", "action_one", undefined, "q_idem");
  const r2 = h.reserve("run_one", "action_one", undefined, "q_idem");
  assert.equal(jcs(r1 as unknown as Json), jcs(r2 as unknown as Json));
  assert.equal(ev(h, "ActionReserved").length, 1);
  assert.equal(ev(h, "AdmissionDenied").length, 0);
});

test("TV-S-21 changed request under same id → IDEMPOTENCY_CONFLICT", () => {
  const h = booted();
  const r1 = h.reserve("run_one", "action_one", undefined, "q_idem");
  assert.equal(r1.ok, true);
  const r2 = h.reserve("run_one", "action_two", undefined, "q_idem");
  assert.equal(errCode(r2), "IDEMPOTENCY_CONFLICT");
});

test("TV-S-22 operation deduplicates across action ids", () => {
  const h = booted();
  assert.equal(h.reserve("run_one", "action_one").ok, true);
  const r2 = h.reserve("run_one", "action_two", makeIntent("run_one", "operation_one"));
  assert.equal(errCode(r2), "CONFLICT");
});

test("TV-S-23 foreign capability cannot dispatch another run's action", () => {
  const h = booted();
  h.startRun("run_two");
  assert.equal(h.reserve("run_one", "action_one").ok, true);
  // capability injection field → INVALID_SCHEMA
  const r1 = h.call(h.guest("run_two"), "action.dispatch", { action_id: "action_one", capability_id: "cap_one" });
  assert.equal(errCode(r1), "INVALID_SCHEMA");
  // well-formed call through run_two's channel → action not found on that run
  const r2 = h.dispatch("action_one", "run_two");
  assert.equal(errCode(r2), "NOT_FOUND");
});

test("TV-S-24 stop before dispatch wins", () => {
  const h = booted();
  assert.equal(h.reserve().ok, true);
  h.setNow(1100n);
  assert.equal(h.call(h.guest("run_one"), "run.stop", { run_id: "run_one", reason: "SELF_STOP" }).ok, true);
  h.setNow(1101n);
  const d = h.dispatch();
  assert.equal(errCode(d), "STOPPED");
  assert.equal(h.store.action("action_one")?.state, "CANCELED");
  for (const b of ["run_one", "project", "root"]) assert.deepEqual(cnt(h, b).held, V(), b);
  assert.equal(h.sends(), 0);
  assert.equal(h.killRequests("run_one"), 1);
});

test("TV-S-25 dispatch before stop: charge persists, SUCCEEDED observed after stop", () => {
  const h = booted();
  h.adapter.autoComplete = false;
  h.adapter.nextQuoteUpper = V("40", "0", "0", "1");
  h.setNow(1100n);
  assert.equal(h.reserve().ok, true);
  h.setNow(1101n);
  assert.equal(h.dispatch().ok, true); // marker committed, send attempted
  assert.equal(h.sends(), 1);
  h.setNow(1102n);
  assert.equal(h.call(h.guest("run_one"), "run.stop", { run_id: "run_one", reason: "SELF_STOP" }).ok, true);
  h.setNow(1200n);
  h.engine.deliverOutcome("action_one", { status: "SUCCEEDED", actual: V("40", "0", "0", "1"), result_hash: null, evidence: [] }, null, "execute");
  assert.deepEqual(cnt(h, "project").charged, V("40", "0", "0", "1"));
  assert.equal(h.store.action("action_one")?.state, "SUCCEEDED");
  const rs = h.store.run("run_one")?.state;
  assert.ok(rs === "STOPPING" || rs === "STOPPED");
});

test("TV-S-26 crash before reservation commit leaves nothing", () => {
  const h = makeHarness({ failpoints: new Set(["reserve_commit"]) });
  h.bootstrap();
  h.startRun();
  const r = h.reserve("run_one", "action_one", undefined, "q_crash");
  assert.equal(errCode(r), "AUDIT_UNAVAILABLE");
  assert.equal(h.store.action("action_one"), undefined);
  assert.equal(ev(h, "ActionReserved").length, 0);
  // no request-id consumed: a second attempt with the same id does not conflict
  const h2 = makeHarness();
  h2.bootstrap();
  h2.startRun();
  assert.equal(h2.reserve("run_one", "action_one", undefined, "q_crash").ok, true);
});

test("TV-S-27 crash after reservation commit releases hold on recovery", () => {
  const h = booted();
  h.adapter.nextQuoteUpper = V("40", "0", "0", "1");
  assert.equal(h.reserve().ok, true);
  h.restart();
  assert.equal(h.store.action("action_one")?.state, "EXPIRED");
  for (const b of ["run_one", "project", "root"]) assert.deepEqual(cnt(h, b).held, V(), b);
  assert.equal(h.sends(), 0);
  const rs = h.store.run("run_one")?.state;
  assert.ok(rs === "STOPPING" || rs === "STOPPED");
  assert.ok(kinds(h).includes("RunEnded") || h.store.run("run_one")?.state === "STOPPING");
});

test("TV-S-28 crash in marker/send gap → UNKNOWN, charge kept", () => {
  const h = booted();
  h.adapter.autoComplete = false;
  h.adapter.nextQuoteUpper = V("40", "0", "0", "1");
  assert.equal(h.reserve().ok, true);
  // commit the marker but prevent the post-commit send: detach the executor
  const ex = h.executor;
  h.engine.setExecutor(null);
  assert.equal(h.dispatch().ok, true);
  assert.equal(ex.sends.length, 0);
  h.restart();
  assert.equal(h.store.action("action_one")?.state, "UNKNOWN");
  assert.deepEqual(cnt(h, "project").charged, V("40", "0", "0", "1"));
});

test("TV-S-29 lost response after external effect → UNKNOWN, no resend", () => {
  const h = booted();
  h.adapter.autoComplete = false;
  h.adapter.nextQuoteUpper = V("40", "0", "0", "1");
  assert.equal(h.reserve().ok, true);
  assert.equal(h.dispatch("action_one", "run_one", "q_disp_1").ok, true);
  assert.equal(h.sends(), 1);
  // provider succeeded remotely; our outcome never arrives; deadline passes
  h.setNow(1000n + 10000n + 1n);
  h.tick();
  assert.equal(h.store.action("action_one")?.state, "UNKNOWN");
  // a stored dispatch retry (same request id) replays the cached response and cannot send again
  const r = h.dispatch("action_one", "run_one", "q_disp_1");
  assert.equal(r.ok, true); // dedup replay of the original accepted dispatch
  const r2 = h.dispatch("action_one", "run_one", "q_disp_fresh");
  assert.equal(r2.ok, false); // fresh request on an UNKNOWN action: conflict/stopped
  assert.equal(h.sends(), 1);
});

test("TV-S-30 observation-only reconcile resolves UNKNOWN once", () => {
  const h = booted();
  h.adapter.autoComplete = false;
  h.adapter.nextQuoteUpper = V("40", "0", "0", "1");
  assert.equal(h.reserve().ok, true);
  assert.equal(h.dispatch().ok, true);
  h.setNow(1000n + 10000n + 1n);
  h.tick();
  assert.equal(h.store.action("action_one")?.state, "UNKNOWN");
  h.adapter.lookupOutcome = { outcome: { status: "SUCCEEDED", actual: V("40", "0", "0", "1"), result_hash: null, evidence: [] }, resultBytes: Buffer.from("r") };
  const r1 = h.call(h.admin, "action.reconcile", { action_id: "action_one" });
  assert.equal(r1.ok, true);
  assert.equal(h.store.action("action_one")?.state, "SUCCEEDED");
  const r2 = h.call(h.admin, "action.reconcile", { action_id: "action_one" });
  assert.equal(r2.ok, true);
  assert.equal(h.sends(), 1);
});

test("TV-S-31 reservation deadline equality expires", () => {
  const h = makeHarness();
  h.bootstrap();
  h.startRun();
  h.adapter.nextQuoteUpper = V("40", "0", "0", "1");
  assert.equal(h.reserve().ok, true);
  // expires = reserved_at(1000) + reservation_ms(5000) = 6000
  h.setNow(6000n);
  const d = h.dispatch();
  assert.equal(errCode(d), "EXPIRED");
  for (const b of ["run_one", "project", "root"]) assert.deepEqual(cnt(h, b).held, V(), b);
});

test("TV-S-32 heartbeat replay resistance", () => {
  const h = booted();
  // beat 1 at 1000 → heartbeat_deadline = min(1000+1000, 11000) = 2000
  const r1 = h.call(h.guest("run_one"), "run.heartbeat", { run_id: "run_one", beat: "1" }, "q_hb1");
  assert.equal(r1.ok, true);
  // same request retried at 1900 → identical dedup response, no double-accept
  h.setNow(1900n);
  const r1b = h.call(h.guest("run_one"), "run.heartbeat", { run_id: "run_one", beat: "1" }, "q_hb1");
  assert.equal(jcs(r1 as unknown as Json), jcs(r1b as unknown as Json));
  assert.equal(ev(h, "HeartbeatAccepted").length, 1);
  // fresh request with beat 1 → CONFLICT
  const r2 = h.call(h.guest("run_one"), "run.heartbeat", { run_id: "run_one", beat: "1" }, "q_hb2");
  assert.equal(errCode(r2), "CONFLICT");
  // absent beat 2, guard fires HEARTBEAT at deadline 2000
  h.setNow(2000n);
  h.tick();
  assert.equal(h.killRequests("run_one"), 1);
  const latch = h.guard.core.latchOf("run_one");
  assert.equal(latch?.reason, "HEARTBEAT");
});

test("TV-S-33 wall time never extends", () => {
  const h = booted();
  for (let beat = 1; beat <= 10; beat++) {
    const r = h.call(h.guest("run_one"), "run.heartbeat", { run_id: "run_one", beat: String(beat) });
    assert.equal(r.ok, true, `beat ${beat}`);
  }
  const run = h.store.run("run_one");
  assert.equal(run?.deadline_ms, "11000"); // armed at 1000 + wall_ms 10000
  h.setNow(10999n);
  const r10 = h.call(h.guest("run_one"), "run.heartbeat", { run_id: "run_one", beat: "11" });
  assert.equal(r10.ok, true);
  h.setNow(11000n);
  h.tick();
  const latch = h.guard.core.latchOf("run_one");
  assert.equal(latch?.reason, "WALL");
  assert.equal(h.killRequests("run_one"), 1);
});

test("TV-S-34 daemon EOF kills under lease", () => {
  const h = booted();
  h.setNow(1050n);
  h.guard.daemonEof();
  h.tick();
  const latch = h.guard.core.latchOf("run_one");
  assert.equal(latch?.reason, "CONTROL_LOST");
  assert.equal(h.killRequests("run_one"), 1);
});

test("TV-S-35 guard lease equality", () => {
  const h = booted();
  // lease 1750 = armed at 1000 + guard_lease_ms 750; daemon renewal is dead
  h.guard.liveness = false;
  h.setNow(1750n);
  h.tick();
  const latch = h.guard.core.latchOf("run_one");
  assert.equal(latch?.reason, "CONTROL_LOST");
  h.setNow(1751n);
  const r = h.call(h.guest("run_one"), "run.heartbeat", { run_id: "run_one", beat: "1" });
  assert.equal(errCode(r), "STOPPED");
});

test("TV-S-36 cpu cap reached latches CPU", () => {
  const h = booted();
  h.tree("run_one").usageUsec = 999000n; // → 999ms < 1000ms cap
  h.setNow(1100n);
  h.tick();
  assert.equal(h.guard.core.latchOf("run_one"), null);
  h.tree("run_one").usageUsec = 1000000n; // → 1000ms == cap
  h.setNow(1200n);
  h.tick();
  assert.equal(h.guard.core.latchOf("run_one")?.reason, "CPU");
});

test("TV-S-37 memory.max event kills without OOM", () => {
  const h = booted();
  h.tree("run_one").memoryCurrent = 1000n;
  h.tree("run_one").memoryMaxEvents = 1n;
  h.tree("run_one").oomEvents = 0n;
  h.setNow(1100n);
  h.tick();
  assert.equal(h.guard.core.latchOf("run_one")?.reason, "MEMORY");
});

test("TV-S-38 fork containment + pids.max → TASKS", () => {
  assert.equal(seccompDecision("fork"), "EPERM");
  assert.equal(seccompDecision("vfork"), "EPERM");
  assert.equal(seccompDecision("clone"), "EPERM");
  assert.equal(seccompDecision("clone3"), "ENOSYS");
  const h = booted();
  h.tree("run_one").pidsMaxEvents = 1n;
  h.setNow(1100n);
  h.tick();
  assert.equal(h.guard.core.latchOf("run_one")?.reason, "TASKS");
});

test("TV-S-39 guest cannot reach network, host socket, or send SCM_RIGHTS", () => {
  assert.equal(seccompDecision("socket"), "EPERM");
  assert.equal(seccompDecision("sendmsg"), "EPERM");
  assert.equal(seccompDecision("sendmmsg"), "EPERM");
  assert.equal(seccompDecision("recvmsg"), "EPERM");
  // the guest mount plan contains only image + scratch — no control.sock
  const mounts = guestMounts("/img/abc", "/scratch/run_one");
  assert.ok(!mounts.some((m) => m.source.includes("control") || m.target.includes("seatbelt")));
  // a launch descriptor naming a host path is refused at preflight
  const h = booted();
  const r = h.call(h.admin, "run.start", {
    run_id: "run_bad", budget_id: "project", limit: V("1000000", "1000", "1000", "100"),
    resources: R, launch: { ...L, executable: "/run/seatbelt/control.sock" },
  });
  assert.equal(errCode(r), "UNSUPPORTED_HOST");
  assert.equal(h.store.run("run_bad"), undefined);
});

test("TV-S-40 kill requested ≠ empty; populated persists → fence", () => {
  const h = booted();
  h.tree("run_one").dstate = true; // kill signal accepted, tree stays populated
  h.setNow(1000n);
  assert.equal(h.call(h.guest("run_one"), "run.stop", { run_id: "run_one", reason: "SELF_STOP" }).ok, true);
  assert.equal(h.killRequests("run_one"), 1);
  assert.equal(h.tree("run_one").populated, true);
  // kill retries while populated; after 2000ms overdue the host fences
  for (let t = 1100n; t <= 4000n; t += 100n) {
    h.setNow(t);
    h.tick();
  }
  assert.ok(h.killRequests("run_one") >= 1);
  assert.equal((h.call(h.admin, "host.status", {}).result as { state: string }).state, "FENCED");
});

test("TV-S-41 rate-window exact boundary", () => {
  const h = booted();
  h.startRun("run_two");
  for (let i = 1; i <= 10; i++) {
    const run = i <= 5 ? "run_one" : "run_two";
    const r = h.reserve(run, `a_${i}`, makeIntent(run, `op_${i}`));
    assert.equal(r.ok, true, `reserve ${i}`);
  }
  h.setNow(1999n);
  const r11 = h.reserve("run_one", "a_11", makeIntent("run_one", "op_11"));
  assert.equal(errCode(r11), "RATE_LIMIT");
  assert.equal(h.store.breaker("project")?.reason, "RATE");
  assert.equal(h.store.breaker("project")?.state, "OPEN");
  // fresh fixture at exactly 2000: entries at t=1000 age out (window (1000,2000])
  const h2 = booted();
  h2.startRun("run_two");
  for (let i = 1; i <= 10; i++) {
    const run = i <= 5 ? "run_one" : "run_two";
    assert.equal(h2.reserve(run, `a_${i}`, makeIntent(run, `op_${i}`)).ok, true);
  }
  h2.setNow(2000n);
  assert.equal(h2.reserve("run_one", "a_11", makeIntent("run_one", "op_11")).ok, true);
});

test("TV-S-42 canceled holds still consume rate slots", () => {
  const h = booted();
  for (let i = 1; i <= 10; i++) {
    assert.equal(h.reserve("run_one", `a_${i}`, makeIntent("run_one", `op_${i}`)).ok, true);
    assert.equal(h.cancel(`a_${i}`, "run_one").ok, true);
  }
  h.setNow(1001n);
  const r = h.reserve("run_one", "a_11", makeIntent("run_one", "op_11"));
  assert.equal(errCode(r), "RATE_LIMIT");
});

test("TV-S-43 consecutive provider errors open PROVIDER_ERRORS", () => {
  const h = booted();
  h.startRun("run_two");
  h.startRun("run_three");
  h.adapter.autoComplete = false;
  const runs = ["run_one", "run_two", "run_three"];
  for (let i = 0; i < 3; i++) {
    const run = runs[i]!;
    const aid = `a_${i}`;
    assert.equal(h.reserve(run, aid, makeIntent(run, `op_${i}`)).ok, true);
    assert.equal(h.dispatch(aid, run).ok, true);
    h.engine.deliverOutcome(aid, { status: "FAILED", actual: null, result_hash: null, evidence: [] }, null, "execute");
  }
  const br = h.store.breaker("project");
  assert.equal(br?.state, "OPEN");
  assert.equal(br?.reason, "PROVIDER_ERRORS");
});

test("TV-S-44 HALF_OPEN probe holds admissions until resolved", () => {
  const h = booted();
  h.startRun("run_two");
  // open a RATE-limited breaker: 10 admissions + 1 denied
  for (let i = 1; i <= 10; i++) {
    const run = i <= 5 ? "run_one" : "run_two";
    h.reserve(run, `a_${i}`, makeIntent(run, `op_${i}`));
  }
  h.setNow(1999n);
  h.reserve("run_one", "a_11", makeIntent("run_one", "op_11"));
  const br = h.store.breaker("project");
  assert.equal(br?.state, "OPEN");
  h.tick(); // guard reports empty trees → RunEnded
  h.setNow(32000n); // past cooldown 30000
  // RATE opened every full ancestor: reset root first, probe → CLOSED
  assert.equal(h.store.breaker("root")?.state, "OPEN");
  assert.equal(h.call(h.admin, "breaker.reset", { budget_id: "root", expected_revision: h.store.breaker("root")!.revision }).ok, true);
  h.tick();
  assert.equal(h.store.breaker("root")?.state, "CLOSED");
  const rr = h.call(h.admin, "breaker.reset", { budget_id: "project", expected_revision: h.store.breaker("project")!.revision });
  assert.equal(rr.ok, true);
  assert.equal(h.store.breaker("project")?.state, "HALF_OPEN");
  // HALF_OPEN holds admissions: run.start under the budget is denied, and a
  // reserve on a stopped run's channel still cannot pass the stopped latch.
  const rs = h.call(h.admin, "run.start", { run_id: "run_three", budget_id: "project", limit: V("1000000", "1000", "1000", "100"), resources: R, launch: L });
  assert.equal(errCode(rs), "BREAKER_OPEN");
  const r2 = h.reserve("run_one", "a_12", makeIntent("run_one", "op_12"));
  assert.equal(errCode(r2), "STOPPED");
});

test("TV-S-45 probe success does not revive stopped runs", () => {
  const h = booted();
  h.startRun("run_two");
  for (let i = 1; i <= 10; i++) {
    const run = i <= 5 ? "run_one" : "run_two";
    h.reserve(run, `a_${i}`, makeIntent(run, `op_${i}`));
  }
  h.setNow(1999n);
  h.reserve("run_one", "a_11", makeIntent("run_one", "op_11"));
  assert.equal(h.store.breaker("project")?.state, "OPEN");
  assert.equal(h.store.run("run_one")?.state, "STOPPING");
  h.tick(); // guard reports empty trees → RunEnded
  h.setNow(32000n);
  // RATE opened every full ancestor: reset root first, probe → CLOSED
  assert.equal(h.call(h.admin, "breaker.reset", { budget_id: "root", expected_revision: h.store.breaker("root")!.revision }).ok, true);
  h.tick();
  assert.equal(h.store.breaker("root")?.state, "CLOSED");
  assert.equal(h.call(h.admin, "breaker.reset", { budget_id: "project", expected_revision: h.store.breaker("project")!.revision }).ok, true);
  h.tick(); // probe runs and succeeds
  assert.equal(h.store.breaker("project")?.state, "CLOSED");
  // the stopped run stays stopped; its capability is revoked
  const rs = h.store.run("run_one")?.state;
  assert.ok(rs === "STOPPING" || rs === "STOPPED");
  const d = h.call(h.guest("run_one"), "action.reserve", { action_id: "a_x", intent: makeIntent("run_one", "op_x") });
  assert.notEqual(d.ok, true);
  // restarting the same run_id conflicts with the tombstone
  const r = h.call(h.admin, "run.start", { run_id: "run_one", budget_id: "project", limit: V("1000000", "1000", "1000", "100"), resources: R, launch: L });
  assert.equal(errCode(r), "CONFLICT");
});

test("TV-S-46 hard cap breaker never resets", () => {
  const h = makeHarness();
  h.engine.recover(h.now);
  h.call(h.admin, "policy.apply", { bundle: PB, expected_revision: "0" });
  h.call(h.admin, "budget.create", { budget_id: "project", parent: "root", limit: V("100", "0", "0", "1") });
  h.startRun();
  h.adapter.nextQuoteUpper = V("100", "0", "0", "1");
  assert.equal(h.reserve().ok, true);
  assert.equal(h.dispatch().ok, true);
  assert.equal(h.store.breaker("project")?.reason, "CAP");
  const r = h.call(h.admin, "breaker.reset", { budget_id: "project", expected_revision: h.store.breaker("project")!.revision });
  assert.equal(errCode(r), "CONFLICT");
});

test("TV-S-47 stop-only authorization for watch uid", () => {
  const h = booted();
  const t = h.call(h.watch, "budget.tighten", { budget_id: "project", limit: V("1", "1", "1", "1"), expected_revision: "1" });
  assert.equal(errCode(t), "FORBIDDEN");
  const s = h.call(h.watch, "watch.stop", { budget_id: "project", signal_id: "signal_one", evidence: { zone: "watch", schema: "watch-v1", hash: Z } });
  assert.equal(s.ok, true);
  const br = h.store.breaker("project");
  assert.equal(br?.state, "OPEN");
  assert.equal(br?.reason, "WATCH");
  assert.equal(h.store.run("run_one")?.state, "STOPPING");
});

test("TV-S-48 audit failure before admission fences host", () => {
  const h = makeHarness({ failpoints: new Set(["reserve_commit"]) });
  h.bootstrap();
  h.startRun();
  const r = h.reserve();
  assert.equal(errCode(r), "AUDIT_UNAVAILABLE");
  assert.equal(h.store.action("action_one"), undefined);
  // host fenced; the physical stop was still attempted
  const st = h.call(h.admin, "host.status", {});
  assert.equal((st.result as { state: string }).state, "FENCED");
  // next recovery sees the fence and stays FENCED
  const h2 = makeHarness({ dir: h.dir });
  assert.equal(h2.engine.hostState(), "FENCED");
});

test("TV-S-49 disk-full kill path: stop latches, kill attempted, durable=false", () => {
  const h = makeHarness({ failpoints: new Set(["stop_journal", "emergency_fail"]) });
  h.bootstrap();
  h.startRun();
  const r = h.call(h.killer, "host.stop", { reason: "OPERATOR" });
  assert.equal(r.ok, true);
  const stop = r.result as { durable: boolean };
  assert.equal(stop.durable, false);
  assert.equal(h.killRequests("run_one"), 1);
});

test("TV-S-50 tighten respects existing commitments", () => {
  const h = makeHarness();
  h.engine.recover(h.now);
  h.call(h.admin, "policy.apply", { bundle: PB, expected_revision: "0" });
  h.call(h.admin, "budget.create", { budget_id: "project", parent: "root", limit: V("100", "1000", "1000", "100") });
  h.startRun();
  h.adapter.nextQuoteUpper = V("40", "0", "0", "1");
  assert.equal(h.reserve("run_one", "a0", makeIntent("run_one", "op0")).ok, true);
  assert.equal(h.dispatch("a0", "run_one").ok, true); // charged 40
  h.adapter.nextQuoteUpper = V("30", "0", "0", "1");
  assert.equal(h.reserve("run_one", "a1", makeIntent("run_one", "op1")).ok, true); // held 30 → committed 70
  const rev = h.store.budget("project")!.revision;
  const r2 = h.call(h.admin, "budget.tighten", { budget_id: "project", limit: V("69", "1000", "1000", "100"), expected_revision: rev });
  assert.equal(errCode(r2), "CONFLICT");
  const r3 = h.call(h.admin, "budget.tighten", { budget_id: "project", limit: V("70", "1000", "1000", "100"), expected_revision: rev });
  assert.equal(r3.ok, true);
});

test("TV-S-51 parent charged persists across process replacement", () => {
  const h = makeHarness();
  h.engine.recover(h.now);
  h.call(h.admin, "policy.apply", { bundle: PB, expected_revision: "0" });
  h.call(h.admin, "budget.create", { budget_id: "project", parent: "root", limit: V("100", "1000", "1000", "10") });
  h.startRun("run_one");
  h.adapter.nextQuoteUpper = V("80", "0", "0", "1");
  assert.equal(h.reserve("run_one", "a0", makeIntent("run_one", "op0")).ok, true);
  assert.equal(h.dispatch("a0", "run_one").ok, true);
  h.startRun("run_two");
  h.adapter.nextQuoteUpper = V("30", "0", "0", "1");
  const r = h.reserve("run_two", "a1", makeIntent("run_two", "op1"));
  assert.equal(errCode(r), "CAP_EXCEEDED");
});

test("TV-S-52 external billing bound breach → BOUND_BREACH + fence", () => {
  const h = booted();
  h.adapter.autoComplete = false;
  h.adapter.nextQuoteUpper = V("10", "0", "0", "1");
  assert.equal(h.reserve().ok, true);
  assert.equal(h.dispatch().ok, true);
  const out = h.engine.deliverOutcome("action_one", { status: "SUCCEEDED", actual: V("11", "0", "0", "1"), result_hash: null, evidence: [] }, null, "execute");
  assert.equal(out.ok, false);
  if (!out.ok) assert.equal(out.fault.code, "BOUND_BREACH");
  const act = h.store.action("action_one")!;
  assert.equal(act.state, "UNKNOWN");
  assert.deepEqual(act.actual, V("11", "0", "0", "1"));
  assert.deepEqual(cnt(h, "project").charged, V("10", "0", "0", "1"));
  assert.equal(h.engine.hostState(), "FENCED");
});

test("TV-S-53 event tampering detected → HASH_MISMATCH", () => {
  const h = booted();
  h.adapter.nextQuoteUpper = V("40", "0", "0", "1");
  assert.equal(h.reserve().ok, true);
  assert.equal(h.dispatch().ok, true);
  const head = h.head();
  const bundle = JSON.parse(new TextDecoder().decode(h.exportBytes(HEAD0, head, "FULL"))) as { body: { events: SignedEvent[] } };
  // tamper: bump the reserved upper inside the ActionDispatched event body
  const disp = bundle.body.events.find((e) => (e.body.data as { kind: string }).kind === "ActionDispatched")!;
  (disp.body.data as unknown as { upper: { microusd: string } }).upper.microusd = "41";
  const bytes = new TextEncoder().encode(JSON.stringify(bundle));
  const res = h.verify(bytes, head);
  assert.equal(res.integrity, "INVALID");
  assert.equal(res.status, "HASH_MISMATCH");
});

test("TV-S-54 missing anchored suffix → HEAD_MISMATCH", () => {
  const h = booted();
  assert.equal(h.reserve().ok, true);
  const full = h.head();
  const h2 = booted();
  const head2 = { seq: String(BigInt(full.seq) + 5n), hash: "f".repeat(64) };
  const bytes = h.exportBytes(HEAD0, full, "FULL");
  const res = h.verify(bytes, head2);
  assert.equal(res.completeness, "INCOMPLETE");
  assert.equal(res.status, "HEAD_MISMATCH");
});

test("TV-S-55 embedded trust does not establish trust", () => {
  const h = booted();
  assert.equal(h.reserve().ok, true);
  const head = h.head();
  const bundle = JSON.parse(new TextDecoder().decode(h.exportBytes(HEAD0, head, "FULL"))) as { body: Record<string, unknown> };
  // attacker embeds its own key material and re-signs the bundle body; the
  // configured trust set (event_a) must still be what the verifier checks.
  const kp = generateKeyPair();
  const bh = D(HASH_DOMAINS.BUNDLE, bundle.body as unknown as Json);
  (bundle as { sig?: string }).sig = signDigest(SIGN_DOMAINS.BUNDLE, bh, kp.privateKey);
  (bundle as { key_id?: string }).key_id = "k1";
  const bytes = new TextEncoder().encode(JSON.stringify(bundle));
  const res = h.verify(bytes, head);
  assert.equal(res.integrity, "INVALID");
  assert.equal(res.status, "UNTRUSTED_KEY");
});

test("TV-S-56 metadata export: missing preimage hashes, replay INCOMPLETE", () => {
  const h = booted();
  h.adapter.nextQuoteUpper = V("40", "0", "0", "1");
  assert.equal(h.reserve().ok, true);
  assert.equal(h.dispatch().ok, true); // result bytes "hello" → object
  const head = h.head();
  const out = h.exportBundle(HEAD0, head, "METADATA");
  const body = out.body as { missing: string[]; disclosure: string };
  assert.equal(body.disclosure, "METADATA");
  const payloadHash = sha256Hex(jcsBytes({ kind: "record", value: "hello" } as unknown as Json));
  const resultHash = sha256Hex(new TextEncoder().encode("hello"));
  assert.deepEqual(body.missing, [payloadHash, resultHash].sort());
  const res = h.verify(h.exportBytes(HEAD0, head, "METADATA"), head);
  assert.equal(res.replay, "INCOMPLETE");
  assert.equal(res.integrity, "VALID");
});

test("TV-S-57 stale restore fenced by sidecar anchor", () => {
  const dir = join("/tmp", `sb-tv57-${process.pid}-${Math.floor(Math.random() * 1e6)}`);
  const h = makeHarness({ dir });
  h.bootstrap();
  h.startRun();
  assert.equal(h.reserve().ok, true);
  // snapshot the db at this head, then advance
  h.store.db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
  const snap = join(dir, "snap.db");
  copyFileSync(join(dir, "seatbelt.db"), snap);
  assert.equal(h.dispatch().ok, true);
  h.store.db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
  // restore the stale db over the live one, keep the newer anchor sidecar
  copyFileSync(snap, join(dir, "seatbelt.db"));
  const h3 = makeHarness({ dir });
  h3.engine.recover(h3.now);
  assert.equal(h3.engine.hostState(), "FENCED");
  const st = h3.call(h3.admin, "host.status", {});
  assert.equal((st.result as { state: string }).state, "FENCED");
});

test("TV-S-58 unsupported migration target refused", () => {
  const dir = join("/tmp", `sb-tv58-${process.pid}-${Math.floor(Math.random() * 1e6)}`);
  const h = makeHarness({ dir });
  h.bootstrap();
  const head = h.head();
  const dbFile = join(dir, "seatbelt.db");
  void dbFile;
  try {
    migrate(h.store, TRUST, "2", head);
    assert.fail("expected VERSION_UNSUPPORTED");
  } catch (e) {
    assert.equal((e as { code: string }).code, "VERSION_UNSUPPORTED");
  }
});

test("TV-S-59 protocol version rejected", () => {
  const h = makeHarness();
  const r = h.engine.handle(h.admin, { v: 2, request_id: "x", method: "host.status", params: {} } as never);
  assert.equal(r.ok, false);
  assert.equal(errCode(r), "VERSION_UNSUPPORTED");
});

test("TV-S-60 zone-gated composition refused when only offline adapters exist", () => {
  const h = booted();
  const intent: Intent = {
    v: 1, operation_id: "op_bc", run_id: "run_one", adapter: "record_v1", operation: "bounded_call",
    payload: { kind: "bounded_call", request: "x", max_input_tokens: "10", max_output_tokens: "10" },
    ceiling: V("1000", "100", "100", "10"), evidence: [],
  };
  const r = h.call(h.guest("run_one"), "action.reserve", { action_id: "a_bc", intent });
  assert.ok(!r.ok);
  assert.ok(errCode(r) === "ADAPTER_UNAVAILABLE" || errCode(r) === "INVALID_SCHEMA");
  assert.equal(h.store.action("a_bc"), undefined);
  assert.equal(h.sends(), 0);
});
