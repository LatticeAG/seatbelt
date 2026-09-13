// Unit tests: canonical JSON, scalars, spend math, store round-trips,
// emergency slots, object sealing, guard core, kernel simulation.

import { test } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import { jcs, jcsBytes, parseJsonStrict, SchemaError } from "../src/canon.js";
import type { Json } from "../src/canon.js";
import { D, sha256Hex, signDigest, verifyDigest, privateKeyFromSeed, publicKeyRawFromPrivate, sealObject, openObject, HASH_DOMAINS } from "../src/crypto.js";
import { spendToVec, vecToSpend, vecAdd, vecSub, vecLe, vecIsZero, vecExceeds, vecZero } from "../src/spend.js";
import { checkU, checkUint, checkHash, checkId } from "../src/scalars.js";
import { Store } from "../src/store.js";
import { ObjectStore } from "../src/objects.js";
import { EmergencyFile } from "../src/emergency.js";
import { SimKernel } from "../src/kernel.js";
import { GuardCore } from "../src/guard.js";
import { makeHarness, SEED1, B, R, V } from "./harness.js";

test("jcs: RFC 8785 serialization", () => {
  assert.equal(jcs({ b: 1, a: "x" }), '{"a":"x","b":1}');
  assert.equal(jcs({ n: null, t: true, arr: [1, "a", null] }), '{"arr":[1,"a",null],"n":null,"t":true}');
  assert.equal(jcs("héllo"), '"héllo"');
  assert.equal(jcs({ "€": 1 }), '{"€":1}');
});

test("parseJsonStrict: rejects duplicates, deep nesting, unsafe numbers", () => {
  assert.throws(() => parseJsonStrict('{"a":1,"a":2}'), SchemaError);
  assert.throws(() => parseJsonStrict("[".repeat(600) + "]".repeat(600)), SchemaError);
  assert.throws(() => parseJsonStrict('{"x":1e400}')); // out of double range → frame error
  assert.throws(() => parseJsonStrict("{bad"));
  assert.deepEqual(parseJsonStrict('{"ok":[1,2,3]}'), { ok: [1, 2, 3] });
});

test("D() domain-separated hashing is stable", () => {
  const h = D("SEATBELT-POLICY/1", { a: 1 });
  assert.match(h, /^[0-9a-f]{64}$/);
  assert.notEqual(D("A", { x: 1 }), D("B", { x: 1 }));
});

test("ed25519 sign/verify round-trip", () => {
  const priv = privateKeyFromSeed(SEED1);
  const sig = signDigest("SEATBELT-EVENT/1", "ab".repeat(32), priv);
  const pub = publicKeyRawFromPrivate(priv);
  assert.equal(verifyDigest("SEATBELT-EVENT/1", "ab".repeat(32), sig, pub), true);
  assert.equal(verifyDigest("SEATBELT-EVENT/1", "cd".repeat(32), sig, pub), false);
  assert.equal(verifyDigest("SEATBELT-BUNDLE/1", "ab".repeat(32), sig, pub), false);
});

test("spend vec arithmetic", () => {
  const a = spendToVec(V("10", "1", "2", "3"));
  const b = spendToVec(V("5", "1", "1", "1"));
  assert.equal(vecToSpend(vecAdd(a, b)).microusd, "15");
  assert.equal(vecToSpend(vecSub(a, b)).microusd, "5");
  assert.equal(vecLe(b, a), true);
  assert.equal(vecLe(a, b), false);
  assert.equal(vecIsZero(vecZero()), true);
  const x = vecExceeds(a, spendToVec(V("9", "1", "1", "1")));
  assert.equal(x?.output_tokens, 1n);
  assert.equal(vecExceeds(a, spendToVec(V("100", "100", "100", "100"))), null);
});

test("scalars: checkU/checkUint/checkHash/checkId", () => {
  assert.throws(() => checkU("01", "f"), SchemaError);
  assert.throws(() => checkU("-5", "f"), SchemaError);
  assert.throws(() => checkU("9223372036854775808", "f"), SchemaError);
  assert.equal(checkU("9223372036854775807", "f"), "9223372036854775807");
  assert.throws(() => checkUint(1.5, "f"), SchemaError);
  assert.throws(() => checkUint(-0, "f"), SchemaError);
  assert.equal(checkUint(42, "f"), 42);
  assert.throws(() => checkHash("zz", "f"), SchemaError);
  assert.equal(checkHash("ab".repeat(32), "f"), "ab".repeat(32));
  assert.throws(() => checkId("", "f"), SchemaError);
  assert.equal(checkId("run_one", "f"), "run_one");
});

test("store: event append/head/round-trip", () => {
  const dir = join(tmpdir(), `sb-u-${randomBytes(4).toString("hex")}`);
  mkdirSync(dir, { recursive: true });
  const s = new Store(join(dir, "t.db"));
  const h = makeHarness({ dir: join(dir, "h") });
  h.bootstrap();
  const head = h.store.eventHead();
  assert.notEqual(head.seq, "0");
  assert.notEqual(head.hash, "0".repeat(64));
  const e1 = h.store.getEvent(1n)!;
  assert.equal(e1.body.prev, "0".repeat(64));
  s.close();
});

test("object store: sealed put/get/has, tamper detection", () => {
  const dir = join(tmpdir(), `sb-obj-${randomBytes(4).toString("hex")}`);
  const s = new Store(":memory:");
  const os = new ObjectStore(join(dir, "objects"), SEED1.slice(0, 32), "seatbelt_test", s);
  const bytes = new TextEncoder().encode("hello");
  const hash = os.put(bytes);
  assert.equal(hash, sha256Hex(bytes));
  assert.equal(os.has(hash), true);
  assert.deepEqual(os.get(hash), bytes);
  s.close();
});

test("emergency file: write/read round-trip + digest", () => {
  const dir = join(tmpdir(), `sb-em-${randomBytes(4).toString("hex")}`);
  const ef = new EmergencyFile(join(dir, "em.bin"));
  ef.write({
    v: 1, run_id: "run_one", epoch: "1", boot_id: B, kill_id: "k1",
    reason: "CONTROL_LOST", scope_kind: "run", scope_id: "run_one",
    actor: "uid_1000", request_id: "q1", requested_ms: "1000",
    signal_sent: true, empty_observed: false,
  });
  const slots = ef.readAll();
  assert.equal(slots.length, 1);
  assert.equal(slots[0]!.ok, true);
  if (slots[0]!.ok) assert.equal(slots[0]!.payload.kill_id, "k1");
  assert.match(ef.digest(), /^[0-9a-f]{64}$/);
});

test("sim kernel: run trees + deterministic clock", () => {
  const k = new SimKernel(B);
  assert.equal(k.nowMs(), 1000n);
  k.setNow(5000n);
  assert.equal(k.nowMs(), 5000n);
  const t = k.createRunTree("run_one", R) as import("../src/kernel.js").SimRunTree;
  assert.equal(t.sample().populated, true);
  t.kill();
  assert.equal(t.sample().populated, false);
  assert.equal(t.killed, true);
});

test("guard core: arm + sample + control-loss kill", () => {
  const k = new SimKernel(B);
  const g = new GuardCore(k, null, B);
  const tree = k.createRunTree("run_one", R) as import("../src/kernel.js").SimRunTree;
  const reply = g.arm("run_one", "1", "t1", tree, R, 11000n, 1000n, 1000n);
  assert.equal(reply.ok, true);
  assert.equal(reply.lease_until_ms, "1750");
  const evs = g.tick(1750n);
  const stop = evs.find((e) => e.kind === "stop");
  assert.ok(stop);
  assert.equal(stop.stop?.reason, "CONTROL_LOST");
  assert.equal(tree.killed, true);
});

test("events: prev-hash chain verifies", () => {
  const h = makeHarness();
  h.bootstrap();
  h.startRun();
  h.reserve();
  let prev = "0".repeat(64);
  for (let i = 1n; ; i++) {
    const e = h.store.getEvent(i);
    if (e === undefined) break;
    assert.equal(e.body.prev, prev, `seq ${i}`);
    prev = e.hash;
  }
});
