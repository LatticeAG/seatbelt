// Storage migration + chain integrity (spec §6.3). OSS storage version is 1.
// `migrate` verifies the complete event chain + semantic replay before any
// version transition and pins the expected head; a migration manifest is
// required for any forward version.

import { D, HASH_DOMAINS, SIGN_DOMAINS, verifyDigest } from "./crypto.js";
import { jcsBytes, parseJsonStrict } from "./canon.js";
import type { Json } from "./canon.js";
import type { EventBody, Head, SignedEvent, Trust } from "./schema.js";
import { GENESIS_PREV, validateMigrationManifest } from "./schema.js";
import { eventHash, type Store, STORAGE_VERSION } from "./store.js";
import { replayEvents } from "./verify.js";

export interface ChainCheck {
  ok: boolean;
  at: string;
  head: Head;
  detail?: string;
}

/** Full structural verification of the stored event chain (no signatures). */
export function verifyChain(store: Store): ChainCheck {
  const head = store.eventHead();
  let prev: Head = { seq: "0", hash: GENESIS_PREV };
  const all = store.eventsAfter(0n, Number.MAX_SAFE_INTEGER);
  for (const ev of all) {
    const expectedSeq = (BigInt(prev.seq) + 1n).toString();
    if (ev.body.seq !== expectedSeq || ev.body.prev !== prev.hash) {
      return { ok: false, at: ev.body.seq, head, detail: "chain link broken" };
    }
    if (eventHash(ev.body) !== ev.hash) {
      return { ok: false, at: ev.body.seq, head, detail: "event hash mismatch" };
    }
    prev = { seq: ev.body.seq, hash: ev.hash };
  }
  return { ok: true, at: prev.seq, head };
}

export interface MigrateResult {
  from: string;
  to: string;
  head: Head;
  verified: boolean;
  applied: string[];
}

/**
 * `seatbelt migrate`: verify integrity end-to-end (chain + signatures +
 * replay), pin the head, then apply the manifest for `target`. Version 1 is
 * the only storage version; a target above 1 requires a manifest file and
 * fails closed without one.
 */
export function migrate(store: Store, trust: Trust, target: string, expectedHead: Head, manifestBytes?: Uint8Array, checkOnly = false): MigrateResult {
  const current = (store.metaGet("storage_version") as string | undefined) ?? STORAGE_VERSION;
  const chain = verifyChain(store);
  if (!chain.ok) {
    throw new MigrateFault("MIGRATION_INTEGRITY", `chain break at seq ${chain.at}`);
  }
  if (chain.head.seq !== expectedHead.seq || chain.head.hash !== expectedHead.hash) {
    throw new MigrateFault("MIGRATION_INTEGRITY", `head ${chain.head.seq} != expected ${expectedHead.seq}`);
  }
  // signature pass: every event under the trust event key
  for (const ev of store.eventsAfter(0n, Number.MAX_SAFE_INTEGER)) {
    if (ev.key_id !== trust.event_key.key_id || !verifyDigest(SIGN_DOMAINS.EVENT, ev.hash, ev.sig, hexToBytes(trust.event_key.public_key))) {
      throw new MigrateFault("MIGRATION_INTEGRITY", `signature at seq ${ev.body.seq}`);
    }
  }
  const rep = replayEvents(store.eventsAfter(0n, Number.MAX_SAFE_INTEGER));
  if (!rep.ok) {
    throw new MigrateFault("MIGRATION_INTEGRITY", `replay at seq ${rep.at}: ${rep.detail}`);
  }
  if (target === current) {
    return { from: current, to: target, head: chain.head, verified: true, applied: [] };
  }
  if (BigInt(target) <= BigInt(current)) {
    throw new MigrateFault("MIGRATION_INTEGRITY", "no downgrade path");
  }
  if (!manifestBytes) {
    throw new MigrateFault("VERSION_UNSUPPORTED", `no manifest for target ${target}`);
  }
  const manifest = validateMigrationManifest(parseJsonStrict(new TextDecoder().decode(manifestBytes)));
  if (manifest.from !== current || manifest.to !== target) {
    throw new MigrateFault("MIGRATION_INTEGRITY", "manifest version mismatch");
  }
  if (manifest.expected_head.seq !== chain.head.seq || manifest.expected_head.hash !== chain.head.hash) {
    throw new MigrateFault("MIGRATION_INTEGRITY", "manifest expected_head mismatch");
  }
  // manifest signatures verify under the old trust's policy principals
  const manifestHash = D(HASH_DOMAINS.MIGRATION, {
    v: manifest.v, installation_id: manifest.installation_id, from: manifest.from, to: manifest.to,
    expected_head: manifest.expected_head, old_reducer: manifest.old_reducer, new_reducer: manifest.new_reducer,
    tool_hash: manifest.tool_hash, old_trust: manifest.old_trust, new_trust: manifest.new_trust,
    preserve_charged: manifest.preserve_charged,
  } as unknown as Json);
  const seen = new Set<string>();
  for (const s of manifest.signatures) {
    const principal = trust.principals.find((p) => p.key_id === s.key_id);
    if (!principal) continue;
    if (verifyDigest(SIGN_DOMAINS.MIGRATION, manifestHash, s.sig, hexToBytes(principal.public_key))) {
      seen.add(principal.principal_id);
    }
  }
  if (seen.size < Number(trust.threshold)) {
    throw new MigrateFault("MIGRATION_INTEGRITY", "manifest quorum unmet");
  }
  if (checkOnly) {
    return { from: current, to: target, head: chain.head, verified: true, applied: [] };
  }
  store.metaSet("storage_version", target);
  store.checkpointPut(BigInt(chain.head.seq), chain.head.hash, null);
  return { from: current, to: target, head: chain.head, verified: true, applied: [manifest.to] };
}

export class MigrateFault extends Error {
  readonly code: string;
  constructor(code: string, detail: string) {
    super(detail);
    this.code = code;
  }
}

function hexToBytes(h: string): Uint8Array {
  return new Uint8Array(Buffer.from(h, "hex"));
}
