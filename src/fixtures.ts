// Spec §11.1 fixtures: P/T/L/C/Cfg builders and the Ed25519 key material used
// to sign policy bundles. Production deployments generate their own keys;
// these helpers are the bootstrap/signing seams shared by the CLI `init`
// helper, the test harness, and operator tooling.

import { generateKeyPairSync } from "node:crypto";
import { D, HASH_DOMAINS, SIGN_DOMAINS, signDigest, privateKeyFromSeed, publicKeyRawFromPrivate } from "./crypto.js";
import { jcsBytes } from "./canon.js";
import type { Json } from "./canon.js";
import type {
  BreakerPolicy, Launch, Policy, PolicyBundle, ResourceCaps, Signature, Spend, Trust,
} from "./schema.js";
import { FIXED_TIMINGS } from "./profile.js";

export interface KeyPair {
  keyId: string;
  seed: Uint8Array; // 32-byte private seed (file format: raw 32 bytes)
  public: Uint8Array;
}

export function generateKey(keyId: string): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  const seed = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32);
  return { keyId, seed: new Uint8Array(seed), public: new Uint8Array(pub) };
}

export function publicKeyFromSeed(seed: Uint8Array): Uint8Array {
  return publicKeyRawFromPrivate(privateKeyFromSeed(seed));
}

function hex(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}

/** Sign a policy body → Signature under SEATBELT-POLICY-SIGN/1. */
export function signPolicyBody(body: Policy, kp: KeyPair): Signature {
  const hash = D(HASH_DOMAINS.POLICY, body as unknown as Json);
  return { key_id: kp.keyId, sig: signDigest(SIGN_DOMAINS.POLICY, hash, privateKeyFromSeed(kp.seed)) };
}

export const DEFAULT_BREAKER: BreakerPolicy = {
  max_admissions: "10", window_ms: "1000", consecutive_errors: "3",
  cooldown_ms: "30000", probe_timeout_ms: "1000",
};

export interface PolicyOpts {
  policyId?: string;
  revision?: string;
  previous?: string | null;
  rootBudget?: string;
  rootLimit?: Spend;
  reservationMs?: string;
  heartbeatMs?: string;
  maxRuns?: string;
  maxRunLimit?: Spend;
  maxResources?: ResourceCaps;
  adapters?: Policy["adapters"];
  adminUids?: number[];
  observerUids?: number[];
  killerUids?: number[];
  watchUids?: number[];
  breaker?: BreakerPolicy;
}

export function buildPolicy(opts: PolicyOpts = {}): Policy {
  return {
    policy_id: opts.policyId ?? "pol_one",
    v: 1,
    revision: opts.revision ?? "1",
    previous: opts.previous ?? null,
    root_budget: opts.rootBudget ?? "root",
    root_limit: opts.rootLimit ?? { microusd: "100", input_tokens: "0", output_tokens: "0", calls: "1" },
    reservation_ms: opts.reservationMs ?? "5000",
    heartbeat_ms: opts.heartbeatMs ?? "1000",
    max_runs: opts.maxRuns ?? "4",
    max_run_limit: opts.maxRunLimit ?? { microusd: "100", input_tokens: "0", output_tokens: "0", calls: "1" },
    max_resources: opts.maxResources ?? {
      wall_ms: "60000", cpu_ms: "60000", memory_bytes: "67108864",
      scratch_bytes: "33554432", tasks: "4", cpu_quota_us: "50000", cpu_period_us: "100000",
    },
    breaker: opts.breaker ?? DEFAULT_BREAKER,
    guard_lease_ms: "750", sample_ms: "100",
    adapters: opts.adapters ?? [{
      adapter: "record_v1", executable_hash: D(HASH_DOMAINS.QUOTE, { adapter: "record_v1" } as unknown as Json),
      operation: "record", tariff: recordTariff(), max_payload_bytes: "16384",
      max_duration_ms: "2000", max_response_bytes: "16384", live: false,
    }],
    admin_uids: opts.adminUids ?? [1001],
    observer_uids: opts.observerUids ?? [1002],
    killer_uids: opts.killerUids ?? [1003],
    watch_uids: opts.watchUids ?? [1004],
  };
}

/** Build a bundle signed by the given keys (order = given order). */
export function buildBundle(body: Policy, keys: KeyPair[]): PolicyBundle {
  return { body, signatures: keys.map((k) => signPolicyBody(body, k)) };
}

/** Trust file: three principals, threshold 2, one event key. */
export function buildTrust(installationId: string, principals: KeyPair[], eventKey: KeyPair): Trust {
  return {
    v: 1, installation_id: installationId, threshold: 2,
    principals: principals.map((k) => ({ principal_id: k.keyId, key_id: k.keyId, public_key: hex(k.public) })),
    event_key: { key_id: eventKey.keyId, public_key: hex(eventKey.public) },
  };
}

export function buildLaunch(over: Partial<Launch> = {}): Launch {
  return { image: D(HASH_DOMAINS.EVENT, { label: "guest-image" } as unknown as Json), executable: "/usr/bin/true", argv: ["/usr/bin/true"], ...over };
}

export function buildCaps(over: Partial<ResourceCaps> = {}): ResourceCaps {
  return {
    wall_ms: "60000", cpu_ms: "60000", memory_bytes: "67108864",
    scratch_bytes: "33554432", tasks: "4", cpu_quota_us: "50000", cpu_period_us: "100000", ...over,
  };
}

export function recordIntent(runId: string, operationId: string, value: string, ceiling?: Spend): {
  v: 1; run_id: string; operation_id: string; adapter: string; operation: "record";
  ceiling: Spend; payload: { kind: "record"; value: string };
} {
  return {
    v: 1, run_id: runId, operation_id: operationId, adapter: "record_v1", operation: "record",
    ceiling: ceiling ?? { microusd: "100", input_tokens: "0", output_tokens: "0", calls: "1" },
    payload: { kind: "record", value },
  };
}

export function recordTariff(): string {
  return D(HASH_DOMAINS.QUOTE, { tariff: "record_v1", v: 1 } as unknown as Json);
}

/** The canonical fixture policy used across the vector suite. */
export function fixturePolicy(keys: { adminUids?: number[] } = {}): Policy {
  const p = buildPolicy({ ...(keys.adminUids !== undefined ? { adminUids: keys.adminUids } : {}) });
  p.adapters = [{
    adapter: "record_v1", executable_hash: D(HASH_DOMAINS.QUOTE, { adapter: "record_v1" } as unknown as Json),
    operation: "record", tariff: recordTariff(), max_payload_bytes: "16384",
    max_duration_ms: "2000", max_response_bytes: "16384", live: false,
  }];
  return p;
}

export function signEventsFactory(eventKey: KeyPair): (domain: string, hashHex: string) => { key_id: string; sig: string } {
  const priv = privateKeyFromSeed(eventKey.seed);
  return (domain, hashHex) => ({ key_id: eventKey.keyId, sig: signDigest(domain, hashHex, priv) });
}
