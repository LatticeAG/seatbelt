// seatbelt doctor: local preflight/integrity report. Checks the same
// cross-validations bootstrap performs plus liveness probes; it never mutates.

import { existsSync, readFileSync, statfsSync } from "node:fs";
import { platform, arch } from "node:os";
import { join } from "node:path";
import { parseJsonStrict } from "./canon.js";
import { sha256Hex, publicKeyRawFromPrivate, privateKeyFromSeed } from "./crypto.js";
import { validateHostConfig, validateTrust } from "./schema.js";
import type { HostConfig, Trust } from "./schema.js";
import { Store } from "./store.js";
import { verifyChain } from "./migrate.js";

export interface DoctorCheck {
  name: string;
  ok: boolean;
  detail: string;
}

export function doctor(configPath: string, trustPath: string): { ok: boolean; checks: DoctorCheck[] } {
  const checks: DoctorCheck[] = [];
  const push = (name: string, ok: boolean, detail: string) => checks.push({ name, ok, detail });

  let config: HostConfig | null = null;
  let trust: Trust | null = null;
  try {
    config = validateHostConfig(parseJsonStrict(readFileSync(configPath, "utf8")));
    push("config.schema", true, "closed-schema config parses");
  } catch (e) {
    push("config.schema", false, `config invalid: ${(e as Error).message}`);
    return { ok: false, checks };
  }
  try {
    trust = validateTrust(parseJsonStrict(readFileSync(trustPath, "utf8")));
    push("trust.schema", true, "closed-schema trust parses");
  } catch (e) {
    push("trust.schema", false, `trust invalid: ${(e as Error).message}`);
    return { ok: false, checks };
  }
  push("config.installation", config.installation_id === trust.installation_id,
    config.installation_id === trust.installation_id ? config.installation_id : "installation_id mismatch");

  // keys
  try {
    const seed = new Uint8Array(readFileSync(config.event_key_file));
    const pub = Buffer.from(publicKeyRawFromPrivate(privateKeyFromSeed(seed))).toString("hex");
    push("keys.event", seed.length === 32 && pub === trust.event_key.public_key,
      pub === trust.event_key.public_key ? "event key matches trust" : "event key mismatch");
  } catch (e) {
    push("keys.event", false, `event key unreadable: ${(e as Error).message}`);
  }
  push("keys.object", existsSync(config.object_key_file) && readFileSync(config.object_key_file).length === 32,
    "object key 32 bytes");
  push("keys.separation", trust.principals.every((p) => p.public_key !== trust.event_key.public_key),
    "event key distinct from policy signers");

  // platform: a hard requirement only for linux-contained-v1; the ledger-only
  // offline profile reports the host tuple without gating on it.
  const platformOk = platform() === "linux" && arch() === "x64";
  push("platform", config.profile === "linux-contained-v1" ? platformOk : true,
    `${platform()}/${arch()}${platformOk ? "" : " (containment unsupported)"}`);
  let boot = "";
  try {
    boot = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
    push("boot_id", /^[0-9a-f-]{36}$/.test(boot), boot);
  } catch {
    push("boot_id", false, "boot_id unreadable");
  }

  // containment
  if (config.profile === "linux-contained-v1") {
    let ok = false;
    let why = "";
    try {
      const st = statfsSync(config.cgroup_root);
      const isCg2 = (st as unknown as { type?: number }).type === 0x27e0eb;
      const ctrls = readFileSync(join(config.cgroup_root, "cgroup.controllers"), "utf8");
      const have = ["cpu", "memory", "pids"].every((c) => ctrls.split(/\s+/).includes(c));
      ok = isCg2 && have;
      why = `cgroup2=${isCg2} controllers=${have}`;
    } catch (e) {
      why = (e as Error).message;
    }
    push("containment", ok, why);
  } else {
    push("containment", true, "offline-v1: containment not required; run.start reports UNSUPPORTED_HOST");
  }

  // store integrity
  if (existsSync(config.database)) {
    try {
      const store = new Store(config.database);
      const v = verifyChain(store);
      push("store.chain", v.ok, v.ok ? `head ${v.head.seq}` : `chain break at seq ${v.at}`);
      push("store.head", true, `seq=${v.head.seq} hash=${v.head.hash.slice(0, 12)}…`);
      store.close();
    } catch (e) {
      push("store.chain", false, `store unreadable: ${(e as Error).message}`);
    }
  } else {
    push("store.chain", true, "no store yet (first boot)");
  }
  push("emergency_file", true, config.emergency_file);
  push("socket", existsSync(config.socket), existsSync(config.socket) ? "present" : "absent (daemon not running)");

  return { ok: checks.every((c) => c.ok), checks };
}
