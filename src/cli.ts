// seatbelt CLI (spec §4). Every daemon-facing command takes --config (or
// --socket) and supports --json where defined. Guest-channel commands use the
// preopened fd (--fd, default 3). Output files are no-clobber mode 0600.

import { readFileSync, writeFileSync, openSync, closeSync, mkdirSync } from "node:fs";
import { Socket } from "node:net";
import { join } from "node:path";
import { parseJsonStrict, parseFramePayload, jcsBytes, jcs } from "./canon.js";
import type { Json } from "./canon.js";
import { validateSpend, validateResourceCaps, validateLaunch, validateIntent, validatePolicyBundle, validatePolicy, validateTrust, validateHead, validateHostConfig, validateEvidenceRef } from "./schema.js";
import type { Head, Policy, Trust } from "./schema.js";
import { Fault, errResponse } from "./errors.js";
import type { ErrorCode, Response } from "./errors.js";
import { rpcOnce, frame } from "./server.js";
import { verifyBundle } from "./verify.js";
import type { VerifyCode } from "./verify.js";
import { doctor } from "./doctor.js";
import { bootstrap, loadConfig, loadTrust } from "./daemon.js";
import { migrate, MigrateFault } from "./migrate.js";
import { Store, STORAGE_VERSION } from "./store.js";
import { generateKey, buildPolicy, buildBundle, buildTrust, publicKeyFromSeed } from "./fixtures.js";
import { randomBytes } from "node:crypto";
import { D, HASH_DOMAINS, SIGN_DOMAINS, signDigest, verifyDigest, privateKeyFromSeed } from "./crypto.js";

// ---------- exit mapping (§4.2) ----------

const EXIT_BY_CODE: Record<string, number> = {
  INVALID_FRAME: 2, INVALID_SCHEMA: 2, VERSION_UNSUPPORTED: 2,
  UNAUTHENTICATED: 3, FORBIDDEN: 3,
  CAP_EXCEEDED: 4, CEILING_TOO_LOW: 4, UNBOUNDED_COST: 4, PRICE_CHANGED: 4,
  EXPIRED: 4, STOPPED: 4, BREAKER_OPEN: 4, RATE_LIMIT: 4,
  NOT_FOUND: 5, CONFLICT: 5, IDEMPOTENCY_CONFLICT: 5, STALE_REVISION: 5,
  BUSY: 6, UNSUPPORTED_HOST: 6, ADAPTER_UNAVAILABLE: 6, AUDIT_UNAVAILABLE: 6,
  HOST_FENCED: 6, COUNTER_EXHAUSTED: 6, BOUND_BREACH: 6,
  CONTAINMENT_UNKNOWN: 7,
  EVIDENCE_INVALID: 8, EVIDENCE_TRUNCATED: 8, EVIDENCE_STALE: 8, TRUST_QUORUM: 8,
  MISSING_OBJECT: 8, REPLAY_MISMATCH: 8, CLOCK_VIOLATION: 8, DISCLOSURE_LEAK: 8,
  CONFIG_INVALID: 9, TRUST_INVALID: 9, MIGRATION_INTEGRITY: 9,
};

const STOP_HUMAN_TEXT = "Local stop requested; external effects may be committed or unknown.";

interface Args {
  _: string[];
  flags: Map<string, string | true>;
}

const CLI_VERSION = "0.1.0";

const BOOL_FLAGS = new Set([
  "json", "force", "yes", "wait", "follow", "allow-unanchored",
  "full", "foreground", "host", "check-only",
]);

function parseArgs(argv: string[]): Args {
  const args: Args = { _: [], flags: new Map() };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      const name = eq !== -1 ? a.slice(2, eq) : a.slice(2);
      if (eq !== -1) {
        args.flags.set(name, a.slice(eq + 1));
      } else if (BOOL_FLAGS.has(name)) {
        args.flags.set(name, true);
      } else if (i + 1 < argv.length && !argv[i + 1]!.startsWith("--")) {
        args.flags.set(name, argv[++i]!);
      } else {
        args.flags.set(name, true);
      }
    } else {
      args._.push(a);
    }
  }
  return args;
}

function flag(args: Args, name: string): string | undefined {
  const v = args.flags.get(name);
  return v === true ? undefined : v;
}
function reqFlag(args: Args, name: string): string {
  const v = flag(args, name);
  if (v === undefined) throw new CliFault(2, `missing --${name}`);
  return v;
}

class CliFault extends Error {
  constructor(readonly exitCode: number, message: string) {
    super(message);
  }
}

function readJsonFile(path: string): unknown {
  try {
    return parseJsonStrict(readFileSync(path, "utf8"));
  } catch (e) {
    throw new CliFault(2, `cannot parse ${path}: ${(e as Error).message}`);
  }
}

function socketPath(args: Args): string {
  const s = flag(args, "socket");
  if (s) return s;
  const cfg = flag(args, "config");
  if (!cfg) throw new CliFault(2, "missing --config (or --socket)");
  const config = loadConfig(cfg);
  return config.socket;
}

function writeOutFile(path: string, bytes: Uint8Array | string): void {
  const fd = openSync(path, "wx", 0o600); // no-clobber, mode 0600
  try {
    writeFileSync(fd, bytes);
  } finally {
    closeSync(fd);
  }
}

let requestSeq = 0;
function rid(prefix = "cli"): string {
  requestSeq++;
  return `${prefix}_${process.pid}_${Date.now().toString(36)}_${requestSeq}`;
}

async function rpc(args: Args, method: string, params: unknown): Promise<unknown> {
  const sock = socketPath(args);
  const resp = await rpcOnce(sock, { v: 1, request_id: rid(), method, params } as Json);
  if (resp.ok) return resp.result;
  const e = resp.error;
  throw new CliFault(EXIT_BY_CODE[e.code] ?? 1, `${e.code}: ${e.detail}`);
}

/** Send a request on a preopened guest fd and read one framed reply. */
function fdRpc(fdNum: number, method: string, params: unknown): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let sock: Socket;
    try {
      sock = new Socket({ fd: fdNum, readable: true, writable: true });
    } catch {
      reject(new CliFault(6, `fd ${fdNum} unavailable`));
      return;
    }
    const req = { v: 1, request_id: rid("guest"), method, params } as Json;
    let buf = Buffer.alloc(0);
    sock.on("data", (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length < 4) return;
      const len = buf.readUInt32BE(0);
      if (buf.length < 4 + len) return;
      try {
        const resp = parseJsonStrict(buf.subarray(4, 4 + len).toString("utf8")) as Response;
        if (resp.ok) resolve(resp.result);
        else {
          const e = resp.error;
          reject(new CliFault(EXIT_BY_CODE[e.code] ?? 1, `${e.code}: ${e.detail}`));
        }
      } catch {
        reject(new CliFault(2, "malformed reply frame"));
      }
    });
    sock.on("error", () => reject(new CliFault(6, `fd ${fdNum} unusable`)));
    sock.write(frame(jcsBytes(req)));
  });
}

function guestFd(args: Args): number {
  const v = flag(args, "fd");
  return v === undefined ? 3 : Number(v);
}

const ACTION_TERMINAL = new Set(["SUCCEEDED", "FAILED", "CANCELLED"]);

/** One long-lived fd3 session: sequential framed requests over a single socket. */
function fdSession(fd: number): (method: string, params: unknown) => Promise<unknown> {
  let sock: Socket;
  try {
    sock = new Socket({ fd, readable: true, writable: true });
  } catch {
    throw new CliFault(6, `fd ${fd} unavailable`);
  }
  let buf = Buffer.alloc(0);
  const pending: { resolve: (v: unknown) => void; reject: (e: Error) => void }[] = [];
  sock.on("data", (chunk: Buffer) => {
    buf = Buffer.concat([buf, chunk]);
    while (buf.length >= 4) {
      const len = buf.readUInt32BE(0);
      if (buf.length < 4 + len) break;
      const frameBytes = buf.subarray(4, 4 + len);
      buf = buf.subarray(4 + len);
      const waiter = pending.shift();
      if (!waiter) continue;
      try {
        const resp = parseJsonStrict(frameBytes.toString("utf8")) as Response;
        if (resp.ok) waiter.resolve(resp.result);
        else waiter.reject(new CliFault(EXIT_BY_CODE[resp.error.code] ?? 1, `${resp.error.code}: ${resp.error.detail}`));
      } catch {
        waiter.reject(new CliFault(2, "malformed reply frame"));
      }
    }
  });
  sock.on("error", () => { for (const w of pending.splice(0)) w.reject(new CliFault(6, `fd ${fd} unusable`)); });
  return (method, params) => new Promise((resolve, reject) => {
    pending.push({ resolve, reject });
    sock.write(frame(jcsBytes({ v: 1, request_id: rid("guest"), method, params } as Json)));
  });
}

/** Poll action.get until a terminal outcome or the bounded wait expires. */
async function pollAction(args: Args, actionId: string, ask: (method: string, params: unknown) => Promise<unknown>, timeoutMs: number): Promise<number> {
  const deadline = Date.now() + timeoutMs;
  const params = { action_id: actionId };
  let lastState = "DISPATCHED";
  while (Date.now() <= deadline) {
    try {
      const r = await ask("action.get", params) as { state?: string; action?: { state: string } };
      const state = r.action?.state ?? r.state ?? "DISPATCHED";
      lastState = state;
      if (ACTION_TERMINAL.has(state)) {
        out(args, r);
        return state === "SUCCEEDED" ? 0 : state === "FAILED" ? 6 : 4;
      }
    } catch (e) {
      if (e instanceof CliFault && e.exitCode === 5) throw e; // NOT_FOUND is terminal
    }
    await sleep(200);
  }
  return 7; // UNKNOWN or unobserved at the bounded wait
}

function out(args: Args, result: unknown, human?: string): void {
  if (args.flags.has("json")) {
    process.stdout.write(jcs(result as Json) + "\n");
  } else if (human !== undefined) {
    process.stdout.write(human + "\n");
  } else {
    process.stdout.write(jcs(result as Json) + "\n");
  }
}

export async function main(argv: string[]): Promise<number> {
  const args = parseArgs(argv);
  const [cmd, sub] = args._;
  try {
    switch (cmd) {
      case "init": return cmdInit(args);
      case "version": return cmdVersion(args);
      case "daemon": return await cmdDaemon(args);
      case "doctor": return cmdDoctor(args);
      case "status": return await cmdStatus(args);
      case "recover": return await cmdRecover(args);
      case "host": return await cmdHost(args, sub);
      case "policy": return await cmdPolicy(args, sub);
      case "budget": return await cmdBudget(args, sub);
      case "run": return await cmdRun(args, sub);
      case "stop": return await cmdStop(args);
      case "action": return await cmdAction(args, sub);
      case "breaker": return await cmdBreaker(args, sub);
      case "watch": return await cmdWatch(args, sub);
      case "events": return await cmdEvents(args);
      case "export": return await cmdExport(args);
      case "verify": return cmdVerify(args);
      case "metrics": return await cmdMetrics(args);
      case "migrate": return cmdMigrate(args);
      default:
        throw new CliFault(2, `unknown command: ${cmd ?? "(none)"}`);
    }
  } catch (e) {
    if (e instanceof CliFault) {
      process.stderr.write(`error: ${e.message}\n`);
      return e.exitCode;
    }
    if (e instanceof Fault) {
      process.stderr.write(`error: ${e.code}: ${e.message}\n`);
      return EXIT_BY_CODE[e.code] ?? 1;
    }
    if (e instanceof MigrateFault) {
      process.stderr.write(`error: ${e.code}: ${e.message}\n`);
      return EXIT_BY_CODE[e.code] ?? 9;
    }
    if ((e as NodeJS.ErrnoException).code === "ENOENT" || (e as NodeJS.ErrnoException).code === "ECONNREFUSED" || (e as NodeJS.ErrnoException).code === "EACCES") {
      process.stderr.write(`error: daemon unavailable: ${(e as Error).message}\n`);
      return 6;
    }
    if ((e as NodeJS.ErrnoException).code === "EEXIST") {
      process.stderr.write(`error: output file exists (no-clobber): ${(e as Error).message}\n`);
      return 5;
    }
    throw e;
  }
}

// ---------- operator tooling ----------

function cmdVersion(args: Args): number {
  out(args, { cli: CLI_VERSION, protocol: "1", storage: STORAGE_VERSION, schema: "seatbelt/1" },
    `seatbelt ${CLI_VERSION} (protocol 1, storage ${STORAGE_VERSION}, schema seatbelt/1)`);
  return 0;
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function waitDeadline(args: Args, fallbackMs: number): number {
  const v = flag(args, "wait-ms");
  return v === undefined ? fallbackMs : Number(v);
}

async function cmdStatus(args: Args): Promise<number> {
  const r = await rpc(args, "host.status", {});
  out(args, r, `state=${(r as { state: string }).state} epoch=${(r as { epoch: string }).epoch}`);
  return 0;
}

async function cmdRecover(args: Args): Promise<number> {
  const r = await rpc(args, "host.recover", { expected_epoch: reqFlag(args, "expected-epoch") });
  out(args, r);
  return 0;
}

function cmdInit(args: Args): number {
  const dir = reqFlag(args, "dir");
  const profile = (flag(args, "profile") ?? "offline-v1") as "offline-v1" | "linux-contained-v1";
  if (profile !== "offline-v1" && profile !== "linux-contained-v1") throw new CliFault(2, "--profile must be offline-v1|linux-contained-v1");
  const installationId = flag(args, "installation-id") ?? "inst_one";
  mkdirSync(dir, { recursive: true });
  mkdirSync(join(dir, "keys"), { recursive: true });

  const policyKeys = [generateKey("sign_one"), generateKey("sign_two"), generateKey("sign_three")];
  const eventKey = generateKey("event_key");
  const objectKey = randomBytes(32);
  const myUid = flag(args, "admin-uid") !== undefined ? Number(flag(args, "admin-uid")) : process.getuid?.() ?? 1001;

  for (const k of [...policyKeys, eventKey]) {
    writeOutFile(join(dir, "keys", `${k.keyId}.seed`), k.seed);
    writeOutFile(join(dir, "keys", `${k.keyId}.pub`), Buffer.from(k.public).toString("hex") + "\n");
  }
  writeOutFile(join(dir, "keys", "object.key"), objectKey);

  const policy = buildPolicy({
    adminUids: [myUid], observerUids: [myUid], killerUids: [myUid], watchUids: [myUid],
    rootLimit: { microusd: "1000000", input_tokens: "1000", output_tokens: "1000", calls: "100" },
    maxRunLimit: { microusd: "1000000", input_tokens: "1000", output_tokens: "1000", calls: "100" },
    maxRuns: "32",
  });
  const bundle = buildBundle(policy, [policyKeys[0]!, policyKeys[1]!, policyKeys[2]!]);
  writeOutFile(join(dir, "policy.json"), jcsBytes(bundle as unknown as Json));

  const trust = buildTrust(installationId, policyKeys, eventKey);
  writeOutFile(join(dir, "trust.json"), jcsBytes(trust as unknown as Json));

  const config = {
    v: 1, installation_id: installationId, profile,
    database: join(dir, "seatbelt.db"), socket: join(dir, "control.sock"),
    cgroup_root: flag(args, "cgroup-root") ?? "/sys/fs/cgroup",
    image_store: join(dir, "images"),
    event_key_file: join(dir, "keys", "event_key.seed"),
    object_key_file: join(dir, "keys", "object.key"),
    emergency_file: join(dir, "emergency.bin"),
    uid_first: 0, uid_count: 8,
    controller_memory_bytes: "268435456", guard_memory_bytes: "67108864", audit_reserve_bytes: "1048576",
    live_adapters: false, watch_scopes: [{ uid: myUid, budgets: ["project", "root", "task"] }],
  };
  writeOutFile(join(dir, "config.json"), jcsBytes(config as unknown as Json));
  mkdirSync(join(dir, "images"), { recursive: true });

  process.stdout.write(`seatbelt init: ${dir}\n  config=${join(dir, "config.json")}\n  trust=${join(dir, "trust.json")}\n  policy=${join(dir, "policy.json")}\n`);
  return 0;
}

async function cmdDaemon(args: Args): Promise<number> {
  const configPath = reqFlag(args, "config");
  const trustPath = reqFlag(args, "trust");
  const d = bootstrap(configPath, trustPath, {});
  await d.server.listen();
  if (flag(args, "policy") !== undefined) {
    // --policy applies the bundle through the real control socket so caller
    // identity comes from peercred, not process arguments. An already-active
    // policy on restart is not a boot failure.
    const bundle = validatePolicyBundle(readJsonFile(flag(args, "policy")!));
    let resp: Response | undefined;
    for (let i = 0; i < 40; i++) {
      resp = await rpcOnce(d.config.socket, {
        v: 1, request_id: rid(), method: "policy.apply",
        params: { bundle, expected_revision: "0" },
      } as Json);
      if (resp.ok || resp.error.code !== "BUSY") break;
      await sleep(250); // host still RECOVERING; retry until READY/FENCED
    }
    if (resp !== undefined && !resp.ok) {
      if (resp.error.code === "CONFLICT" || resp.error.code === "STALE_REVISION") {
        process.stderr.write(`note: --policy already active (${resp.error.code})\n`);
      } else {
        process.stderr.write(`error: --policy apply failed: ${resp.error.code}: ${resp.error.detail}\n`);
        await d.close();
        return EXIT_BY_CODE[resp.error.code] ?? 9;
      }
    }
  }
  process.stdout.write(`seatbelt daemon: ${d.config.installation_id} listening on ${d.config.socket}\n`);
  const shutdown = async () => {
    await d.close();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
  return new Promise<number>(() => { /* runs until signal */ });
}

function cmdDoctor(args: Args): number {
  const r = doctor(reqFlag(args, "config"), reqFlag(args, "trust"));
  if (args.flags.has("json")) {
    process.stdout.write(jcs(r as unknown as Json) + "\n");
  } else {
    for (const c of r.checks) {
      process.stdout.write(`${c.ok ? "ok" : "FAIL"}  ${c.name.padEnd(24)} ${c.detail}\n`);
    }
  }
  return r.ok ? 0 : 9;
}

// ---------- host / policy ----------

async function cmdHost(args: Args, sub?: string): Promise<number> {
  switch (sub) {
    case "status": {
      const r = await rpc(args, "host.status", {});
      out(args, r, `state=${(r as { state: string }).state} epoch=${(r as { epoch: string }).epoch}`);
      return 0;
    }
    case "stop": {
      const r = await rpc(args, "host.stop", { reason: "OPERATOR" });
      out(args, r, STOP_HUMAN_TEXT);
      return 0;
    }
    case "recover": {
      const r = await rpc(args, "host.recover", { expected_epoch: reqFlag(args, "expected-epoch") });
      out(args, r);
      return 0;
    }
    default:
      throw new CliFault(2, "usage: seatbelt host status|stop|recover");
  }
}

async function cmdPolicy(args: Args, sub?: string): Promise<number> {
  switch (sub) {
    case "apply": {
      const file = flag(args, "file") ?? flag(args, "bundle");
      if (file === undefined) throw new CliFault(2, "missing --file");
      const bundle = validatePolicyBundle(readJsonFile(file));
      const r = await rpc(args, "policy.apply", { bundle, expected_revision: reqFlag(args, "expected-revision") });
      out(args, r);
      return 0;
    }
    case "validate": {
      // Offline closed-schema + quorum check; never contacts a daemon.
      const bundle = validatePolicyBundle(readJsonFile(reqFlag(args, "file")));
      const trust = validateTrust(readJsonFile(reqFlag(args, "trust")));
      const q = policyQuorum(bundle, trust);
      out(args, {
        ok: q.ok, policy: q.policyHash, revision: bundle.body.revision,
        quorum: q.verified, threshold: trust.threshold, detail: q.detail ?? null,
      });
      return q.ok ? 0 : 8;
    }
    case "sign": {
      // Offline detached signature over the canonical policy digest.
      const body = readPolicyBody(readJsonFile(reqFlag(args, "file")));
      const seed = new Uint8Array(readFileSync(reqFlag(args, "key")));
      if (seed.length !== 32) throw new CliFault(2, "--key must be a 32-byte seed file");
      const sig = {
        key_id: reqFlag(args, "key-id"),
        sig: signDigest(SIGN_DOMAINS.POLICY, D(HASH_DOMAINS.POLICY, body as unknown as Json), privateKeyFromSeed(seed)),
      };
      const outPath = flag(args, "out");
      if (outPath) {
        writeOutFile(outPath, jcsBytes(sig as unknown as Json));
        process.stdout.write(`wrote ${outPath}\n`);
      } else {
        out(args, sig);
      }
      return 0;
    }
    default:
      throw new CliFault(2, "usage: seatbelt policy apply|validate|sign");
  }
}

/** Accept either a bare Policy body or a signed PolicyBundle; return the body. */
function readPolicyBody(v: unknown): Policy {
  try {
    return validatePolicyBundle(v).body;
  } catch {
    return validatePolicy(v);
  }
}

/** Offline quorum check: distinct trusted principals with valid signatures. */
function policyQuorum(bundle: ReturnType<typeof validatePolicyBundle>, trust: Trust): { ok: boolean; policyHash: string; verified: number; detail: string | undefined } {
  const policyHash = D(HASH_DOMAINS.POLICY, bundle.body as unknown as Json);
  const seen = new Set<string>();
  let sigBad = false;
  for (const s of bundle.signatures) {
    const principal = trust.principals.find((p) => p.key_id === s.key_id);
    if (!principal) continue;
    if (verifyDigest(SIGN_DOMAINS.POLICY, policyHash, s.sig, hexBytes(principal.public_key))) {
      seen.add(principal.principal_id);
    } else {
      sigBad = true;
    }
  }
  const ok = seen.size >= Number(trust.threshold);
  return {
    ok, policyHash, verified: seen.size,
    detail: ok ? undefined : (sigBad ? "signature invalid" : "quorum unmet"),
  };
}

function hexBytes(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// ---------- budgets ----------

async function cmdBudget(args: Args, sub?: string): Promise<number> {
  switch (sub) {
    case "create": {
      const r = await rpc(args, "budget.create", {
        budget_id: reqFlag(args, "id"), parent: reqFlag(args, "parent"),
        limit: validateSpend(readJsonFile(reqFlag(args, "limit"))),
      });
      out(args, r);
      return 0;
    }
    case "get": {
      const r = await rpc(args, "budget.get", { budget_id: reqFlag(args, "id") });
      out(args, r);
      return 0;
    }
    case "tighten": {
      const r = await rpc(args, "budget.tighten", {
        budget_id: reqFlag(args, "id"), limit: validateSpend(readJsonFile(reqFlag(args, "limit"))),
        expected_revision: reqFlag(args, "expected-revision"),
      });
      out(args, r);
      return 0;
    }
    case "close": {
      const r = await rpc(args, "budget.close", { budget_id: reqFlag(args, "id"), expected_revision: reqFlag(args, "expected-revision") });
      out(args, r);
      return 0;
    }
    default:
      throw new CliFault(2, "usage: seatbelt budget create|get|tighten|close");
  }
}

// ---------- runs ----------

const RUN_TERMINAL = new Set(["STOPPED", "FINISHED", "FAILED"]);

/** Poll run.get until a terminal state or the bounded wait expires. */
async function pollRun(args: Args, runId: string, timeoutMs: number): Promise<{ state: string } | null> {
  const deadline = Date.now() + timeoutMs;
  let last: { state: string } | null = null;
  while (Date.now() <= deadline) {
    try {
      const r = await rpc(args, "run.get", { run_id: runId }) as { run: { state: string } };
      last = r.run;
      if (RUN_TERMINAL.has(r.run.state)) return r.run;
    } catch {
      // transient daemon fault during teardown; keep polling to the deadline
    }
    await sleep(200);
  }
  return last;
}

function runExit(state: string | null): number {
  switch (state) {
    case "FINISHED": return 0;
    case "STOPPED": return 4;
    case "FAILED": return 6;
    default: return 7; // still STOPPING / unobserved at the bounded wait
  }
}

async function cmdRun(args: Args, sub?: string): Promise<number> {
  switch (sub) {
    case undefined: {
      // `seatbelt run --id --budget --limit --resources --launch` = run.start
      const runId = reqFlag(args, "id");
      const r = await rpc(args, "run.start", {
        run_id: runId, budget_id: reqFlag(args, "budget"),
        limit: validateSpend(readJsonFile(reqFlag(args, "limit"))),
        resources: validateResourceCaps(readJsonFile(reqFlag(args, "resources"))),
        launch: validateLaunch(readJsonFile(reqFlag(args, "launch"))),
      });
      out(args, r);
      if (!args.flags.has("wait") && flag(args, "wait-ms") === undefined) return 0;
      const final = await pollRun(args, runId, waitDeadline(args, 30_000));
      return runExit(final?.state ?? null);
    }
    case "get": {
      const fd = flag(args, "fd");
      const params = { run_id: reqFlag(args, "id") };
      const r = fd !== undefined ? await fdRpc(Number(fd), "run.get", params) : await rpc(args, "run.get", params);
      out(args, r);
      return 0;
    }
    case "heartbeat": {
      const r = await fdRpc(guestFd(args), "run.heartbeat", { run_id: reqFlag(args, "id"), beat: reqFlag(args, "beat") });
      out(args, r);
      return 0;
    }
    case "stop": {
      const fd = flag(args, "fd");
      const params = { run_id: reqFlag(args, "id"), reason: flag(args, "reason") ?? (fd !== undefined ? "SELF_STOP" : "OPERATOR") };
      const r = fd !== undefined ? await fdRpc(Number(fd), "run.stop", params) : await rpc(args, "run.stop", params);
      out(args, r, STOP_HUMAN_TEXT);
      return 0;
    }
    default:
      throw new CliFault(2, "usage: seatbelt run [--id ...] | run get|heartbeat|stop");
  }
}

async function cmdStop(args: Args): Promise<number> {
  if (args.flags.has("host")) {
    const r = await rpc(args, "host.stop", { reason: "OPERATOR" });
    out(args, r, STOP_HUMAN_TEXT);
    return 0;
  }
  const runId = flag(args, "run");
  if (runId === undefined) throw new CliFault(2, "usage: seatbelt stop --host | --run ID [--wait-ms U]");
  const fd = flag(args, "fd");
  const params = { run_id: runId, reason: flag(args, "reason") ?? (fd !== undefined ? "SELF_STOP" : "OPERATOR") };
  const r = fd !== undefined ? await fdRpc(Number(fd), "run.stop", params) : await rpc(args, "run.stop", params);
  out(args, r, STOP_HUMAN_TEXT);
  if (fd === undefined && (args.flags.has("wait-ms") || args.flags.has("wait"))) {
    // exit reflects observed containment, not provider rollback
    const final = await pollRun(args, runId, waitDeadline(args, 2000));
    return RUN_TERMINAL.has(final?.state ?? "") ? 0 : 7;
  }
  return 0;
}

// ---------- actions ----------

async function cmdAction(args: Args, sub?: string): Promise<number> {
  switch (sub) {
    case "reserve": {
      const intent = validateIntent(readJsonFile(reqFlag(args, "intent")));
      const r = await fdRpc(guestFd(args), "action.reserve", { action_id: reqFlag(args, "id"), intent });
      out(args, r);
      return 0;
    }
    case "dispatch": {
      const actionId = reqFlag(args, "id");
      const waitMs = flag(args, "wait-ms");
      if (waitMs === undefined) {
        const r = await fdRpc(guestFd(args), "action.dispatch", { action_id: actionId });
        out(args, r);
        return 0;
      }
      // dispatch + poll over one fd3 session (print DISPATCHED, never
      // synchronous success)
      const ask = fdSession(guestFd(args));
      out(args, await ask("action.dispatch", { action_id: actionId }));
      return await pollAction(args, actionId, ask, Number(waitMs));
    }
    case "cancel": {
      const r = await fdRpc(guestFd(args), "action.cancel", { action_id: reqFlag(args, "id") });
      out(args, r);
      return 0;
    }
    case "get": {
      const fd = flag(args, "fd");
      const params = { action_id: reqFlag(args, "id") };
      const waitMs = flag(args, "wait-ms");
      if (waitMs !== undefined) {
        const ask = fd !== undefined ? fdSession(Number(fd)) : (m: string, p: unknown) => rpc(args, m, p);
        return await pollAction(args, params.action_id, ask, Number(waitMs));
      }
      const r = fd !== undefined ? await fdRpc(Number(fd), "action.get", params) : await rpc(args, "action.get", params);
      out(args, r);
      return 0;
    }
    case "reconcile": {
      const r = await rpc(args, "action.reconcile", { action_id: reqFlag(args, "id") });
      out(args, r);
      return 0;
    }
    default:
      throw new CliFault(2, "usage: seatbelt action reserve|dispatch|cancel|get|reconcile");
  }
}

// ---------- breakers / watch ----------

async function cmdBreaker(args: Args, sub?: string): Promise<number> {
  switch (sub) {
    case "get": {
      const r = await rpc(args, "breaker.get", { budget_id: reqFlag(args, "budget") });
      out(args, r);
      return 0;
    }
    case "reset": {
      const r = await rpc(args, "breaker.reset", { budget_id: reqFlag(args, "budget"), expected_revision: reqFlag(args, "expected-revision") });
      out(args, r);
      return 0;
    }
    default:
      throw new CliFault(2, "usage: seatbelt breaker get|reset");
  }
}

async function cmdWatch(args: Args, sub?: string): Promise<number> {
  if (sub !== "stop") throw new CliFault(2, "usage: seatbelt watch stop --budget ID --signal ID --evidence FILE");
  const r = await rpc(args, "watch.stop", {
    budget_id: reqFlag(args, "budget"), signal_id: reqFlag(args, "signal"),
    evidence: validateEvidenceRef(readJsonFile(reqFlag(args, "evidence"))),
  });
  out(args, r, STOP_HUMAN_TEXT);
  return 0;
}

// ---------- events / export / verify / metrics / migrate ----------

async function cmdEvents(args: Args): Promise<number> {
  const after = flag(args, "after") ?? "0";
  const limit = flag(args, "limit") ?? "64";
  if (!args.flags.has("follow")) {
    const r = await rpc(args, "events.read", { after, limit });
    out(args, r);
    return 0;
  }
  // --follow: resume from the last durable seq with a fresh request_id per call.
  let cursor = after;
  for (;;) {
    const r = await rpc(args, "events.read", { after: cursor, limit }) as {
      events: { body: { seq: string } }[]; next: string; head: Head;
    };
    for (const ev of r.events) process.stdout.write(jcs(ev as unknown as Json) + "\n");
    if (BigInt(r.next) > BigInt(cursor)) cursor = r.next;
    await sleep(500);
  }
}

async function cmdExport(args: Args): Promise<number> {
  const from = validateHead(readJsonFile(reqFlag(args, "from")));
  const to = validateHead(readJsonFile(reqFlag(args, "to")));
  const disclosure = (flag(args, "disclosure") ?? "METADATA") as "FULL" | "METADATA";
  if (disclosure !== "FULL" && disclosure !== "METADATA") throw new CliFault(2, "--disclosure must be FULL|METADATA");
  const r = await rpc(args, "evidence.export", { from, to, disclosure });
  const outPath = flag(args, "out");
  if (outPath) {
    writeOutFile(outPath, jcsBytes(r as Json));
    process.stdout.write(`wrote ${outPath}\n`);
  } else {
    out(args, r);
  }
  return 0;
}

function cmdVerify(args: Args): number {
  const bundleBytes = readFileSync(reqFlag(args, "bundle"));
  const trust = validateTrust(readJsonFile(reqFlag(args, "trust")));
  const unanchored = args.flags.has("allow-unanchored");
  const expectedPath = flag(args, "expected-head");
  if (expectedPath === undefined && !unanchored) throw new CliFault(2, "missing --expected-head (or --allow-unanchored)");
  const expected = expectedPath === undefined ? null : validateHead(readJsonFile(expectedPath));
  const r = verifyBundle(new Uint8Array(bundleBytes), trust, expected, undefined, { allowUnanchored: unanchored });
  out(args, r, `verify: ${r.status}`);
  if (r.status === "OK") return 0;
  if (r.status === "UNANCHORED") return 0; // accepted, visibly weaker
  return EXIT_BY_CODE[r.status] ?? 8;
}

/** Derive the complete metrics registry from the retained event range. */
async function fullMetrics(args: Args): Promise<Json> {
  const counts: Record<string, number> = {};
  let cursor = "0";
  let firstSeq: string | null = null;
  let head: Head = { seq: "0", hash: "0".repeat(64) };
  for (;;) {
    const r = await rpc(args, "events.read", { after: cursor, limit: "128" }) as {
      events: { body: { seq: string; data: { kind: string } } }[]; next: string; head: Head;
    };
    head = r.head;
    if (firstSeq === null && r.events.length > 0) firstSeq = r.events[0]!.body.seq;
    for (const ev of r.events) counts[ev.body.data.kind] = (counts[ev.body.data.kind] ?? 0) + 1;
    if (r.events.length === 0 || BigInt(r.next) >= BigInt(head.seq)) break;
    cursor = r.next;
  }
  // refuse incomplete history: the retained range must start at seq 1
  if (firstSeq !== "1" && head.seq !== "0") {
    throw new CliFault(8, `incomplete retained history (starts at seq ${firstSeq ?? "none"}); cannot derive full registry`);
  }
  return { ...counts, range_head: head.seq } as unknown as Json;
}

function prometheusText(m: Record<string, unknown>): string {
  const lines: string[] = [];
  const emit = (name: string, value: unknown, labels: Record<string, string> = {}): void => {
    const l = Object.entries(labels).map(([k, v]) => `${k}="${v}"`).join(",");
    lines.push(`seatbelt_${name}${l ? `{${l}}` : ""} ${value}`);
  };
  for (const [k, v] of Object.entries(m)) {
    if (typeof v === "string" || typeof v === "number") {
      if (/^-?\d+$/.test(String(v))) emit(k, v);
    } else if (v && typeof v === "object") {
      for (const [dim, dv] of Object.entries(v as Record<string, unknown>)) {
        if (typeof dv === "string" || typeof dv === "number") emit(k, dv, { dim });
      }
    }
  }
  return lines.join("\n") + "\n";
}

async function cmdMetrics(args: Args): Promise<number> {
  const format = flag(args, "format") ?? "json";
  if (format !== "json" && format !== "prometheus") throw new CliFault(2, "--format must be json|prometheus");
  const r = args.flags.has("full")
    ? await fullMetrics(args)
    : (await rpc(args, "metrics.read", {})) as Json;
  if (format === "prometheus") {
    process.stdout.write(prometheusText(r as Record<string, unknown>));
  } else {
    out(args, r);
  }
  return 0;
}

function cmdMigrate(args: Args): number {
  const config = loadConfig(reqFlag(args, "config"));
  const trust = loadTrust(reqFlag(args, "trust"));
  const expected = validateHead(readJsonFile(reqFlag(args, "expected-head")));
  const target = reqFlag(args, "target");
  const manifestPath = flag(args, "manifest");
  const store = new Store(config.database);
  try {
    const r = migrate(store, trust, target, expected,
      manifestPath ? new Uint8Array(readFileSync(manifestPath)) : undefined,
      args.flags.has("check-only"));
    out(args, r, `migrate: ${r.from} -> ${r.to} (verified, ${r.applied.length} migrations)`);
    return 0;
  } finally {
    store.close();
  }
}
