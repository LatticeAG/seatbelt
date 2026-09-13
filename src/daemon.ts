// Daemon bootstrap + supervision (spec §5, §6, §7.4). Loads config + trust,
// cross-validates them (identical installation_id; event key in config matches
// the trust event key; no policy signer may be the event key), opens storage,
// runs deterministic recovery, then serves the control socket and drives the
// sequencer tick.

import { readFileSync, existsSync, mkdirSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { jcs, parseJsonStrict } from "./canon.js";
import type { Json } from "./canon.js";
import { sha256Hex, publicKeyRawFromPrivate, privateKeyFromSeed, signDigest } from "./crypto.js";
import { validateHostConfig, validateTrust } from "./schema.js";
import type { HostConfig, Trust, Run, ResourceCaps, Reason, Sample } from "./schema.js";
import { Store } from "./store.js";
import { ObjectStore } from "./objects.js";
import { EmergencyFile } from "./emergency.js";
import { Engine } from "./engine.js";
import type { GuardPort, ExecutorPort } from "./engine.js";
import type { GuardTickEvent } from "./guard.js";
import { LinuxKernel, SimKernel } from "./kernel.js";
import type { KernelBackend } from "./kernel.js";
import { AdapterPort, RecordV1Adapter, ProviderAdapterStub } from "./adapter.js";
import type { Intent, Outcome } from "./schema.js";
import { ControlServer, unlinkIfExists } from "./server.js";
import { Fault } from "./errors.js";
import { GuardCore } from "./guard.js";
import { GuardProcessPort } from "./guardproc.js";


const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
export interface DaemonDeps {
  kernel?: KernelBackend;
  guard?: GuardPort;
  executor?: ExecutorPort;
  peercredHelper?: string;
  uidOverride?: number;
  adapters?: Map<string, AdapterPort>;
  now?: () => bigint;
}

export interface Daemon {
  config: HostConfig;
  trust: Trust;
  store: Store;
  engine: Engine;
  server: ControlServer;
  close(): Promise<void>;
}

function hex(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}

export function loadConfig(path: string): HostConfig {
  return validateHostConfig(parseJsonStrict(readFileSync(path, "utf8")));
}
export function loadTrust(path: string): Trust {
  return validateTrust(parseJsonStrict(readFileSync(path, "utf8")));
}

/** Offline guard port: no runs can arm under offline-v1, so nothing to drive. */
export class NullGuard implements GuardPort {
  arm(): { containmentId: string } | null {
    return null;
  }
  renew(): void { /* nothing armed */ }
  relayStop(): void { /* nothing armed */ }
  drive(): GuardTickEvent[] {
    return [];
  }
  isStopped(): boolean {
    return true;
  }
  latestSample(): Sample | null {
    return null;
  }
}

/** In-process guard for offline-v1: GuardCore over the simulated kernel. */
export class LocalGuard implements GuardPort {
  readonly core: GuardCore;
  private seqs = new Map<string, bigint>();
  constructor(private kernel: SimKernel, private clock: () => bigint, bootId: string, emergency: EmergencyFile | null) {
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

/** In-process executor for the deterministic record_v1 adapter. */
export class LocalExecutor implements ExecutorPort {
  constructor(private engine: Engine, private adapters: Map<string, AdapterPort>) {}
  startExecution(input: { actionId: string; operationKey: string; intent: Intent; dispatchSeq: string; deadlineMs: bigint }): void {
    const adapter = this.adapters.get(input.intent.adapter) as RecordV1Adapter | undefined;
    if (!adapter || adapter.adapterId !== "record_v1") {
      this.engine.deliverOutcome(input.actionId, { status: "UNKNOWN", actual: null, result_hash: null, evidence: [] }, null, "execute");
      return;
    }
    try {
      const res = adapter.execute({ intent: input.intent });
      this.engine.deliverOutcome(input.actionId, res.outcome, res.resultBytes, "execute");
    } catch {
      this.engine.deliverOutcome(input.actionId, { status: "UNKNOWN", actual: null, result_hash: null, evidence: [] }, null, "execute");
    }
  }
}

export function bootstrap(configPath: string, trustPath: string, deps: DaemonDeps = {}): Daemon {
  const config = loadConfig(configPath);
  const trust = loadTrust(trustPath);

  // config/trust cross-validation: identical installation_id; event key file's
  // public half must equal trust.event_key; event key must differ from every
  // policy signer (M14).
  if (config.installation_id !== trust.installation_id) {
    throw new Fault("CONFIG_INVALID");
  }
  if (!existsSync(config.event_key_file) || !existsSync(config.object_key_file)) {
    throw new Fault("CONFIG_INVALID");
  }
  const eventSeed = new Uint8Array(readFileSync(config.event_key_file));
  if (eventSeed.length !== 32) throw new Fault("CONFIG_INVALID");
  const eventPub = hex(publicKeyRawFromPrivate(privateKeyFromSeed(eventSeed)));
  if (eventPub !== trust.event_key.public_key) throw new Fault("CONFIG_INVALID");
  const objectKey = new Uint8Array(readFileSync(config.object_key_file));
  if (objectKey.length !== 32) throw new Fault("CONFIG_INVALID");
  for (const p of trust.principals) {
    if (p.public_key === trust.event_key.public_key) throw new Fault("CONFIG_INVALID");
  }
  if (config.profile === "linux-contained-v1") {
    if (config.cgroup_root === "/" || config.image_store === "/") throw new Fault("CONFIG_INVALID");
  }
  // §3.3 fixture keys are public test material; live provisioning must refuse them.
  if (config.live_adapters || config.profile === "linux-contained-v1") {
    const FIXTURE_KEYS = new Set([
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
      "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
      "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    ]);
    const keys = [...trust.principals.map((p) => p.public_key), trust.event_key.public_key];
    if (keys.some((k) => FIXTURE_KEYS.has(k))) throw new Fault("CONFIG_INVALID");
  }

  for (const dir of [dirname(config.database), config.image_store]) {
    mkdirSync(dir, { recursive: true });
  }

  const store = new Store(config.database);
  const objects = new ObjectStore(`${config.database}.objects`, objectKey, config.installation_id, store);
  const emergency = new EmergencyFile(config.emergency_file);
  const kernel = deps.kernel ?? (config.profile === "offline-v1"
    ? new SimKernel(randomUUID(), config.uid_first, config.uid_count)
    : new LinuxKernel(config.cgroup_root, config.uid_first, config.uid_count));
  const bootId = kernel.bootId();

  // the trust file is the installation root of trust; persist it once and
  // refuse to boot under a different anchor on restart.
  const storedTrust = store.metaGet("trust") as unknown | undefined;
  if (storedTrust === undefined) {
    store.metaSet("trust", trust);
  } else if (jcs(storedTrust as Json) !== jcs(trust as unknown as Json)) {
    throw new Fault("CONFIG_INVALID");
  }
  const storedBoot = store.metaGet("boot_id") as string | undefined;
  if (storedBoot !== undefined && storedBoot !== bootId) {
    // new boot: epoch already persists; recovery emits the new boot boundary
  }

  const adapters = deps.adapters ?? new Map<string, AdapterPort>();
  if (!deps.adapters) {
    // adapters from policy are resolved at use time; record_v1 is always local
  }

  const guard: GuardPort = deps.guard ?? (config.profile === "linux-contained-v1"
    ? new GuardProcessPort(config, kernel)
    : new NullGuard());

  const engine = new Engine({
    store,
    installationId: config.installation_id,
    clock: deps.now ?? (() => kernel.nowMs()),
    bootId,
    sign: (domain, hashHex) => ({ key_id: trust.event_key.key_id, sig: signDigest(domain, hashHex, privateKeyFromSeed(eventSeed)) }),
    kernel,
    guard,
    adapters,
    executor: deps.executor ?? null,
    objects,
    emergency,
    profile: config.profile,
    watchScopes: config.watch_scopes,
    liveAdapters: config.live_adapters,
    imageStore: config.profile === "offline-v1" ? null : config.image_store,
  });

  // recovery (spec §7.4): a persisted FENCED host re-fences immediately and
  // never replays recovery; fresh and restarted stores both run the
  // deterministic recovery sequence (RECOVERING marker → READY).
  if (engine.hostState() === "FENCED") {
    // remain fenced; no recovery emissions
  } else {
    engine.recover(kernel.nowMs());
  }
  store.metaSet("boot_id", bootId);

  unlinkIfExists(config.socket);
  const server = new ControlServer({
    socketPath: config.socket,
    engine,
    peercredHelper: deps.peercredHelper ?? join(MODULE_DIR, "..", "..", "native", "peercred"),
    uidOverride: deps.uidOverride,
  });

  const tick = setInterval(() => {
    try {
      engine.tick(kernel.nowMs());
    } catch {
      /* sequencer tick failures surface via metrics/host.status */
    }
  }, 50);
  tick.unref();

  return {
    config, trust, store, engine, server,
    close: async () => {
      clearInterval(tick);
      await server.close();
      unlinkIfExists(config.socket);
      store.close();
    },
  };
}

export function defaultAdapters(liveAdapters: boolean): Map<string, AdapterPort> {
  const m = new Map<string, AdapterPort>();
  m.set("record_v1", new RecordV1Adapter(recordTariffHash()));
  m.set("provider_stub", new ProviderAdapterStub("provider_stub"));
  void liveAdapters;
  return m;
}
function recordTariffHash(): string {
  return sha256Hex(Buffer.from("seatbelt-record-v1-tariff"));
}
