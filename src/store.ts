// Authoritative journal + transactional projections (spec §6).
// SQLite WAL, synchronous=FULL, foreign_keys=ON, busy_timeout=100ms, STRICT tables.

import { DatabaseSync } from "node:sqlite";
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { jcsBytes, jcs, parseJsonStrict } from "./canon.js";
import type { Json } from "./canon.js";
import type {
  SignedEvent, EventBody, EventData, Head, Budget, Run, Action, Breaker,
  Capability, Stop, Sample, PolicyBundle,
} from "./schema.js";
import { GENESIS_PREV } from "./schema.js";
import { DBytes, HASH_DOMAINS, sha256Hex } from "./crypto.js";
import { Fault } from "./errors.js";
import { DIMS, type Dim, type SpendVec, spendToVec, vecToSpend } from "./spend.js";

export const STORAGE_VERSION = "1";

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value BLOB NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS events (
  seq INTEGER PRIMARY KEY CHECK(seq > 0), epoch INTEGER NOT NULL,
  kind TEXT NOT NULL, subject TEXT NOT NULL, body BLOB NOT NULL,
  hash BLOB NOT NULL UNIQUE CHECK(length(hash)=32), prev BLOB NOT NULL CHECK(length(prev)=32),
  key_id TEXT NOT NULL, signature BLOB NOT NULL CHECK(length(signature)=64)
) STRICT;
CREATE TABLE IF NOT EXISTS policies (hash BLOB PRIMARY KEY, revision INTEGER NOT NULL UNIQUE, bundle BLOB NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS budgets (
  id TEXT PRIMARY KEY, parent TEXT REFERENCES budgets(id), revision INTEGER NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('ACTIVE','CLOSED')), record BLOB NOT NULL
) STRICT;
CREATE UNIQUE INDEX IF NOT EXISTS one_root ON budgets((1)) WHERE parent IS NULL;
CREATE TABLE IF NOT EXISTS ancestry (
  ancestor TEXT NOT NULL REFERENCES budgets(id), descendant TEXT NOT NULL REFERENCES budgets(id),
  depth INTEGER NOT NULL CHECK(depth BETWEEN 0 AND 7), PRIMARY KEY(ancestor,descendant)
) STRICT;
CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY, budget TEXT NOT NULL REFERENCES budgets(id), epoch INTEGER NOT NULL,
  state TEXT NOT NULL, owner_uid INTEGER NOT NULL, record BLOB NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS counters (
  owner_kind TEXT NOT NULL CHECK(owner_kind IN ('budget','run')), owner TEXT NOT NULL,
  dimension TEXT NOT NULL CHECK(dimension IN ('microusd','input_tokens','output_tokens','calls')),
  cap INTEGER NOT NULL CHECK(cap>=0), held INTEGER NOT NULL CHECK(held>=0),
  charged INTEGER NOT NULL CHECK(charged>=0), CHECK(held<=cap-charged),
  PRIMARY KEY(owner_kind,owner,dimension)
) STRICT;
CREATE TABLE IF NOT EXISTS capabilities (id TEXT PRIMARY KEY, run TEXT NOT NULL UNIQUE REFERENCES runs(id), record BLOB NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS actions (
  id TEXT PRIMARY KEY, operation_id TEXT NOT NULL UNIQUE, run TEXT NOT NULL REFERENCES runs(id),
  intent_hash BLOB NOT NULL, state TEXT NOT NULL, expires_ms INTEGER NOT NULL,
  reserve_seq INTEGER NOT NULL REFERENCES events(seq), dispatch_seq INTEGER UNIQUE REFERENCES events(seq),
  record BLOB NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS holds (
  action TEXT NOT NULL REFERENCES actions(id), owner_kind TEXT NOT NULL, owner TEXT NOT NULL,
  dimension TEXT NOT NULL, amount INTEGER NOT NULL CHECK(amount>=0),
  PRIMARY KEY(action,owner_kind,owner,dimension),
  FOREIGN KEY(owner_kind,owner,dimension) REFERENCES counters(owner_kind,owner,dimension)
) STRICT;
CREATE TABLE IF NOT EXISTS requests (
  principal TEXT NOT NULL, request_id TEXT NOT NULL, input_hash BLOB NOT NULL,
  result BLOB NOT NULL, seq INTEGER NOT NULL, PRIMARY KEY(principal,request_id)
) STRICT;
CREATE TABLE IF NOT EXISTS breakers (budget TEXT PRIMARY KEY REFERENCES budgets(id), record BLOB NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS stops (id TEXT PRIMARY KEY, signal_id TEXT UNIQUE, scope_kind TEXT NOT NULL, scope_id TEXT NOT NULL, record BLOB NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS outbox (
  action TEXT PRIMARY KEY REFERENCES actions(id), state TEXT NOT NULL CHECK(state IN ('MARKED','ATTEMPTED','UNKNOWN','DONE')),
  epoch INTEGER NOT NULL, record BLOB NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS objects (hash BLOB PRIMARY KEY, size INTEGER NOT NULL, relative_path TEXT NOT NULL UNIQUE, encrypted INTEGER NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS checkpoints (seq INTEGER PRIMARY KEY REFERENCES events(seq), hash BLOB NOT NULL, external_pin BLOB) STRICT;
CREATE INDEX IF NOT EXISTS event_subject_seq ON events(subject,seq);
CREATE INDEX IF NOT EXISTS ancestry_descendant_depth ON ancestry(descendant,depth);
CREATE INDEX IF NOT EXISTS run_budget_state ON runs(budget,state);
CREATE INDEX IF NOT EXISTS action_run_state ON actions(run,state);
CREATE INDEX IF NOT EXISTS reservation_expiry ON actions(expires_ms) WHERE state='RESERVED';
CREATE INDEX IF NOT EXISTS unresolved_actions ON actions(run) WHERE state='UNKNOWN';
CREATE INDEX IF NOT EXISTS stop_scope ON stops(scope_kind,scope_id);
`;

export function jToBlob(v: unknown): Buffer {
  return Buffer.from(jcsBytes(v as Json));
}
export function blobToJ<T>(b: Uint8Array): T {
  return parseJsonStrict(new TextDecoder("utf-8", { fatal: true }).decode(b)) as T;
}

export type Row = Record<string, unknown>;

export class Store {
  readonly db: DatabaseSync;
  private readonly anchorPath: string | null;
  constructor(path: string, opts: { anchor?: string } = {}) {
    this.anchorPath = opts.anchor !== undefined ? opts.anchor : (path === ":memory:" ? null : `${path}.anchor`);
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA journal_mode=WAL");
    this.db.exec("PRAGMA synchronous=FULL");
    this.db.exec("PRAGMA foreign_keys=ON");
    this.db.exec("PRAGMA busy_timeout=100");
    this.db.exec(SCHEMA_SQL);
  }
  close(): void {
    this.db.close();
  }
  /** Run fn inside BEGIN IMMEDIATE; commit or roll back atomically. */
  tx<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const r = fn();
      this.db.exec("COMMIT");
      return r;
    } catch (e) {
      try {
        this.db.exec("ROLLBACK");
      } catch {
        // connection-level failure
      }
      throw e;
    }
  }

  metaGet(key: string): Json | undefined {
    const r = this.db.prepare("SELECT value FROM meta WHERE key=?").get(key) as { value: Uint8Array } | undefined;
    return r === undefined ? undefined : blobToJ(r.value);
  }
  metaSet(key: string, value: Json): void {
    this.db.prepare("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(key, jToBlob(value));
  }

  eventHead(): Head {
    const v = this.metaGet("event_head") as Head | undefined;
    return v ?? { seq: "0", hash: GENESIS_PREV };
  }
  nextSeq(): bigint {
    return BigInt(this.eventHead().seq) + 1n;
  }
  getEvent(seq: bigint): SignedEvent | undefined {
    const r = this.db.prepare("SELECT body,hash,key_id,signature FROM events WHERE seq=?").get(seq.toString() as never) as
      | { body: Uint8Array; hash: Uint8Array; key_id: string; signature: Uint8Array }
      | undefined;
    if (!r) return undefined;
    return { body: blobToJ<EventBody>(r.body), hash: Buffer.from(r.hash).toString("hex"), key_id: r.key_id, sig: Buffer.from(r.signature).toString("base64url") };
  }
  /** longest seq-contiguous prefix of (after, head] bounded by count; caller enforces frame size */
  eventsAfter(after: bigint, count: number): SignedEvent[] {
    const rows = this.db
      .prepare("SELECT body,hash,key_id,signature FROM events WHERE seq>? ORDER BY seq ASC LIMIT ?")
      .all(after.toString() as never, count as never) as unknown as { body: Uint8Array; hash: Uint8Array; key_id: string; signature: Uint8Array }[];
    return rows.map((r) => ({
      body: blobToJ<EventBody>(r.body),
      hash: Buffer.from(r.hash).toString("hex"),
      key_id: r.key_id,
      sig: Buffer.from(r.signature).toString("base64url"),
    }));
  }

  /** Append a signed event row. seq must equal head.seq+1; prev must equal head.hash. */
  appendEvent(ev: SignedEvent): void {
    const head = this.eventHead();
    const seq = BigInt(ev.body.seq);
    if (seq !== BigInt(head.seq) + 1n) throw new Error("non-contiguous event seq");
    if (ev.body.prev !== head.hash) throw new Error("prev link mismatch");
    this.db
      .prepare("INSERT INTO events(seq,epoch,kind,subject,body,hash,prev,key_id,signature) VALUES(?,?,?,?,?,?,?,?,?)")
      .run(
        ev.body.seq as never,
        ev.body.epoch as never,
        ev.body.data.kind as never,
        subjectOf(ev.body.data, ev.body.installation_id) as never,
        jToBlob(ev.body),
        Buffer.from(ev.hash, "hex"),
        Buffer.from(ev.body.prev, "hex"),
        ev.key_id,
        Buffer.from(ev.sig, "base64url"),
      );
    this.metaSet("event_head", { seq: ev.body.seq, hash: ev.hash });
    this.writeAnchor(ev.body.seq, ev.hash);
  }

  budget(id: string): Budget | undefined {
    const r = this.db.prepare("SELECT record FROM budgets WHERE id=?").get(id) as { record: Uint8Array } | undefined;
    return r ? blobToJ<Budget>(r.record) : undefined;
  }
  putBudget(b: Budget): void {
    this.db
      .prepare("INSERT INTO budgets(id,parent,revision,state,record) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,state=excluded.state,record=excluded.record")
      .run(b.budget_id, b.parent, b.revision as never, b.state, jToBlob(b));
  }
  budgetsAll(): Budget[] {
    const rows = this.db.prepare("SELECT record FROM budgets").all() as unknown as { record: Uint8Array }[];
    return rows.map((r) => blobToJ<Budget>(r.record));
  }
  ancestryPairs(): { ancestor: string; descendant: string; depth: number }[] {
    return this.db.prepare("SELECT ancestor,descendant,depth FROM ancestry").all() as unknown as { ancestor: string; descendant: string; depth: number }[];
  }
  /** Inclusive root-to-leaf path for a budget: [root, ..., id]. */
  budgetPath(id: string): string[] {
    const chain: string[] = [];
    let cur: string | null = id;
    for (let i = 0; i < 16 && cur !== null; i++) {
      chain.unshift(cur);
      const b = this.budget(cur);
      cur = b ? b.parent : null;
    }
    return chain;
  }
  depthOf(id: string): number {
    return this.budgetPath(id).length - 1;
  }
  descendantsInclusive(id: string): string[] {
    const rows = this.db.prepare("SELECT descendant FROM ancestry WHERE ancestor=? ORDER BY depth").all(id) as unknown as { descendant: string }[];
    return rows.map((r) => r.descendant);
  }
  insertAncestry(parent: string | null, child: string): void {
    if (parent === null) {
      this.db.prepare("INSERT INTO ancestry(ancestor,descendant,depth) VALUES(?,?,0)").run(child, child);
      return;
    }
    // child inherits all ancestors of parent at depth+1, plus self at 0
    const parents = this.db.prepare("SELECT ancestor,depth FROM ancestry WHERE descendant=?").all(parent) as unknown as { ancestor: string; depth: number }[];
    for (const p of parents) {
      this.db.prepare("INSERT INTO ancestry(ancestor,descendant,depth) VALUES(?,?,?)").run(p.ancestor, child, p.depth + 1);
    }
    this.db.prepare("INSERT INTO ancestry(ancestor,descendant,depth) VALUES(?,?,0)").run(child, child);
  }

  counter(ownerKind: "budget" | "run", owner: string): { cap: SpendVec; held: SpendVec; charged: SpendVec } {
    const stmt = this.db
      .prepare("SELECT dimension,cap,held,charged FROM counters WHERE owner_kind=? AND owner=?");
    stmt.setReadBigInts(true);
    const rows = stmt.all(ownerKind, owner) as unknown as { dimension: Dim; cap: bigint | number | string; held: bigint | number | string; charged: bigint | number | string }[];
    const cap: SpendVec = { microusd: 0n, input_tokens: 0n, output_tokens: 0n, calls: 0n };
    const held: SpendVec = { microusd: 0n, input_tokens: 0n, output_tokens: 0n, calls: 0n };
    const charged: SpendVec = { microusd: 0n, input_tokens: 0n, output_tokens: 0n, calls: 0n };
    for (const r of rows) {
      cap[r.dimension] = BigInt(r.cap);
      held[r.dimension] = BigInt(r.held);
      charged[r.dimension] = BigInt(r.charged);
    }
    return { cap, held, charged };
  }
  initCounters(ownerKind: "budget" | "run", owner: string, cap: SpendVec): void {
    for (const d of DIMS) {
      this.db.prepare("INSERT INTO counters(owner_kind,owner,dimension,cap,held,charged) VALUES(?,?,?,?,0,0)").run(ownerKind, owner, d, cap[d].toString() as never);
    }
  }
  setCounter(ownerKind: "budget" | "run", owner: string, dim: Dim, held: bigint, charged: bigint, cap?: bigint): void {
    if (cap === undefined) {
      this.db.prepare("UPDATE counters SET held=?,charged=? WHERE owner_kind=? AND owner=? AND dimension=?").run(held.toString() as never, charged.toString() as never, ownerKind, owner, dim);
    } else {
      this.db.prepare("UPDATE counters SET cap=?,held=?,charged=? WHERE owner_kind=? AND owner=? AND dimension=?").run(cap.toString() as never, held.toString() as never, charged.toString() as never, ownerKind, owner, dim);
    }
  }

  run(id: string): Run | undefined {
    const r = this.db.prepare("SELECT record FROM runs WHERE id=?").get(id) as { record: Uint8Array } | undefined;
    return r ? blobToJ<Run>(r.record) : undefined;
  }
  putRun(r: Run): void {
    this.db
      .prepare("INSERT INTO runs(id,budget,epoch,state,owner_uid,record) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state,record=excluded.record")
      .run(r.run_id, r.budget_id, r.epoch as never, r.state, r.owner_uid, jToBlob(r));
  }
  liveRuns(): Run[] {
    const rows = this.db.prepare("SELECT record FROM runs WHERE state IN ('ARMING','ACTIVE','STOPPING')").all() as unknown as { record: Uint8Array }[];
    return rows.map((r) => blobToJ<Run>(r.record));
  }
  runsUnderBudget(budgetId: string): Run[] {
    const rows = this.db.prepare("SELECT record FROM runs WHERE budget=?").all(budgetId) as unknown as { record: Uint8Array }[];
    return rows.map((r) => blobToJ<Run>(r.record));
  }

  capability(id: string): Capability | undefined {
    const r = this.db.prepare("SELECT record FROM capabilities WHERE id=?").get(id) as { record: Uint8Array } | undefined;
    return r ? blobToJ<Capability>(r.record) : undefined;
  }
  capabilityForRun(runId: string): Capability | undefined {
    const r = this.db.prepare("SELECT record FROM capabilities WHERE run=?").get(runId) as { record: Uint8Array } | undefined;
    return r ? blobToJ<Capability>(r.record) : undefined;
  }
  putCapability(c: Capability): void {
    this.db.prepare("INSERT INTO capabilities(id,run,record) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET record=excluded.record").run(c.capability_id, c.run_id, jToBlob(c));
  }

  action(id: string): Action | undefined {
    const r = this.db.prepare("SELECT record FROM actions WHERE id=?").get(id) as { record: Uint8Array } | undefined;
    return r ? blobToJ<Action>(r.record) : undefined;
  }
  actionByOperation(opId: string): Action | undefined {
    const r = this.db.prepare("SELECT record FROM actions WHERE operation_id=?").get(opId) as { record: Uint8Array } | undefined;
    return r ? blobToJ<Action>(r.record) : undefined;
  }
  putAction(a: Action): void {
    this.db
      .prepare("INSERT INTO actions(id,operation_id,run,intent_hash,state,expires_ms,reserve_seq,dispatch_seq,record) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state,dispatch_seq=excluded.dispatch_seq,record=excluded.record")
      .run(a.action_id, a.intent.operation_id, a.intent.run_id, Buffer.from(a.hash, "hex"), a.state, a.expires_ms as never, a.reserve_seq as never, a.dispatch_seq === null ? null : (a.dispatch_seq as never), jToBlob(a));
  }
  reservedActions(runId: string): Action[] {
    const rows = this.db.prepare("SELECT record FROM actions WHERE run=? AND state='RESERVED'").all(runId) as unknown as { record: Uint8Array }[];
    return rows.map((r) => blobToJ<Action>(r.record));
  }
  expiredReserved(now: bigint): Action[] {
    const stmt = this.db.prepare("SELECT record FROM actions WHERE state='RESERVED' AND expires_ms<=? ORDER BY expires_ms ASC");
    stmt.setReadBigInts(true);
    const rows = stmt.all(now.toString() as never) as unknown as { record: Uint8Array }[];
    return rows.map((r) => blobToJ<Action>(r.record));
  }
  /** all RESERVED actions regardless of run (daemon-wide expiry pass) */
  allReserved(): Action[] {
    const rows = this.db.prepare("SELECT record FROM actions WHERE state='RESERVED'").all() as unknown as { record: Uint8Array }[];
    return rows.map((r) => blobToJ<Action>(r.record));
  }
  actionsByState(state: string): Action[] {
    const rows = this.db.prepare("SELECT record FROM actions WHERE state=?").all(state) as unknown as { record: Uint8Array }[];
    return rows.map((r) => blobToJ<Action>(r.record));
  }
  dispatchedUnfinalized(): Action[] {
    const rows = this.db.prepare("SELECT record FROM actions WHERE state='DISPATCHED'").all() as unknown as { record: Uint8Array }[];
    return rows.map((r) => blobToJ<Action>(r.record));
  }
  insertHold(action: string, ownerKind: "budget" | "run", owner: string, amounts: SpendVec): void {
    for (const d of DIMS) {
      this.db.prepare("INSERT INTO holds(action,owner_kind,owner,dimension,amount) VALUES(?,?,?,?,?)").run(action, ownerKind, owner, d, amounts[d].toString() as never);
    }
  }
  deleteHolds(action: string): void {
    this.db.prepare("DELETE FROM holds WHERE action=?").run(action);
  }

  breaker(budgetId: string): Breaker | undefined {
    const r = this.db.prepare("SELECT record FROM breakers WHERE budget=?").get(budgetId) as { record: Uint8Array } | undefined;
    return r ? blobToJ<Breaker>(r.record) : undefined;
  }
  putBreaker(b: Breaker): void {
    this.db.prepare("INSERT INTO breakers(budget,record) VALUES(?,?) ON CONFLICT(budget) DO UPDATE SET record=excluded.record").run(b.budget_id, jToBlob(b));
  }
  breakersAll(): Breaker[] {
    const rows = this.db.prepare("SELECT record FROM breakers").all() as unknown as { record: Uint8Array }[];
    return rows.map((r) => blobToJ<Breaker>(r.record));
  }

  stop(id: string): Stop | undefined {
    const r = this.db.prepare("SELECT record FROM stops WHERE id=?").get(id) as { record: Uint8Array } | undefined;
    return r ? blobToJ<Stop>(r.record) : undefined;
  }
  stopBySignal(signalId: string): Stop | undefined {
    const r = this.db.prepare("SELECT record FROM stops WHERE signal_id=?").get(signalId) as { record: Uint8Array } | undefined;
    return r ? blobToJ<Stop>(r.record) : undefined;
  }
  putStop(s: Stop): void {
    this.db.prepare("INSERT INTO stops(id,signal_id,scope_kind,scope_id,record) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET record=excluded.record").run(s.kill_id, s.signal_id, s.scope.kind, s.scope.id, jToBlob(s));
  }
  /** Latest stop (by insertion order) for a scope, if any. */
  stopsForScope(kind: string, id: string): Stop[] {
    const rows = this.db.prepare("SELECT record FROM stops WHERE scope_kind=? AND scope_id=?").all(kind, id) as unknown as { record: Uint8Array }[];
    return rows.map((r) => blobToJ<Stop>(r.record));
  }

  outboxGet(action: string): { state: string; epoch: string; record: Uint8Array } | undefined {
    const r = this.db.prepare("SELECT state,epoch,record FROM outbox WHERE action=?").get(action) as { state: string; epoch: bigint | number | string; record: Uint8Array } | undefined;
    return r ? { state: r.state, epoch: String(r.epoch), record: r.record } : undefined;
  }
  outboxPut(action: string, state: string, epoch: string, record: unknown): void {
    this.db.prepare("INSERT INTO outbox(action,state,epoch,record) VALUES(?,?,?,?) ON CONFLICT(action) DO UPDATE SET state=excluded.state,epoch=excluded.epoch,record=excluded.record").run(action, state, epoch as never, jToBlob(record));
  }
  outboxPending(): { action: string; state: string; record: unknown }[] {
    const rows = this.db.prepare("SELECT action,state,record FROM outbox WHERE state IN ('MARKED','ATTEMPTED')").all() as unknown as { action: string; state: string; record: Uint8Array }[];
    return rows.map((r) => ({ action: r.action, state: r.state, record: blobToJ(r.record) }));
  }

  /** Highest head this installation durably committed (sidecar anchor; §7.4 stale-restore detection). */
  anchorHead(): Head | null {
    const p = this.anchorPath;
    if (p === null || !existsSync(p)) return null;
    try {
      const o = JSON.parse(readFileSync(p, "utf8")) as { seq?: string; hash?: string };
      if (typeof o.seq !== "string" || typeof o.hash !== "string") return null;
      return { seq: o.seq, hash: o.hash };
    } catch { return null; }
  }
  private writeAnchor(seq: string, hash: string): void {
    if (this.anchorPath === null) return;
    const tmp = `${this.anchorPath}.tmp`;
    writeFileSync(tmp, JSON.stringify({ seq, hash }));
    renameSync(tmp, this.anchorPath);
  }

  requestGet(principal: string, requestId: string): { inputHash: string; result: Uint8Array; seq: bigint } | undefined {
    const r = this.db.prepare("SELECT input_hash,result,seq FROM requests WHERE principal=? AND request_id=?").get(principal, requestId) as { input_hash: Uint8Array; result: Uint8Array; seq: bigint | number | string } | undefined;
    return r ? { inputHash: Buffer.from(r.input_hash).toString("hex"), result: r.result, seq: BigInt(r.seq) } : undefined;
  }
  requestPut(principal: string, requestId: string, inputHash: string, result: Uint8Array, seq: bigint): void {
    this.db.prepare("INSERT INTO requests(principal,request_id,input_hash,result,seq) VALUES(?,?,?,?,?)").run(principal, requestId, Buffer.from(inputHash, "hex"), Buffer.from(result), seq.toString() as never);
  }

  policyByHash(hash: string): PolicyBundle | undefined {
    const r = this.db.prepare("SELECT bundle FROM policies WHERE hash=?").get(Buffer.from(hash, "hex")) as { bundle: Uint8Array } | undefined;
    return r ? blobToJ<PolicyBundle>(r.bundle) : undefined;
  }
  policyByRevision(rev: bigint): { hash: string; bundle: PolicyBundle } | undefined {
    const r = this.db.prepare("SELECT hash,bundle FROM policies WHERE revision=?").get(rev.toString() as never) as { hash: Uint8Array; bundle: Uint8Array } | undefined;
    return r ? { hash: Buffer.from(r.hash).toString("hex"), bundle: blobToJ<PolicyBundle>(r.bundle) } : undefined;
  }
  putPolicy(hash: string, revision: bigint, bundle: PolicyBundle): void {
    this.db.prepare("INSERT INTO policies(hash,revision,bundle) VALUES(?,?,?)").run(Buffer.from(hash, "hex"), revision.toString() as never, jToBlob(bundle));
  }

  objectRegister(hash: string, size: number, relPath: string, encrypted: boolean): void {
    this.db.prepare("INSERT INTO objects(hash,size,relative_path,encrypted) VALUES(?,?,?,?) ON CONFLICT(hash) DO NOTHING").run(Buffer.from(hash, "hex"), size as never, relPath, encrypted ? 1 : 0);
  }
  objectRegistered(hash: string): boolean {
    return this.db.prepare("SELECT 1 FROM objects WHERE hash=?").get(Buffer.from(hash, "hex")) !== undefined;
  }
  objectsAll(): { hash: string; relPath: string }[] {
    const rows = this.db.prepare("SELECT hash,relative_path FROM objects").all() as unknown as { hash: Uint8Array; relative_path: string }[];
    return rows.map((r) => ({ hash: Buffer.from(r.hash).toString("hex"), relPath: r.relative_path }));
  }

  checkpointPut(seq: bigint, hash: string, externalPin: Uint8Array | null): void {
    this.db.prepare("INSERT INTO checkpoints(seq,hash,external_pin) VALUES(?,?,?) ON CONFLICT(seq) DO UPDATE SET hash=excluded.hash,external_pin=excluded.external_pin").run(seq.toString() as never, Buffer.from(hash, "hex"), externalPin === null ? null : Buffer.from(externalPin));
  }

  countRuns(states: string[]): number {
    const ph = states.map(() => "?").join(",");
    const r = this.db.prepare(`SELECT COUNT(*) c FROM runs WHERE state IN (${ph})`).get(...(states as never[])) as { c: bigint | number };
    return Number(r.c);
  }
}

export function subjectOf(data: EventData, installationId: string): string {
  switch (data.kind) {
    case "PolicyActivated": return data.policy.body.policy_id;
    case "BudgetCreated": return data.budget.budget_id;
    case "BudgetTightened": case "BudgetClosed": case "ProbeObserved": return data.budget_id;
    case "BreakerChanged": return data.breaker.budget_id;
    case "RunCreated": return data.run.run_id;
    case "RunArmed": case "HeartbeatAccepted": case "RunEnded": case "AdmissionDenied": return data.run_id;
    case "UsageObserved": return data.sample.run_id;
    case "ActionReserved": return data.action.action_id;
    case "ActionDispatched": case "ActionReleased": case "ActionObserved": return data.action_id;
    case "StopLatched": case "StopObserved": return data.stop.kill_id;
    case "HostChanged": case "RecoveryGap": case "MigrationApplied": return installationId;
  }
}

/** Compute the event hash of an EventBody. */
export function eventHash(body: EventBody): string {
  return Buffer.from(DBytes(HASH_DOMAINS.EVENT, body as unknown as Json)).toString("hex");
}
export { jcs, sha256Hex };
