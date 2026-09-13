// Adapter boundary (spec §1.4, §3.4). Only trusted pinned adapters compute
// quotes from exact Intent bytes and a locally pinned tariff; quoting performs
// no billable I/O. Live provider adapters are a zone-gated certified surface:
// the stub below fails closed with ADAPTER_UNAVAILABLE/NotImplemented rather
// than emulating a provider.

import { D, HASH_DOMAINS, payloadHash, sha256Hex } from "./crypto.js";
import { jcsBytes } from "./canon.js";
import type { Json } from "./canon.js";
import type { AdapterPin, Intent, Outcome, Quote } from "./schema.js";
import { spendZero, type Spend } from "./spend.js";
import { Fault } from "./errors.js";

export type AdapterError = "UNBOUNDED_COST" | "PRICE_CHANGED" | "ADAPTER_UNAVAILABLE";
export type QuoteResult = { ok: true; quote: Quote } | { ok: false; error: AdapterError };
export type ExecuteResult = { outcome: Outcome; resultBytes: Uint8Array | null };

export interface AdapterPort {
  readonly adapterId: string;
  /** current installed tariff hash for preflight PRICE_CHANGED detection */
  tariffHash(): string;
  quote(intent: Intent, pin: AdapterPin, actionHash: string): QuoteResult;
  /** synchronous local probe; no billable work */
  probe(probeId: string, tariff: string): boolean;
  /** read-only outcome lookup; bounded, non-billable */
  lookup(actionId: string, operationKey: string, actionHash: string): ExecuteResult;
}

/** Executor seam: the engine calls start after the dispatch marker commits. */
export interface ExecutorPort {
  startExecution(input: {
    actionId: string; operationKey: string; intent: Intent; quote: Quote;
    dispatchSeq: string; deadlineMs: bigint; pin: AdapterPin;
  }): void;
}

// ---------------- record_v1: deterministic non-billable adapter ----------------

export class RecordV1Adapter implements AdapterPort {
  readonly adapterId = "record_v1";
  private tariff: string;
  constructor(tariff: string) {
    this.tariff = tariff;
  }
  tariffHash(): string {
    return this.tariff;
  }
  quote(_intent: Intent, pin: AdapterPin, actionHash: string): QuoteResult {
    if (pin.operation !== "record") return { ok: false, error: "ADAPTER_UNAVAILABLE" };
    return {
      ok: true,
      quote: {
        action_hash: actionHash,
        adapter: this.adapterId,
        tariff: this.tariff,
        upper: { microusd: "0", input_tokens: "0", output_tokens: "0", calls: "1" },
        duration_ms: "1000",
        response_bytes: pin.max_response_bytes,
      },
    };
  }
  probe(_probeId: string, _tariff: string): boolean {
    return true;
  }
  execute(input: { intent: Intent }): ExecuteResult {
    const p = input.intent.payload;
    const bytes = p.kind === "record" ? new TextEncoder().encode(p.value) : new Uint8Array(0);
    return {
      outcome: {
        status: "SUCCEEDED",
        actual: { microusd: "0", input_tokens: "0", output_tokens: "0", calls: "1" },
        result_hash: sha256Hex(bytes),
        evidence: [],
      },
      resultBytes: bytes,
    };
  }
  lookup(_a: string, _k: string, _h: string): ExecuteResult {
    return { outcome: { status: "UNKNOWN", actual: null, result_hash: null, evidence: [] }, resultBytes: null };
  }
}

// ---------------- test-only bounded adapter (harness) ----------------

/**
 * Harness-only adapter (spec §11.1): supplies caller-programmed quotes and
 * outcomes with no network calls. Production configuration cannot select it —
 * the daemon only wires it when constructed through the test harness.
 */
export class TestAdapter implements AdapterPort {
  readonly adapterId: string;
  tariff: string;
  nextQuoteUpper: Spend | null = null;
  nextQuoteDuration = "1000";
  nextQuoteResponseBytes = "16384";
  unbounded = false;
  priceChangedOnDispatch = false;
  sends = 0;
  executes: string[] = [];
  lookupOutcome: ExecuteResult = { outcome: { status: "UNKNOWN", actual: null, result_hash: null, evidence: [] }, resultBytes: null };
  probeResult = true;
  /** pending execute outcomes the harness delivers explicitly */
  pending = new Map<string, ExecuteResult>();
  nextOutcome: ExecuteResult | null = null;
  autoComplete = true;
  /** per-token tariff for the bounded_call simulator (§1.4 formula) */
  tokenTariff: { pi: bigint; po: bigint; fee: bigint } | null = null;
  /** installed-executable drift: digest the adapter reports for its binary */
  exeDrift = false;
  exeHash(): string {
    return this.exeDrift ? D("fixture", { exe: "drifted" } as unknown as Json) : D("fixture", { exe: "record-v1" } as unknown as Json);
  }

  constructor(adapterId = "record_v1", tariff = "") {
    this.adapterId = adapterId;
    this.tariff = tariff;
  }
  tariffHash(): string {
    return this.priceChangedOnDispatch ? D(HASH_DOMAINS.QUOTE, { drifted: true } as unknown as Json) : this.tariff;
  }
  quote(_intent: Intent, _pin: AdapterPin, actionHash: string): QuoteResult {
    if (this.unbounded) return { ok: false, error: "UNBOUNDED_COST" };
    const upper = this.nextQuoteUpper ?? { microusd: "0", input_tokens: "0", output_tokens: "0", calls: "1" };
    if (this.tokenTariff !== null) {
      // §1.4: f + ceil(in*pi/1e6) + ceil(out*po/1e6)
      const p = _intent.payload;
      const inT = p.kind === "bounded_call" ? BigInt(p.max_input_tokens) : 0n;
      const outT = p.kind === "bounded_call" ? BigInt(p.max_output_tokens) : 0n;
      const t = this.tokenTariff;
      const micro = t.fee + (inT * t.pi + 999999n) / 1000000n + (outT * t.po + 999999n) / 1000000n;
      upper.microusd = micro.toString();
    }
    return {
      ok: true,
      quote: {
        action_hash: actionHash, adapter: this.adapterId, tariff: this.tariff, upper,
        duration_ms: this.nextQuoteDuration, response_bytes: this.nextQuoteResponseBytes,
      },
    };
  }
  probe(_probeId: string, _tariff: string): boolean {
    return this.probeResult;
  }
  lookup(_a: string, _k: string, _h: string): ExecuteResult {
    return this.lookupOutcome;
  }
}

// ---------------- zone-gated provider adapter stub ----------------

/**
 * A certified live provider adapter (bounded_call over real egress) is gated on
 * the release conditions in spec §12 phase 5 — destination pinning, billing
 * bound, idempotency, no-retry, response limits, and lookup certification.
 * This stub documents the interface and fails closed; it never emits bytes.
 */
export class ProviderAdapterStub implements AdapterPort {
  readonly adapterId: string;
  constructor(adapterId: string) {
    this.adapterId = adapterId;
  }
  private unavailable(): never {
    throw new Fault("ADAPTER_UNAVAILABLE");
  }
  tariffHash(): string {
    return this.unavailable();
  }
  quote(): QuoteResult {
    return { ok: false, error: "ADAPTER_UNAVAILABLE" };
  }
  probe(): boolean {
    return false;
  }
  lookup(): ExecuteResult {
    this.unavailable();
  }
}

export function actionHashOf(intent: Intent): string {
  return D(HASH_DOMAINS.ACTION, intent as unknown as Json);
}
export function sealedIntentOf(intent: Intent): Omit<Intent, "payload"> & { payload_hash: string } {
  const { payload, ...rest } = intent;
  return { ...rest, payload_hash: payloadHash(payload as unknown as Json) };
}
export function quoteHashOf(quote: Quote): string {
  return D(HASH_DOMAINS.QUOTE, quote as unknown as Json);
}
export { payloadHash, jcsBytes };
export { spendZero };
