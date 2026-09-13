// ErrorCode registry (spec §1.5), fault detail sentences (§3.1), and the
// CLI fault→exit mapping (§4.2).

export type ErrorCode =
  | "INVALID_FRAME" | "INVALID_SCHEMA" | "VERSION_UNSUPPORTED" | "UNAUTHENTICATED"
  | "FORBIDDEN" | "NOT_FOUND" | "CONFLICT" | "IDEMPOTENCY_CONFLICT" | "STALE_REVISION"
  | "CAP_EXCEEDED" | "CEILING_TOO_LOW" | "UNBOUNDED_COST" | "PRICE_CHANGED" | "EXPIRED"
  | "STOPPED" | "BREAKER_OPEN" | "RATE_LIMIT" | "BUSY" | "UNSUPPORTED_HOST"
  | "ADAPTER_UNAVAILABLE" | "AUDIT_UNAVAILABLE" | "HOST_FENCED" | "COUNTER_EXHAUSTED"
  | "BOUND_BREACH" | "EVIDENCE_INVALID" | "CONFIG_INVALID";

const DETAILS: Record<ErrorCode, string> = {
  INVALID_FRAME: "Malformed frame.",
  INVALID_SCHEMA: "Message violates the closed schema.",
  VERSION_UNSUPPORTED: "Unsupported protocol or object version.",
  UNAUTHENTICATED: "Peer identity is not authenticated.",
  FORBIDDEN: "Caller lacks the required role.",
  NOT_FOUND: "Resource not found.",
  CONFLICT: "Request conflicts with current state.",
  IDEMPOTENCY_CONFLICT: "Request identifier was reused with different bytes.",
  STALE_REVISION: "Expected revision does not match the stored revision.",
  CAP_EXCEEDED: "Budget capacity exceeded.",
  CEILING_TOO_LOW: "Intent ceiling is below the quoted upper bound.",
  UNBOUNDED_COST: "Operation cost cannot be bounded.",
  PRICE_CHANGED: "Pinned price changed since reservation.",
  EXPIRED: "Deadline expired.",
  STOPPED: "Run is stopped.",
  BREAKER_OPEN: "Circuit breaker is open.",
  RATE_LIMIT: "Admission rate limit exceeded.",
  BUSY: "Service temporarily busy.",
  UNSUPPORTED_HOST: "Host lacks the required containment support.",
  ADAPTER_UNAVAILABLE: "Required adapter is unavailable.",
  AUDIT_UNAVAILABLE: "Durable audit is unavailable.",
  HOST_FENCED: "Host is fenced.",
  COUNTER_EXHAUSTED: "Sequence counter space exhausted.",
  BOUND_BREACH: "Observed billing exceeded its certified bound.",
  EVIDENCE_INVALID: "Evidence failed verification.",
  CONFIG_INVALID: "Configuration or trust failed cross-validation.",
};

const RETRYABLE: ReadonlySet<ErrorCode> = new Set(["BUSY"]);

const EXIT: Record<ErrorCode, number> = {
  INVALID_FRAME: 2, INVALID_SCHEMA: 2, VERSION_UNSUPPORTED: 2,
  UNAUTHENTICATED: 3, FORBIDDEN: 3,
  CAP_EXCEEDED: 4, CEILING_TOO_LOW: 4, UNBOUNDED_COST: 4, PRICE_CHANGED: 4,
  EXPIRED: 4, STOPPED: 4, BREAKER_OPEN: 4, RATE_LIMIT: 4,
  NOT_FOUND: 5, CONFLICT: 5, IDEMPOTENCY_CONFLICT: 5, STALE_REVISION: 5,
  BUSY: 6, UNSUPPORTED_HOST: 6, ADAPTER_UNAVAILABLE: 6, AUDIT_UNAVAILABLE: 6,
  HOST_FENCED: 6, COUNTER_EXHAUSTED: 6, BOUND_BREACH: 6,
  EVIDENCE_INVALID: 8,
  CONFIG_INVALID: 9,
};

export class Fault extends Error {
  readonly code: ErrorCode;
  constructor(code: ErrorCode) {
    super(DETAILS[code]);
    this.name = "Fault";
    this.code = code;
  }
  get retryable(): boolean {
    return RETRYABLE.has(this.code);
  }
  get detail(): string {
    return DETAILS[this.code];
  }
  get exitCode(): number {
    return EXIT[this.code];
  }
  toJSON(): { code: ErrorCode; retryable: boolean; detail: string } {
    return { code: this.code, retryable: this.retryable, detail: this.detail };
  }
}

export function fault(code: ErrorCode): Fault {
  return new Fault(code);
}

export type Response =
  | { v: 1; request_id: string; ok: true; result: unknown; error: null }
  | { v: 1; request_id: string; ok: false; result: null; error: { code: ErrorCode; retryable: boolean; detail: string } };

export function okResponse(requestId: string, result: unknown): Response {
  return { v: 1, request_id: requestId, ok: true, result, error: null };
}
export function errResponse(requestId: string, f: Fault): Response {
  return { v: 1, request_id: requestId, ok: false, result: null, error: f.toJSON() };
}
