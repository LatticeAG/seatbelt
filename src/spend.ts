// Spend vectors (spec §1.2–1.3): four independent integer coordinates,
// checked 128-bit-style arithmetic via BigInt, vector comparison requires all
// four coordinates to satisfy the predicate.

export type Spend = { microusd: string; input_tokens: string; output_tokens: string; calls: string };
export type SpendVec = { microusd: bigint; input_tokens: bigint; output_tokens: bigint; calls: bigint };

export const DIMS = ["microusd", "input_tokens", "output_tokens", "calls"] as const;
export type Dim = (typeof DIMS)[number];

export function spendToVec(s: Spend): SpendVec {
  return { microusd: BigInt(s.microusd), input_tokens: BigInt(s.input_tokens), output_tokens: BigInt(s.output_tokens), calls: BigInt(s.calls) };
}
export function vecToSpend(v: SpendVec): Spend {
  return { microusd: v.microusd.toString(), input_tokens: v.input_tokens.toString(), output_tokens: v.output_tokens.toString(), calls: v.calls.toString() };
}
export function spendZero(): Spend {
  return { microusd: "0", input_tokens: "0", output_tokens: "0", calls: "0" };
}
export function vecZero(): SpendVec {
  return { microusd: 0n, input_tokens: 0n, output_tokens: 0n, calls: 0n };
}
export function vecAdd(a: SpendVec, b: SpendVec): SpendVec {
  return { microusd: a.microusd + b.microusd, input_tokens: a.input_tokens + b.input_tokens, output_tokens: a.output_tokens + b.output_tokens, calls: a.calls + b.calls };
}
export function vecSub(a: SpendVec, b: SpendVec): SpendVec {
  const r = { microusd: a.microusd - b.microusd, input_tokens: a.input_tokens - b.input_tokens, output_tokens: a.output_tokens - b.output_tokens, calls: a.calls - b.calls };
  if (r.microusd < 0n || r.input_tokens < 0n || r.output_tokens < 0n || r.calls < 0n) throw new Error("spend underflow");
  return r;
}
/** a <= b coordinatewise */
export function vecLe(a: SpendVec, b: SpendVec): boolean {
  return a.microusd <= b.microusd && a.input_tokens <= b.input_tokens && a.output_tokens <= b.output_tokens && a.calls <= b.calls;
}
export function vecLt(a: SpendVec, b: SpendVec): boolean {
  return vecLe(a, b) && !vecEq(a, b);
}
export function vecEq(a: SpendVec, b: SpendVec): boolean {
  return a.microusd === b.microusd && a.input_tokens === b.input_tokens && a.output_tokens === b.output_tokens && a.calls === b.calls;
}
export function vecIsZero(a: SpendVec): boolean {
  return a.microusd === 0n && a.input_tokens === 0n && a.output_tokens === 0n && a.calls === 0n;
}
/** Any positive coordinate of `a` strictly exceeding the same coordinate of `b`. */
export function vecExceeds(a: SpendVec, b: SpendVec): SpendVec | null {
  let over = false;
  const d = vecZero();
  for (const k of DIMS) {
    if (a[k] > b[k]) {
      over = true;
      d[k] = a[k] - b[k];
    }
  }
  return over ? d : null;
}
export function spend(s: SpendVec | Spend): SpendVec {
  return typeof s.microusd === "bigint" ? (s as SpendVec) : spendToVec(s as Spend);
}
