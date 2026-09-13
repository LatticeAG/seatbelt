// Scalar grammars from spec §1.1–1.2.

import { SchemaError } from "./canon.js";

export const U_MAX = 9223372036854775807n;
const U_RE = /^(0|[1-9][0-9]{0,18})$/;
const ID_RE = /^[a-z][a-z0-9_-]{0,63}$/;
const HASH_RE = /^[0-9a-f]{64}$/;
const SIG_RE = /^[A-Za-z0-9_-]{86}$/;
const BOOT_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const EV_SCHEMA_RE = /^[a-z][a-z0-9_/-]{0,95}$/;
const B64U_RE = /^[A-Za-z0-9_-]+$/;

export function isU(v: unknown): v is string {
  return typeof v === "string" && U_RE.test(v) && BigInt(v) <= U_MAX;
}
export function checkU(v: unknown, field: string): string {
  if (!isU(v)) throw new SchemaError(`${field}: invalid unsigned decimal string`);
  return v;
}
export function isId(v: unknown): v is string {
  return typeof v === "string" && ID_RE.test(v);
}
export function checkId(v: unknown, field: string): string {
  if (!isId(v)) throw new SchemaError(`${field}: invalid identifier`);
  return v;
}
export function isHash(v: unknown): v is string {
  return typeof v === "string" && HASH_RE.test(v);
}
export function checkHash(v: unknown, field: string): string {
  if (!isHash(v)) throw new SchemaError(`${field}: invalid hash`);
  return v;
}
export function isSig(v: unknown): v is string {
  return typeof v === "string" && SIG_RE.test(v);
}
export function checkSig(v: unknown, field: string): string {
  if (!isSig(v)) throw new SchemaError(`${field}: invalid signature encoding`);
  return v;
}
export function isBootId(v: unknown): v is string {
  return typeof v === "string" && BOOT_RE.test(v);
}
export function checkBootId(v: unknown, field: string): string {
  if (!isBootId(v)) throw new SchemaError(`${field}: invalid boot id`);
  return v;
}
export function isEvidenceSchema(v: unknown): v is string {
  return typeof v === "string" && EV_SCHEMA_RE.test(v);
}
export function checkEvidenceSchema(v: unknown, field: string): string {
  if (!isEvidenceSchema(v)) throw new SchemaError(`${field}: invalid evidence schema`);
  return v;
}
export function isBase64Url(v: unknown): v is string {
  return typeof v === "string" && v.length > 0 && B64U_RE.test(v);
}
/** Non-negative safe integer JSON number field (v, uids, exit codes, bounds). */
export function checkUint(v: unknown, field: string): number {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0 || Object.is(v, -0)) {
    throw new SchemaError(`${field}: invalid nonnegative integer`);
  }
  return v;
}
export function uToBig(v: string): bigint {
  return BigInt(v);
}
export function bigToU(v: bigint): string {
  if (v < 0n || v > U_MAX) throw new SchemaError("u128 range violation");
  return v.toString(10);
}
