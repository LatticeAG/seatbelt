// Canonical representation (spec §1.1): strict UTF-8 JSON with duplicate-member,
// BOM, invalid-UTF-8, lone-surrogate, and frame-limit rejection; JCS (RFC 8785)
// serialization for hashing.
//
// Boundary: a byte sequence that never yields a complete JSON value is
// INVALID_FRAME; a fully parsed value violating closed rules (duplicate members
// included) is INVALID_SCHEMA.

export const MAX_FRAME_BYTES = 65536;
export const MAX_GUARD_FRAME_BYTES = 4096;
export const MAX_DEPTH = 16;
export const MAX_MEMBERS = 256;
export const MAX_ELEMENTS = 256;
export const MAX_ACTION_PAYLOAD_BYTES = 16384;
export const MAX_POLICY_BODY_BYTES = 8192;
export const MAX_LAUNCH_BYTES = 16384;

/** Thrown when bytes never form a complete JSON value → INVALID_FRAME. */
export class FrameError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = "FrameError";
  }
}

/** Thrown when a parsed value violates closed rules → INVALID_SCHEMA. */
export class SchemaError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = "SchemaError";
  }
}

export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

/** Strict decode of UTF-8 bytes to text; rejects BOM, truncation, invalid UTF-8. */
export function decodeUtf8Strict(bytes: Uint8Array): string {
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    throw new FrameError("BOM not allowed");
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new FrameError("invalid UTF-8");
  }
  return text;
}

/**
 * Parse strict JSON text. Rejects lone surrogates (INVALID_FRAME per the
 * invalid-UTF-8-equivalent rule in §1.1), duplicate object members
 * (INVALID_SCHEMA), and frame structural limits (INVALID_SCHEMA).
 */
export function parseJsonStrict(text: string): Json {
  let i = 0;
  const n = text.length;

  function err(msg: string): never {
    throw new FrameError(msg);
  }
  function skipWs(): void {
    while (i < n) {
      const c = text.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else break;
    }
  }
  function hasLoneSurrogate(s: string): boolean {
    for (let k = 0; k < s.length; k++) {
      const c = s.charCodeAt(k);
      if (c >= 0xd800 && c <= 0xdbff) {
        const d = s.charCodeAt(k + 1);
        if (!(d >= 0xdc00 && d <= 0xdfff)) return true;
        k++;
      } else if (c >= 0xdc00 && c <= 0xdfff) return true;
    }
    return false;
  }
  function parseString(): string {
    // i points at opening quote
    i++;
    let out = "";
    while (i < n) {
      const c = text.charCodeAt(i);
      if (c === 0x22) {
        i++;
        if (hasLoneSurrogate(out)) throw new FrameError("lone surrogate");
        return out;
      }
      if (c === 0x5c) {
        i++;
        if (i >= n) err("truncated escape");
        const e = text[i];
        switch (e) {
          case '"': out += '"'; i++; break;
          case "\\": out += "\\"; i++; break;
          case "/": out += "/"; i++; break;
          case "b": out += "\b"; i++; break;
          case "f": out += "\f"; i++; break;
          case "n": out += "\n"; i++; break;
          case "r": out += "\r"; i++; break;
          case "t": out += "\t"; i++; break;
          case "u": {
            if (i + 4 >= n) err("truncated \\u escape");
            const hex = text.slice(i + 1, i + 5);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) err("bad \\u escape");
            const cu = parseInt(hex, 16);
            i += 5;
            if (cu >= 0xd800 && cu <= 0xdbff) {
              // possible surrogate pair
              if (text.charCodeAt(i) === 0x5c && text[i + 1] === "u" && i + 5 < n + 1) {
                const hex2 = text.slice(i + 2, i + 6);
                if (/^[0-9a-fA-F]{4}$/.test(hex2)) {
                  const cu2 = parseInt(hex2, 16);
                  if (cu2 >= 0xdc00 && cu2 <= 0xdfff) {
                    out += String.fromCharCode(cu, cu2);
                    i += 6;
                    break;
                  }
                }
              }
              out += String.fromCharCode(cu); // lone; caught by hasLoneSurrogate
            } else {
              out += String.fromCharCode(cu);
            }
            break;
          }
          default:
            err("bad escape");
        }
      } else {
        if (c < 0x20) err("control character in string");
        out += text[i];
        i++;
      }
    }
    err("unterminated string");
  }
  function parseNumber(): number {
    const start = i;
    if (text[i] === "-") i++;
    if (i >= n) err("bad number");
    if (text[i] === "0") {
      i++;
    } else if (text[i]! >= "1" && text[i]! <= "9") {
      while (i < n && text[i]! >= "0" && text[i]! <= "9") i++;
    } else {
      err("bad number");
    }
    if (text[i] === ".") {
      i++;
      if (!(i < n && text[i]! >= "0" && text[i]! <= "9")) err("bad number");
      while (i < n && text[i]! >= "0" && text[i]! <= "9") i++;
    }
    if (text[i] === "e" || text[i] === "E") {
      i++;
      if (text[i] === "+" || text[i] === "-") i++;
      if (!(i < n && text[i]! >= "0" && text[i]! <= "9")) err("bad number");
      while (i < n && text[i]! >= "0" && text[i]! <= "9") i++;
    }
    const raw = text.slice(start, i);
    const v = Number(raw);
    if (!Number.isFinite(v)) err("non-finite number");
    return v;
  }
  function parseValue(depth: number): Json {
    if (depth > MAX_DEPTH) throw new SchemaError("depth limit exceeded");
    skipWs();
    if (i >= n) err("unexpected end");
    const c = text[i]!;
    if (c === "{") {
      i++;
      const obj: { [k: string]: Json } = {};
      skipWs();
      if (text[i] === "}") {
        i++;
        return obj;
      }
      let members = 0;
      for (;;) {
        skipWs();
        if (text[i] !== '"') err("object key must be string");
        const key = parseString();
        skipWs();
        if (text[i] !== ":") err("expected :");
        i++;
        const val = parseValue(depth + 1);
        if (Object.prototype.hasOwnProperty.call(obj, key)) {
          throw new SchemaError("duplicate object member");
        }
        obj[key] = val;
        members++;
        if (members > MAX_MEMBERS) throw new SchemaError("member limit exceeded");
        skipWs();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "}") {
          i++;
          return obj;
        }
        err("expected , or }");
      }
    }
    if (c === "[") {
      i++;
      const arr: Json[] = [];
      skipWs();
      if (text[i] === "]") {
        i++;
        return arr;
      }
      for (;;) {
        const v = parseValue(depth + 1);
        arr.push(v);
        if (arr.length > MAX_ELEMENTS) throw new SchemaError("array limit exceeded");
        skipWs();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "]") {
          i++;
          return arr;
        }
        err("expected , or ]");
      }
    }
    if (c === '"') return parseString();
    if (c === "t") {
      if (text.slice(i, i + 4) !== "true") err("bad literal");
      i += 4;
      return true;
    }
    if (c === "f") {
      if (text.slice(i, i + 5) !== "false") err("bad literal");
      i += 5;
      return false;
    }
    if (c === "n") {
      if (text.slice(i, i + 4) !== "null") err("bad literal");
      i += 4;
      return null;
    }
    if (c === "-" || (c >= "0" && c <= "9")) return parseNumber();
    err("unexpected character");
  }

  const v = parseValue(1);
  skipWs();
  if (i !== n) err("trailing bytes after value");
  return v;
}

/** Parse a complete wire frame's JSON payload (bytes already length-framed). */
export function parseFramePayload(bytes: Uint8Array): Json {
  if (bytes.length === 0) throw new FrameError("empty frame");
  return parseJsonStrict(decodeUtf8Strict(bytes));
}

// ---------- JCS (RFC 8785) canonical serialization ----------

function escapeString(s: string): string {
  let out = '"';
  for (let k = 0; k < s.length; k++) {
    const c = s.charCodeAt(k);
    if (c === 0x22) out += '\\"';
    else if (c === 0x5c) out += "\\\\";
    else if (c === 0x08) out += "\\b";
    else if (c === 0x09) out += "\\t";
    else if (c === 0x0a) out += "\\n";
    else if (c === 0x0c) out += "\\f";
    else if (c === 0x0d) out += "\\r";
    else if (c < 0x20) out += "\\u" + c.toString(16).padStart(4, "0");
    else out += s[k];
  }
  return out + '"';
}

/** JCS-canonicalize a parsed JSON value to a UTF-8 string. */
export function jcs(v: Json): string {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new SchemaError("non-finite number");
    if (Object.is(v, -0)) return "0";
    return JSON.stringify(v);
  }
  if (typeof v === "string") return escapeString(v);
  if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
  const keys = Object.keys(v).sort(); // UTF-16 code-unit order
  return "{" + keys.map((k) => escapeString(k) + ":" + jcs(v[k]!)).join(",") + "}";
}

/** J(x): JCS UTF-8 bytes. */
export function jcsBytes(v: Json): Uint8Array {
  return new TextEncoder().encode(jcs(v));
}
