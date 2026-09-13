// Hash domains and signatures (spec §1.1).
//   J(x) = JCS UTF-8 bytes.
//   D(tag,x) = hex(SHA256(UTF8(tag) || 0x00 || J(x)))
//   signature = Ed25519 over UTF8(tag) || 0x00 || HEXDECODE(hash)

import { createHash, createPrivateKey, createPublicKey, sign, verify as edVerify, randomBytes, createCipheriv, createDecipheriv, generateKeyPairSync } from "node:crypto";
import type { Json } from "./canon.js";
import { jcsBytes } from "./canon.js";

export const HASH_DOMAINS = {
  POLICY: "SEATBELT-POLICY/1",
  ACTION: "SEATBELT-ACTION/1",
  QUOTE: "SEATBELT-QUOTE/1",
  EVENT: "SEATBELT-EVENT/1",
  BUNDLE: "SEATBELT-BUNDLE/1",
  REQUEST: "SEATBELT-REQUEST/1",
  TRUST: "SEATBELT-TRUST/1",
  MIGRATION: "SEATBELT-MIGRATION/1",
} as const;

export const SIGN_DOMAINS = {
  POLICY: "SEATBELT-POLICY-SIGN/1",
  EVENT: "SEATBELT-EVENT-SIGN/1",
  BUNDLE: "SEATBELT-BUNDLE-SIGN/1",
  MIGRATION: "SEATBELT-MIGRATION-SIGN/1",
} as const;

const enc = new TextEncoder();

export function sha256(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(data).digest());
}
export function sha256Hex(data: Uint8Array | string): string {
  return createHash("sha256").update(data).digest("hex");
}
export function D(tag: string, x: Json): string {
  const h = createHash("sha256");
  h.update(tag + "\0", "utf8");
  h.update(jcsBytes(x));
  return h.digest("hex");
}
export function DBytes(tag: string, x: Json): Uint8Array {
  const h = createHash("sha256");
  h.update(tag + "\0", "utf8");
  h.update(jcsBytes(x));
  return new Uint8Array(h.digest());
}
export function payloadHash(payload: Json): string {
  return sha256Hex(jcsBytes(payload));
}

const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export function publicKeyFromRaw(raw32: Uint8Array): ReturnType<typeof createPublicKey> {
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw32]), format: "der", type: "spki" });
}
export function generateKeyPair(): { publicKey: import("node:crypto").KeyObject; privateKey: import("node:crypto").KeyObject } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { publicKey, privateKey };
}
export function publicKeyHex(pub: import("node:crypto").KeyObject): string {
  return Buffer.from(pub.export({ format: "der", type: "spki" }).subarray(-32)).toString("hex");
}
export function privateKeyFromSeed(seed32: Uint8Array): ReturnType<typeof createPrivateKey> {
  return createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed32]), format: "der", type: "pkcs8" });
}
export function publicKeyRawFromPrivate(priv: ReturnType<typeof createPrivateKey>): Uint8Array {
  const der = createPublicKey(priv).export({ format: "der", type: "spki" });
  return new Uint8Array(der.subarray(der.length - 32));
}

/** Ed25519 over UTF8(tag) || 0x00 || HEXDECODE(hash); returns unpadded base64url. */
export function signDigest(tag: string, hashHex: string, privateKey: ReturnType<typeof createPrivateKey>): string {
  const msg = Buffer.concat([Buffer.from(tag + "\0", "utf8"), Buffer.from(hashHex, "hex")]);
  return sign(null, msg, privateKey).toString("base64url");
}
export function verifyDigest(tag: string, hashHex: string, sigB64: string, publicKeyRaw32: Uint8Array): boolean {
  const msg = Buffer.concat([Buffer.from(tag + "\0", "utf8"), Buffer.from(hashHex, "hex")]);
  let sig: Buffer;
  try {
    sig = Buffer.from(sigB64, "base64url");
  } catch {
    return false;
  }
  if (sig.length !== 64) return false;
  try {
    return edVerify(null, msg, publicKeyFromRaw(publicKeyRaw32), sig);
  } catch {
    return false;
  }
}

export function b64uEncode(b: Uint8Array): string {
  return Buffer.from(b).toString("base64url");
}
export function b64uDecode(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}
export function randomIdBytes(n: number): Uint8Array {
  return new Uint8Array(randomBytes(n));
}

// ---------- Encrypted objects (spec §6.1) ----------
// AES-256-GCM, 12-byte random nonce, 16-byte tag,
// AAD = UTF8("SEATBELT-OBJECT/1" + NUL + installation_id + NUL + lowercase hash)

export function sealObject(key32: Uint8Array, installationId: string, plaintext: Uint8Array): {
  hash: string; nonceB64: string; ciphertextB64: string; tagB64: string;
} {
  const hash = sha256Hex(plaintext);
  const nonce = randomBytes(12);
  const aad = enc.encode(`SEATBELT-OBJECT/1\0${installationId}\0${hash}`);
  const c = createCipheriv("aes-256-gcm", key32, nonce);
  c.setAAD(aad);
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  return { hash, nonceB64: nonce.toString("base64url"), ciphertextB64: ct.toString("base64url"), tagB64: c.getAuthTag().toString("base64url") };
}

export function openObject(key32: Uint8Array, installationId: string, hash: string, nonceB64: string, ciphertextB64: string, tagB64: string): Uint8Array {
  const aad = enc.encode(`SEATBELT-OBJECT/1\0${installationId}\0${hash}`);
  const d = createDecipheriv("aes-256-gcm", key32, Buffer.from(nonceB64, "base64url"));
  d.setAAD(aad);
  d.setAuthTag(Buffer.from(tagB64, "base64url"));
  const pt = Buffer.concat([d.update(Buffer.from(ciphertextB64, "base64url")), d.final()]);
  if (sha256Hex(pt) !== hash) throw new Error("object hash mismatch");
  return new Uint8Array(pt);
}
