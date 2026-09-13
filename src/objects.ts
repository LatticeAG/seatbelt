// Encrypted immutable private evidence objects (spec §6.1).
// Plaintext is J(Payload), J(Launch), or raw result bytes; stored under
// objects/<2-hex>/<hash> as J(EncryptedObject) using AES-256-GCM.

import { mkdirSync, writeFileSync, readFileSync, existsSync, openSync, closeSync, fsyncSync } from "node:fs";
import { join } from "node:path";
import { sealObject, openObject } from "./crypto.js";
import { jcsBytes, parseJsonStrict, jcs } from "./canon.js";
import type { Json } from "./canon.js";
import { validateEncryptedObject } from "./schema.js";
import type { Store } from "./store.js";

export class ObjectStore {
  readonly dir: string;
  private key: Uint8Array;
  private installationId: string;
  private store: Store | null;
  constructor(dir: string, key32: Uint8Array, installationId: string, store: Store | null) {
    this.dir = dir;
    this.key = key32;
    this.installationId = installationId;
    this.store = store;
    mkdirSync(dir, { recursive: true });
  }
  private rel(hash: string): string {
    return join(hash.slice(0, 2), hash);
  }
  private abs(hash: string): string {
    return join(this.dir, this.rel(hash));
  }
  /** Seal and persist plaintext; registers in the objects index. Idempotent. */
  put(plaintext: Uint8Array): string {
    const sealed = sealObject(this.key, this.installationId, plaintext);
    const rec = { v: 1, hash: sealed.hash, nonce_b64: sealed.nonceB64, ciphertext_b64: sealed.ciphertextB64, tag_b64: sealed.tagB64 };
    const p = this.abs(sealed.hash);
    if (!existsSync(p)) {
      mkdirSync(join(this.dir, sealed.hash.slice(0, 2)), { recursive: true });
      const fd = openSync(p, "wx", 0o600); // no-clobber
      try {
        writeFileSync(fd, jcsBytes(rec));
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
    }
    this.store?.objectRegister(sealed.hash, plaintext.length, this.rel(sealed.hash), true);
    return sealed.hash;
  }
  has(hash: string): boolean {
    return existsSync(this.abs(hash));
  }
  /** Decrypt + verify; throws on tamper. */
  get(hash: string): Uint8Array {
    const raw = readFileSync(this.abs(hash));
    const rec = validateEncryptedObject(parseJsonStrict(new TextDecoder().decode(raw)));
    return openObject(this.key, this.installationId, rec.hash, rec.nonce_b64, rec.ciphertext_b64, rec.tag_b64);
  }
  putJson(v: Json): string {
    return this.put(jcsBytes(v));
  }
  getJson(hash: string): Json {
    return parseJsonStrict(new TextDecoder("utf-8", { fatal: true }).decode(this.get(hash)));
  }
}
