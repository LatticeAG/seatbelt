// Emergency evidence slots (spec §6.1): 32 preallocated fixed 4096-byte slots.
// Layout per slot: u32be payload length (1..4088), JCS payload, u32be CRC32C of
// payload, zero padding. Torn/invalid slots force RecoveryGap at import.

import { openSync, closeSync, fsyncSync, readSync, writeSync, existsSync, mkdirSync, statSync } from "node:fs";
import { dirname } from "node:path";
import { jcsBytes, parseJsonStrict, SchemaError } from "./canon.js";
import { validateEmergencyPayload, type EmergencyPayload } from "./schema.js";
import { EMERGENCY_SLOTS, EMERGENCY_SLOT_BYTES } from "./profile.js";
import { sha256Hex } from "./crypto.js";

// CRC-32C (Castagnoli), reflected polynomial 0x82F63B78.
const CRC_TABLE: Uint32Array = (() => {
  const t = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0x82f63b78 ^ (c >>> 1) : c >>> 1;
    t[i] = c >>> 0;
  }
  return t;
})();
export function crc32c(data: Uint8Array): number {
  let c = 0xffffffff;
  for (let i = 0; i < data.length; i++) c = CRC_TABLE[(c ^ data[i]!) & 0xff]! ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

export type SlotParse =
  | { ok: true; payload: EmergencyPayload }
  | { ok: false };

/** A 32-slot emergency file; created preallocated if absent. */
export class EmergencyFile {
  readonly path: string;
  private fd: number;
  constructor(path: string) {
    this.path = path;
    mkdirSync(dirname(path), { recursive: true });
    if (!existsSync(path) || statSync(path).size !== EMERGENCY_SLOTS * EMERGENCY_SLOT_BYTES) {
      const fd = openSync(path, "w");
      try {
        writeSync(fd, Buffer.alloc(EMERGENCY_SLOTS * EMERGENCY_SLOT_BYTES));
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
    }
    this.fd = openSync(path, "r+");
  }
  close(): void {
    closeSync(this.fd);
  }
  private readSlot(i: number): Buffer {
    const b = Buffer.alloc(EMERGENCY_SLOT_BYTES);
    readSync(this.fd, b, 0, EMERGENCY_SLOT_BYTES, i * EMERGENCY_SLOT_BYTES);
    return b;
  }
  /** first free slot index or -1 */
  private freeSlot(): number {
    for (let i = 0; i < EMERGENCY_SLOTS; i++) {
      const b = this.readSlot(i);
      if (b.every((x) => x === 0)) return i;
    }
    return -1;
  }
  /** Write a payload record; returns slot index or -1 when full. */
  write(payload: EmergencyPayload): number {
    const body = jcsBytes(payload);
    if (body.length < 1 || body.length > 4088) return -1;
    const i = this.freeSlot();
    if (i < 0) return -1;
    const slot = Buffer.alloc(EMERGENCY_SLOT_BYTES);
    slot.writeUInt32BE(body.length, 0);
    Buffer.from(body).copy(slot, 4);
    slot.writeUInt32BE(crc32c(body), 4 + body.length);
    writeSync(this.fd, slot, 0, EMERGENCY_SLOT_BYTES, i * EMERGENCY_SLOT_BYTES);
    fsyncSync(this.fd);
    return i;
  }
  /** Parse every slot. Returns per-slot results; unreadable slots are {ok:false}. */
  readAll(): SlotParse[] {
    const out: SlotParse[] = [];
    for (let i = 0; i < EMERGENCY_SLOTS; i++) {
      const b = this.readSlot(i);
      if (b.every((x) => x === 0)) {
        continue; // empty slot — not an error
      }
      const len = b.readUInt32BE(0);
      if (len < 1 || len > 4088) {
        out.push({ ok: false });
        continue;
      }
      const payload = b.subarray(4, 4 + len);
      const crc = b.readUInt32BE(4 + len);
      if (crc32c(payload) !== crc) {
        out.push({ ok: false });
        continue;
      }
      // padding must be zero
      if (!b.subarray(4 + len + 4).every((x) => x === 0)) {
        out.push({ ok: false });
        continue;
      }
      try {
        const v = parseJsonStrict(new TextDecoder("utf-8", { fatal: true }).decode(payload));
        out.push({ ok: true, payload: validateEmergencyPayload(v) });
      } catch (e) {
        if (e instanceof SchemaError) out.push({ ok: false });
        else out.push({ ok: false });
      }
    }
    return out;
  }
  /** Clear a slot after durable import and observed emptiness. */
  clear(i: number): void {
    writeSync(this.fd, Buffer.alloc(EMERGENCY_SLOT_BYTES), 0, EMERGENCY_SLOT_BYTES, i * EMERGENCY_SLOT_BYTES);
    fsyncSync(this.fd);
  }
  /** hash over all raw slot bytes — used for RecoveryGap emergency_hash. */
  digest(): string {
    const all = Buffer.alloc(EMERGENCY_SLOTS * EMERGENCY_SLOT_BYTES);
    readSync(this.fd, all, 0, all.length, 0);
    return sha256Hex(all);
  }
}
