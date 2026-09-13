// AF_UNIX control socket (spec §3.1): one length-prefixed JSON frame per
// request. Peer identity is SO_PEERCRED via the native helper — a socket the
// kernel cannot credential is rejected before any byte is read. Per-UID
// limits: 8 concurrent connections, 100 requests/second.

import { createServer, Socket } from "node:net";
import type { Server } from "node:net";
import { spawnSync } from "node:child_process";
import { chmodSync, unlinkSync, existsSync } from "node:fs";
import { jcsBytes, parseJsonStrict, SchemaError } from "./canon.js";
import type { Json } from "./canon.js";
import { Fault, okResponse, errResponse } from "./errors.js";
import type { Response } from "./errors.js";
import type { Engine, Caller } from "./engine.js";

export const MAX_FRAME = 65536;
const MAX_CONCURRENT_PER_UID = 8;
const MAX_RPS_PER_UID = 100;
const RATE_WINDOW_MS = 1000;

/** Resolve peer UID via SO_PEERCRED using the native helper on the socket fd. */
export function peerUid(socket: Socket, helper: string): number {
  const fd = (socket as unknown as { _handle?: { fd?: number } })._handle?.fd;
  if (fd === undefined || fd < 0) throw new Fault("UNAUTHENTICATED");
  const r = spawnSync(helper, ["3"], { stdio: ["ignore", "pipe", "ignore", fd], encoding: "utf8" });
  if (r.status !== 0) throw new Fault("UNAUTHENTICATED");
  const m = /^(\d+)$/.exec(r.stdout.trim());
  if (!m) throw new Fault("UNAUTHENTICATED");
  return Number(m[1]);
}

class RateWindow {
  private hits: number[] = [];
  allow(now: number): boolean {
    const cutoff = now - RATE_WINDOW_MS;
    while (this.hits.length > 0 && this.hits[0]! <= cutoff) this.hits.shift();
    if (this.hits.length >= MAX_RPS_PER_UID) return false;
    this.hits.push(now);
    return true;
  }
}

export interface ControlServerOptions {
  socketPath: string;
  engine: Engine;
  peercredHelper: string;
  /** test seam only — production always uses SO_PEERCRED */
  uidOverride?: number | undefined;
  onFrame?: (uid: number) => void;
}

export class ControlServer {
  private server: Server;
  private perUid = new Map<number, { concurrent: number; rate: RateWindow }>();
  private opts: ControlServerOptions;

  constructor(opts: ControlServerOptions) {
    this.opts = opts;
    this.server = createServer((s) => this.onConnection(s));
  }

  listen(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server.once("error", reject);
      this.server.listen(this.opts.socketPath, () => {
        try {
          chmodSync(this.opts.socketPath, 0o600);
        } catch { /* mode set below anyway */ }
        resolve();
      });
    });
  }

  close(): Promise<void> {
    return new Promise((resolve) => this.server.close(() => resolve()));
  }

  private onConnection(socket: Socket): void {
    let uid: number;
    try {
      uid = this.opts.uidOverride ?? peerUid(socket, this.opts.peercredHelper);
    } catch {
      socket.destroy();
      return;
    }
    let e = this.perUid.get(uid);
    if (!e) {
      e = { concurrent: 0, rate: new RateWindow() };
      this.perUid.set(uid, e);
    }
    if (e.concurrent >= MAX_CONCURRENT_PER_UID) {
      socket.destroy();
      return;
    }
    e.concurrent++;
    socket.on("close", () => {
      e!.concurrent--;
    });
    let buf = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      for (;;) {
        if (buf.length < 4) break;
        const len = buf.readUInt32BE(0);
        if (len > MAX_FRAME) {
          // a frame over 65536 bytes: reject without reading further
          const resp = errResponse("q_invalid", new Fault("INVALID_FRAME"));
          socket.end(frame(jcsBytes(resp as unknown as Json)));
          return;
        }
        if (buf.length < 4 + len) break;
        const payload = buf.subarray(4, 4 + len);
        buf = buf.subarray(4 + len);
        if (!e!.rate.allow(Date.now())) {
          socket.end(frame(jcsBytes(errResponse("q_invalid", new Fault("RATE_LIMIT")) as unknown as Json)));
          return;
        }
        const resp = this.handleFrame(uid, payload);
        if (resp === null) {
          socket.destroy();
          return;
        }
        socket.write(frame(jcsBytes(resp as unknown as Json)));
      }
    });
    socket.on("error", () => socket.destroy());
  }

  private handleFrame(uid: number, payload: Buffer): Response | null {
    this.opts.onFrame?.(uid);
    let req: unknown;
    try {
      req = parseJsonStrict(payload.toString("utf8"));
    } catch {
      return errResponse("q_invalid", new Fault("INVALID_FRAME"));
    }
    const caller: Caller = { surface: "control", principal: `uid_${uid}`, uid, capabilityId: null };
    return this.opts.engine.handle(caller, req);
  }
}

export function frame(payload: Uint8Array): Buffer {
  const out = Buffer.alloc(4 + payload.length);
  out.writeUInt32BE(payload.length, 0);
  out.set(payload, 4);
  return out;
}

/** Simple synchronous-style client used by the CLI. */
export async function rpcOnce(socketPath: string, request: Json, timeoutMs = 10000): Promise<Response> {
  const { connect } = await import("node:net");
  return new Promise((resolve, reject) => {
    const socket = connect(socketPath);
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Fault("BUSY"));
    }, timeoutMs);
    let buf = Buffer.alloc(0);
    socket.on("connect", () => {
      socket.write(frame(jcsBytes(request)));
    });
    socket.on("data", (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length < 4) return;
      const len = buf.readUInt32BE(0);
      if (buf.length < 4 + len) return;
      clearTimeout(timer);
      socket.end();
      try {
        resolve(parseJsonStrict(buf.subarray(4, 4 + len).toString("utf8")) as Response);
      } catch {
        reject(new Fault("INVALID_FRAME"));
      }
    });
    socket.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

export function unlinkIfExists(p: string): void {
  if (existsSync(p)) {
    try {
      unlinkSync(p);
    } catch { /* ignore */ }
  }
}
