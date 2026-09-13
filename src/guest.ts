// Guest fd-3 channel (spec §3.1): the workload side of the control protocol.
// A guest holds a preopened channel bound to one capability — the capability
// record is the authority, not a bearer string. The channel speaks the same
// framed JSON protocol as the control socket; a revoked channel stops reading
// new frames while frames already received are still evaluated and answered.

import { jcsBytes, parseJsonStrict } from "./canon.js";
import type { Json } from "./canon.js";
import { Fault, errResponse } from "./errors.js";
import type { Response } from "./errors.js";
import type { Engine, Caller } from "./engine.js";
import { frame } from "./server.js";

/**
 * One guest channel per run. `read` is the daemon-side entry — it parses the
 * frame, binds the caller to the channel's capability, and returns response
 * bytes to write back. When the capability is revoked the channel must not be
 * called again with new frames.
 */
export class GuestChannel {
  constructor(private engine: Engine, private capabilityId: string) {}

  handleFrame(payload: Uint8Array): Uint8Array | null {
    let req: unknown;
    try {
      req = parseJsonStrict(new TextDecoder().decode(payload));
    } catch {
      return jcsBytes(errResponse("q_invalid", new Fault("INVALID_FRAME")) as unknown as Json);
    }
    const caller: Caller = {
      surface: "fd3", principal: `cap_${this.capabilityId}`, uid: null, capabilityId: this.capabilityId,
    };
    const resp: Response = this.engine.handle(caller, req);
    return jcsBytes(resp as unknown as Json);
  }
}

/** Serialize a request for the fd-3 protocol. */
export function guestFrame(request: unknown): Uint8Array {
  return frame(jcsBytes(request as Json));
}
