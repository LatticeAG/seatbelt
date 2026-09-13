// Fixed linux-contained-v1 profile constants (spec §5.1, §2.4, §2.5).
// These values are fixed for this profile; a policy carrying different
// fixed-profile values is INVALID_SCHEMA at apply.

export const FIXED_BREAKER = {
  window_ms: "1000",
  max_admissions: "10",
  consecutive_errors: "3",
  cooldown_ms: "30000",
  probe_timeout_ms: "1000",
} as const;

export const FIXED_TIMINGS = {
  reservation_ms: "5000",
  heartbeat_ms: "1000",
  guard_lease_ms: "750",
  sample_ms: "100",
} as const;

export const CPU_PERIOD_US = "100000";

// Resource bounds (§5.1): memory 64MiB–8GiB, scratch 1MiB–1GiB, tasks 2–256,
// wall 1000–86400000ms, cpu 1–86400000ms, quota 1000–400000µs.
export const RESOURCE_BOUNDS = {
  cpu_ms: { min: 1n, max: 86400000n },
  wall_ms: { min: 1000n, max: 86400000n },
  memory_bytes: { min: 67108864n, max: 8589934592n },
  scratch_bytes: { min: 1048576n, max: 1073741824n },
  tasks: { min: 2n, max: 256n },
  cpu_quota_us: { min: 1000n, max: 400000n },
} as const;

export const MAX_RUNS_MIN = 1n;
export const MAX_RUNS_MAX = 32n;
export const MAX_RESERVED_PER_RUN = 8;
export const BUDGET_PATH_MAX_DEPTH = 8; // inclusive; ancestry rows store depth 0..7
export const MAX_ANCESTRY_CHILD_DEPTH = 7;
export const MAX_UID_SET = 32;
export const MAX_ADAPTERS = 16;
export const MAX_EVIDENCE = 32;
export const MAX_ARGV = 64;
export const MAX_ARGV_BYTES = 1024;
export const SETUP_TIMEOUT_MS = 2000n;
export const STOPPING_FENCE_MS = 2000n;
export const KILL_RETRY_MS = 1000n;
export const FIRST_BEAT_GRACE_MS = 1000n;
export const LOOKUP_DEADLINE_MS = 2000;
export const LOOKUP_MAX_RESPONSE = 16384;
export const EVENTS_READ_LIMIT_MAX = 128;
export const EMERGENCY_SLOTS = 32;
export const EMERGENCY_SLOT_BYTES = 4096;
export const GUARD_CHANNEL = 3;
