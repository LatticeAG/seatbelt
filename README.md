# Seatbelt — LatticeAGI zone core

[![LatticeAGI](https://img.shields.io/badge/LatticeAGI-Seatbelt%20zone-f5a623)](https://github.com/LatticeAGI)
[![status: OSS core](https://img.shields.io/badge/status-OSS%20core%2C%20pre--release-f5a623)](#status)
[![spec: seatbelt/1 draft.2](https://img.shields.io/badge/spec-seatbelt%2F1%20draft.2-blue)](#)
[![license: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![conformance: 60/60](https://img.shields.io/badge/conformance-60%2F60-brightgreen)](#conformance)

**Every action gets a budget and a kill switch before it gets a job.**

Seatbelt is the LatticeAGI zone that owns budgets, reservations, dispatch
bounds, kill switches, breakers, containment, and the authoritative event
journal for agent execution on a single host. Nothing runs before a budget
admits it, and nothing outruns its stop path.

> No budget, no reservation. No containment, no run. No durable stop, no trust.

## Status

This repository is the **OSS core** of the Seatbelt zone: the durable budget
ledger with hierarchical holds and charged spend, the kill-switch engine
(host / budget / run / watch stops), circuit breakers, the guard contract,
the signed event chain with independent replay verification, evidence export,
migration integrity checks, the Unix-socket control daemon with an fd-3 guest
capability channel, and the `seatbelt` CLI.

It is pre-release software. Hosted, paid, provider, and cloud surfaces —
metered provider adapters, remote attestation anchors, cross-zone composition —
are defined interfaces that fail closed with a stated reason
(`UNSUPPORTED_HOST`, `ADAPTER_UNAVAILABLE`, `NOT_IMPLEMENTED`); they are never
emulated.

Two host profiles ship:

- `offline-v1` — ledger-only. Reads, exports, verification, and ledger
  mutations work; `run.start` returns `UNSUPPORTED_HOST`. Runs anywhere.
- `linux-contained-v1` — real cgroup-v2 containment plus the guard process and
  the seccomp launcher. Requires Linux x86_64 with writable cgroup2; every
  missing capability fails closed at `doctor` and at `run.start`.

## Layout

- `src/` — the authority core (`engine`, `store`, `guard`, `kernel`,
  `verify`, `daemon`, `server`, `guest`, `cli`, …).
- `bin/seatbelt` — the CLI entry point.
- `native/` — small Linux helpers (`peercred` for `SO_PEERCRED`,
  `seatbelt-launcher` for the contained-exec profile).
- `scripts/gen-seccomp-h.mjs` — generates the launcher's seccomp table from
  `src/seccomp.ts` so there is one decision table.
- `test/` — conformance harness: all 60 `TV-S-*` normative vectors plus unit
  and integration coverage.

## Quick start

Requires Node.js ≥ 22.5 (`node:sqlite`) — developed on Node 24.

```sh
npm ci
npm run build:native   # SO_PEERCRED + contained launcher helpers — required
                       # to run the daemon (control socket auth uses them);
                       # offline commands (verify, policy sign|validate,
                       # doctor) work without it
npm test               # builds, then runs the full suite
```

Run the conformance harness against the normative vectors:

```sh
npm run conformance    # 60/60 TV-S vectors
```

CLI sketch — bootstrap an offline ledger, apply policy, inspect, export and
verify evidence. `init` writes `config.json`, `trust.json`, a quorum-signed
revision-1 `policy.json` bundle, and key material under `keys/`; the caller's
OS uid becomes every administrative role (`admin_uids`, `observer_uids`,
`killer_uids`, `watch_uids`).

```sh
seatbelt init --dir /srv/sb --profile offline-v1 --installation-id inst_one
seatbelt doctor --config /srv/sb/config.json --trust /srv/sb/trust.json --json
# every check except "socket" passes before the daemon exists (exit 9)
seatbelt daemon --config /srv/sb/config.json --trust /srv/sb/trust.json \
  --policy /srv/sb/policy.json --foreground &
# `daemon --policy` submits the bundle through the control socket at boot
# with expected_revision "0" — the policy is ACTIVE (revision 1) by the time
# status returns. Re-applying the same bundle reports STALE_REVISION.

seatbelt status --config /srv/sb/config.json --json
# -> {... "policy":"<active policy hash>" ...}
```

Policy updates are compare-and-swap: the new bundle's `body.revision` must be
the active revision + 1, `body.previous` must equal the active policy hash,
and `--expected-revision` must equal the active revision. `--file` takes a
full `PolicyBundle` (`{body, signatures[2..3]}`), not the bare body — sign
the body with `policy sign` and assemble it (trust threshold is 2 distinct
principals):

```sh
# policy2-body.json = body of policy.json with revision "2" and
# previous = <active policy hash> (root_budget/root_limit must not change)
seatbelt policy sign --file policy2-body.json \
  --key /srv/sb/keys/sign_one.seed --key-id sign_one --out sig1.json
seatbelt policy sign --file policy2-body.json \
  --key /srv/sb/keys/sign_two.seed --key-id sign_two --out sig2.json
# -> policy2.json = {"body": policy2-body.json, "signatures": [sig1, sig2]}
seatbelt policy validate --file policy2.json --trust /srv/sb/trust.json --json
seatbelt policy apply --file policy2.json --expected-revision 1 \
  --config /srv/sb/config.json --json
# -> {"policy":"<new policy hash>","revision":"2"}
```

Budgets, events, and offline evidence:

```sh
seatbelt budget create --id project --parent root --limit limit.json \
  --config /srv/sb/config.json --json
seatbelt events --after 0 --limit 64 --config /srv/sb/config.json --json
# -> {"events":[...], "head":{"seq":"N","hash":"<64-hex>"}, "next":"N"}

# export/verify anchors are chain heads: {"seq":"0","hash":"<64 zeros>"} is
# genesis; the `to` head is the `head` field from `events`/`status`.
seatbelt export --from head0.json --to head1.json --disclosure FULL \
  --out bundle.json --config /srv/sb/config.json
seatbelt verify --bundle bundle.json --trust /srv/sb/trust.json \
  --expected-head head1.json --json   # offline, independent replay
```

### Input file schemas

JSON files the CLI validates against closed schemas (extra keys are
rejected). All counters are unsigned-integer *strings* matching
`^(0|[1-9][0-9]{0,18})$`; ids match `^[a-z][a-z0-9_-]{0,63}$`; hashes are
64 lowercase hex chars.

- `--limit FILE` (`budget create`, `budget tighten`, `run`) — a Spend:
  `{"microusd","input_tokens","output_tokens","calls"}` — all four members
  required.
- `--resources FILE` (`run`) — ResourceCaps, all seven members required and
  bounded: `cpu_ms` 1..86400000, `wall_ms` 1000..86400000,
  `memory_bytes` 67108864..8589934592 (64 MiB–8 GiB),
  `scratch_bytes` 1048576..1073741824 (1 MiB–1 GiB), `tasks` 2..256,
  `cpu_quota_us` 1000..400000, and `cpu_period_us` which must equal
  `"100000"` (fixed profile).
- `--launch FILE` (`run`) — `{"image": <64-hex image digest>,
  "executable": "<absolute path>", "argv": [<string>…]}` — argv at most 64
  entries of 1024 bytes each.
- `--evidence FILE` (`watch stop`) — EvidenceRef:
  `{"zone": <id>, "schema": "<^[a-z][a-z0-9_/-]{0,95}$>",
  "hash": <64-hex>}`.
- `--from/--to FILE` (`export`), `--expected-head FILE` (`verify`) — a chain
  Head: `{"seq": <uint string>, "hash": <64-hex>}`. Genesis is
  `{"seq":"0","hash":"000…000"}`. `verify` requires `--expected-head` unless
  `--allow-unanchored` is given.
- `policy apply --file` — a PolicyBundle `{"body": Policy,
  "signatures": [{key_id, sig}…]}` with 2–3 signatures; `policy sign --file`
  accepts either the bare body or a bundle. The Policy body itself is a
  closed 18-member object (`v`, `policy_id`, `revision`, `previous`,
  `root_budget`, `root_limit`, `max_run_limit`, `max_resources`,
  `admin_uids`, `observer_uids`, `killer_uids`, `watch_uids`, `adapters`,
  `breaker`, `max_runs`, `reservation_ms`, `heartbeat_ms`,
  `guard_lease_ms`, `sample_ms`); breaker and the four timings are
  profile-fixed (`{window_ms 1000, max_admissions 10, consecutive_errors 3,
  cooldown_ms 30000, probe_timeout_ms 1000}` and `{reservation_ms 5000,
  heartbeat_ms 1000, guard_lease_ms 750, sample_ms 100}`), `max_runs` is
  1..32, and `root_budget`/`root_limit` are immutable across revisions.

Kill-switch surface:

```sh
seatbelt watch stop --budget project --signal sig_1 --evidence ref.json --config C
seatbelt stop --run run_one --wait-ms 2000 --config C
seatbelt stop --host --config C
seatbelt recover --expected-epoch 1 --config C
```

## Security boundary

Single host, single administrative tenant, mutually untrusted guest workloads.
Caller identity comes from `SO_PEERCRED` on the control socket and from a
scoped capability on the guest's inherited fd 3 — never from request fields.
The journal is a hash-chained, event-key-signed log; evidence bundles verify
against an externally supplied trust anchor, never embedded keys. Audit or
journal failure fences the host rather than degrading to best-effort.

See `STATUS.md` (build-local, gitignored) for phase coverage and known limits.

## License

MIT — see [LICENSE](LICENSE).
