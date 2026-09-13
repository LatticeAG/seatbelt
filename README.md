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
npm run build:native   # optional: SO_PEERCRED + contained launcher helpers
npm test               # builds, then runs the full suite
```

Run the conformance harness against the normative vectors:

```sh
npm run conformance    # 60/60 TV-S vectors
```

CLI sketch — bootstrap an offline ledger, apply policy, inspect, export and
verify evidence:

```sh
seatbelt init --dir /srv/sb --profile offline-v1 --installation-id inst_one
seatbelt doctor --config /srv/sb/config.json --trust /srv/sb/trust.json --json
seatbelt daemon --config /srv/sb/config.json --trust /srv/sb/trust.json \
  --policy /srv/sb/policy.json --foreground &

seatbelt status --config /srv/sb/config.json --json
seatbelt policy apply --file /srv/sb/policy.json --expected-revision 0 \
  --config /srv/sb/config.json --json
seatbelt budget create --id project --parent root --limit limit.json \
  --config /srv/sb/config.json --json
seatbelt events --after 0 --limit 64 --config /srv/sb/config.json --json
seatbelt export --from head0.json --to head1.json --disclosure FULL \
  --out bundle.json --config /srv/sb/config.json
seatbelt verify --bundle bundle.json --trust /srv/sb/trust.json \
  --expected-head head1.json --json   # offline, independent replay
```

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
