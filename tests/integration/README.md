# Integration tests

Run with `make integration` (from the repo root). These spawn real `dht44`
binaries; they're slower and noisier than the unit tests under `tests/test_*`.

## Available

| Script | Status | What it asserts |
|---|---|---|
| `local_roundtrip.sh` | flaky | Two daemons on localhost cross-bootstrap, immutable `put` on A, `get` on B retrieves the same value. **Currently fails:** even with the bootstrap retry, the routing table doesn't populate from a single localhost peer in the time the test allows. Needs investigation — likely related to jech's node-good criteria (a peer is "good" only after it replies to *our* ping, not just having sent us one). May need a longer warm-up window or a tweak to the daemon's bootstrap behavior. |
| `live_get.sh` | opt-in (`LIVE=1`) | Puts a value to mainline, sleeps 10 s, retrieves from a fresh state dir on a second daemon. |

## TODO (deferred to commit 12+)

| Script | Blocker |
|---|---|
| `cas_race.sh` | needs inbound `put` to enforce CAS (returns err 301). Daemon currently accepts any token-validated put without seq/sig checking. |
| `seq_regression.sh` | needs inbound `put` to enforce seq monotonicity (err 302). |
| Mutable round-trip | item file format must store `pk` for the daemon to return `k` in inbound `get` responses; currently mutable items are stored without `pk`. |

## Conventions

- Each script `source`s `common.sh` for `start_daemon NAME PORT [extras...]`,
  `wait_for_socket NAME`, `client NAME args...`, and SIGTERM cleanup.
- All daemons run `--no-upnp --no-routers` so the test environment can't
  leak traffic to the public mainline.
- State directories are per-test under `mktemp -d`; SIGTERM cleanup removes them.
- Logs land in `$TMPROOT/<daemon-name>.log` and are dumped to stderr on
  failure for triage.
