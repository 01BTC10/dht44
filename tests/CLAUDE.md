# tests/

Unit tests live at `tests/test_<module>.c` and are picked up automatically by the
root `Makefile`:

```sh
make test
```

Each test binary links against every `src/*.o` except `src/main.o` (see
`Makefile`). Tests are plain C: assert and exit non-zero on failure. No external
test framework.

## Per-layer coverage

| Test | Covers |
|---|---|
| `test_bencode.c` | encoder/decoder round-trip, strict dict-key ordering, malformed-input rejection, BEP 44 fixture |
| `test_bep44.c` | target hash, signable bytes, sign/verify against libtorrent vectors, KRPC put/get assembly |

## Integration tests

`tests/integration/*.sh` — slow, spawn real `dht44` binaries, gated behind
`make integration`. None are run by `make test`.

| Script | What it asserts |
|---|---|
| `local_roundtrip.sh` | two-daemon localhost put/get round-trip with sig verification |
| `cas_race.sh` | err 301 on CAS mismatch |
| `seq_regression.sh` | err 302 on seq decrease |
| `live_get.sh` | (opt-in `LIVE=1`) live mainline put + 10s + get from fresh state |

## Conventions

- One `assert_*` helper per test file (or none — direct `if (...) { fprintf; return 1; }`).
- Print `==> <test name>: ok` on success so `make test` output is readable.
- For crypto vectors, hardcode expected hex inline; on failure print
  `expected: ... got: ...` byte-by-byte hex so a mismatch is debuggable.
