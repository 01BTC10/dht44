#!/usr/bin/env python3
"""
Pull recently-active peers without a GreyNoise reputation record and
look them up against the GreyNoise Community API. Results are written
to peer_reputation(ip='greynoise', label, queried_at).

The Community API is free, requires an API key, and is documented at:
  https://docs.greynoise.io/reference/get_v3-community-ip
Free-tier rate limit is 50 lookups per workspace per day. The script
respects that with a fixed budget per run.

API key path: /etc/dht44/greynoise.token (mode 0600). Missing key →
script logs and exits 0 (so the systemd timer doesn't keep failing).

Driven by deploy/systemd/dht44-greynoise.timer (hourly).

Manual run:
  /home/r2d2/dht44-crawler/scripts/query-greynoise.py [--max N]
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.request

DB_PATH = os.environ.get('DHT44_DB', '/var/lib/dht44/observe.db')
KEY_PATH = os.environ.get('DHT44_GN_KEY', '/etc/dht44/greynoise.token')
DEFAULT_BUDGET = 30          # leave headroom in the 50/day free-tier cap
MIN_PEER_AGE_S = 3600        # only look up peers we've seen recently
RECHECK_AFTER_S = 7 * 86400  # rerun stale rows every week


def log(msg: str) -> None:
    print(f'[greynoise] {msg}', flush=True)


def load_key() -> str | None:
    try:
        with open(KEY_PATH, 'r', encoding='utf-8') as f:
            return f.read().strip() or None
    except FileNotFoundError:
        return None
    except PermissionError:
        log(f'cannot read {KEY_PATH} (perm denied)')
        return None


def pick_targets(conn: sqlite3.Connection, limit: int) -> list[str]:
    """Peers active within MIN_PEER_AGE_S that don't yet have a fresh
    GreyNoise reputation row. Sorted by recency so the most-likely-to-
    actually-be-online IPs are queried first."""
    now = int(time.time())
    fresh = now - MIN_PEER_AGE_S
    recheck = now - RECHECK_AFTER_S
    rows = conn.execute(
        """
        SELECT DISTINCT p.ip FROM peers p
          LEFT JOIN peer_reputation r
                 ON r.ip = p.ip AND r.source = 'greynoise'
         WHERE p.last_seen >= ?
           AND (r.ip IS NULL OR r.queried_at < ?)
           AND p.ip NOT LIKE '%:%'           -- v4 only on the free tier
           AND p.ip NOT LIKE '%/%'            -- skip already-redacted rows
         ORDER BY p.last_seen DESC
         LIMIT ?
        """,
        (fresh, recheck, limit),
    ).fetchall()
    return [r[0] for r in rows]


def query_gn(ip: str, key: str, timeout: float = 8.0) -> dict | None:
    req = urllib.request.Request(
        f'https://api.greynoise.io/v3/community/{ip}',
        headers={
            'key': key,
            'Accept': 'application/json',
            'User-Agent': 'dht44-reputation/1.0 (+https://dht44.com)',
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {'noise': False, 'classification': 'unseen'}
        if e.code == 429:
            log('rate limited (429); stopping')
            raise
        log(f'{ip}: HTTP {e.code}')
        return None
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        log(f'{ip}: {e}')
        return None


def label_from_response(payload: dict) -> str | None:
    """Convert the GN community response into a compact label.
    Possible labels:
      benign:<actor>            (e.g. "benign:censys")
      malicious                 (the API doesn't disclose actor name)
      suspicious
      unseen                    (recorded so we don't keep re-querying)
    """
    if not isinstance(payload, dict):
        return None
    cls = (payload.get('classification') or '').strip().lower()
    if not payload.get('noise', False) and cls in ('', 'unseen'):
        return 'unseen'
    if cls == 'benign':
        actor = (payload.get('name') or '').strip().lower().replace(' ', '_')
        return f'benign:{actor}' if actor else 'benign'
    if cls in ('malicious', 'suspicious'):
        return cls
    if cls == 'unknown':
        return 'unknown'
    return cls or 'unseen'


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--max', type=int, default=DEFAULT_BUDGET,
                    help='max API calls in this run (default: %(default)d)')
    ap.add_argument('--db', default=DB_PATH)
    args = ap.parse_args()

    key = load_key()
    if not key:
        log(f'no API key at {KEY_PATH}; place a GreyNoise key (mode 0600) and rerun')
        return 0

    if not os.path.exists(args.db):
        log(f'db missing: {args.db}')
        return 0

    conn = sqlite3.connect(args.db, timeout=10.0)
    conn.execute('PRAGMA busy_timeout = 5000')
    targets = pick_targets(conn, args.max)
    if not targets:
        log('nothing to query')
        return 0

    log(f'will query {len(targets)} IP(s)')
    written = 0
    now = int(time.time())
    try:
        for ip in targets:
            payload = query_gn(ip, key)
            if not payload:
                continue
            label = label_from_response(payload)
            if not label:
                continue
            conn.execute(
                """
                INSERT INTO peer_reputation(ip,source,label,queried_at)
                VALUES(?,?,?,?)
                ON CONFLICT(ip,source) DO UPDATE SET
                  label=excluded.label, queried_at=excluded.queried_at
                """,
                (ip, 'greynoise', label, now),
            )
            written += 1
            # Polite pacing — well under the per-second cap and gives
            # the daemon's writers air.
            time.sleep(0.5)
        conn.commit()
    finally:
        conn.close()
    log(f'wrote {written} rows')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
