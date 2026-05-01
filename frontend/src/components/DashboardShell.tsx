/*
 * Wraps the live crawler dashboard. Header + live-badge + stats panel
 * + tab nav, with <Outlet /> for the active tab page.
 *
 * Marked noindex via SEO — the data is real-time and not citable.
 */

import { useEffect, useRef, useState } from "react";
import { NavLink, Outlet, Link } from "react-router-dom";
import SEO from "./SEO";
import { stream } from "../ws";

type DenyBreakdown = { reputation: number; rate_limit: number; classifier: number };
type Stats = {
  peers: number;
  peers_v4?: number;
  peers_v6?: number;
  peers_alive_6h?: number;
  peers_alive_24h?: number;
  peers_stale?: number;
  /* jech/dht routing-table populations (IPv4). "good" = responsive
   * within ~15 min; "total" = good + dubious. Optional so the
   * dashboard still renders against an older daemon. */
  routing_good?: number;
  routing_total?: number;
  queries: number;
  infohashes: number;
  bep44_items: number;
  queries_per_min: number;
  /* Unix seconds of the earliest peer observation in this db.
   * Used to render "uptime since first observation". 0 if empty. */
  db_first_seen?: number;
  deny_set_size?: number;
  denied_pkts?: DenyBreakdown;
  deny_breakdown?: DenyBreakdown;
};

/* "since X" duration in compact form: "3d 4h", "5h 12m", "47m", "8s".
 * Uses Date arithmetic so it follows the browser's clock and timezone. */
function fmtUptime(firstSeenSec: number): string {
  if (!firstSeenSec) return "—";
  const elapsed = Math.max(0, Date.now() / 1000 - firstSeenSec);
  const d = Math.floor(elapsed / 86400);
  const h = Math.floor((elapsed % 86400) / 3600);
  const m = Math.floor((elapsed % 3600) / 60);
  const s = Math.floor(elapsed % 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${s}s`;
  return `${s}s`;
}

const TABS: { to: string; label: string }[] = [
  { to: "/dashboard/peers",      label: "peers" },
  { to: "/dashboard/queries",    label: "queries" },
  { to: "/dashboard/infohashes", label: "infohashes" },
  { to: "/dashboard/bep44",      label: "bep44" },
  { to: "/dashboard/graph",      label: "graph" },
];

/* Sum the three denied_pkts buckets into a single cumulative count. */
function deniedTotal(d: DenyBreakdown | undefined): number {
  if (!d) return 0;
  return (d.reputation ?? 0) + (d.rate_limit ?? 0) + (d.classifier ?? 0);
}

export default function DashboardShell() {
  const [up, setUp]       = useState(false);
  const [stats, setStats] = useState<Stats | null>(null);
  /* Rolling window of recent samples for computing drops/min. We keep
   * the oldest sample within the 60-second window plus the latest;
   * the rate is (latest.total - oldest.total) / elapsed_minutes.
   * After a daemon restart the cumulative counter resets to 0, which
   * we detect (latest < oldest) and reseed the window. */
  const sampleHistory = useRef<{ ts: number; denied: number }[]>([]);
  const [dropsPerMin, setDropsPerMin] = useState<number | null>(null);

  useEffect(() => {
    stream.onStatus = setUp;
    // The Stream singleton is constructed at module-load time, so its
    // ws.onopen fires before this component mounts and the indicator
    // misses the "connected" event. Sync to the current state on mount.
    setUp(stream.isConnected());
    fetch("/api/stats").then(r => r.json()).then(setStats).catch(() => {});
    return stream.subscribe((topic, data) => {
      if (topic === "stats") setStats(data as Stats);
    });
  }, []);

  /* Recompute drops/min whenever a new stats sample arrives. */
  useEffect(() => {
    if (!stats || !stats.denied_pkts) return;
    const now    = Date.now();
    const denied = deniedTotal(stats.denied_pkts);
    const hist   = sampleHistory.current;
    /* Detect counter reset (daemon restart): drops counter went down. */
    if (hist.length && denied < hist[hist.length - 1].denied) hist.length = 0;
    hist.push({ ts: now, denied });
    /* Trim anything older than 5 min. */
    while (hist.length > 1 && now - hist[0].ts > 5 * 60 * 1000) hist.shift();
    /* Need at least 5s of history for a non-jittery rate. */
    if (hist.length >= 2 && now - hist[0].ts >= 5000) {
      const elapsedMin = (now - hist[0].ts) / 60000;
      setDropsPerMin((denied - hist[0].denied) / elapsedMin);
    }
  }, [stats]);

  return (
    <div className="app">
      {/* Dashboard is now the default landing (/ → /dashboard/peers), so
       * we let search engines index it. The canonical is the Peers tab,
       * which is what the index route renders. */}
      <SEO
        title="Live DHT Dashboard — Peers, Queries, Infohashes"
        description="Real-time BitTorrent Mainline DHT observation: live peer counts, BEP 51 infohash sampling, classifier scores, and a 3D peer-graph view."
        path="/dashboard/peers"
      />
      <header>
        <h1><Link to="/dashboard/peers" className="home-link">dht44</Link> <span className="small">crawler</span></h1>
        <span className={"badge-live" + (up ? " on" : "")}>●</span>
        <span className="small">{up ? "connected" : "reconnecting…"}</span>
        <span className="header-spacer" />
        <Link
          to="/intro"
          style={{
            color: "#8fc0ff",
            fontSize: 12,
            padding: "4px 12px",
            border: "1px solid #2a3642",
            borderRadius: 3,
            background: "#14181d",
            whiteSpace: "nowrap",
          }}
        >
          about the project →
        </Link>
      </header>
      {stats && (
        <div className="stats">
          {stats.routing_good != null && (
            <div title="BitTorrent DHT routing table — good IPv4 nodes (have responded within ~15 min per BEP 5). Total = good + dubious. This is the closest thing to a live-link count."
                 style={{ color: "#7ce0ff" }}>
              <b>connected (good)</b>{stats.routing_good.toLocaleString()}
              {stats.routing_total != null && (
                <span className="small" style={{ marginLeft: 6 }}>
                  /{stats.routing_total.toLocaleString()}
                </span>
              )}
            </div>
          )}
          <div title="Unique (ip, port) peers ever observed since the database was first opened (cumulative, all-time).">
            <b>peers seen</b>{stats.peers.toLocaleString()}
            {(stats.peers_v4 != null || stats.peers_v6 != null) && (
              <span className="small" style={{ marginLeft: 6 }}>
                (v4:{(stats.peers_v4 ?? 0).toLocaleString()}
                {" "}· v6:{(stats.peers_v6 ?? 0).toLocaleString()})
              </span>
            )}
          </div>
          {stats.peers_alive_6h != null && (
            <div title="Peers with last_seen in the last 6 hours. The liveness sweeper re-pings every observed peer on a rolling cadence so this count stays meaningful."
                 style={{ color: "#9be88a" }}>
              <b>seen 6h</b>{stats.peers_alive_6h.toLocaleString()}
            </div>
          )}
          {stats.peers_alive_24h != null && (
            <div title="Peers with last_seen in the last 24 hours."
                 style={{ color: "#cfd66c" }}>
              <b>seen 24h</b>{stats.peers_alive_24h.toLocaleString()}
            </div>
          )}
          {stats.peers_stale != null && (
            <div title="Peers not heard from in over 24 hours. The sweeper keeps re-pinging until --prune-days (default 7d), at which point they're deleted from the DB."
                 style={{ color: "#a0a8b0" }}>
              <b>stale (&gt;24h)</b>{stats.peers_stale.toLocaleString()}
            </div>
          )}
          <div title="All KRPC queries observed (cumulative since DB opened).">
            <b>queries seen</b>{stats.queries.toLocaleString()}
          </div>
          <div title="Query rate over the trailing 60 seconds." style={{ minWidth: 110 }}>
            <b>queries/min</b>{stats.queries_per_min.toLocaleString()}
          </div>
          <div title="Unique infohashes observed (cumulative since DB opened).">
            <b>infohashes</b>{stats.infohashes.toLocaleString()}
          </div>
          <div title="BEP 44 mutable + immutable items observed (cumulative since DB opened).">
            <b>bep44 items</b>{stats.bep44_items.toLocaleString()}
          </div>
          {stats.deny_set_size != null && (
            <div title={
              "Active set (TTL ≤ 1h, currently denied): "
              + (stats.deny_breakdown
                  ? `rep:${stats.deny_breakdown.reputation} `
                    + `rate:${stats.deny_breakdown.rate_limit} `
                    + `cls:${stats.deny_breakdown.classifier}`
                  : "?")
              + "\nDrops/min (rolling 60s): "
              + (dropsPerMin != null ? Math.round(dropsPerMin).toLocaleString() : "?")
              + "\nCumulative drops (persisted across restarts, since DB opened): "
              + (stats.denied_pkts
                  ? `rep:${stats.denied_pkts.reputation} `
                    + `rate:${stats.denied_pkts.rate_limit} `
                    + `cls:${stats.denied_pkts.classifier}`
                  : "?")
            }
                 style={{ color: "#ff9bb5", minWidth: 170 }}>
              <b>denied (active)</b>{stats.deny_set_size.toLocaleString()}
              {dropsPerMin != null && (
                /* inline-block + min-width so jumping from "(87/min)"
                 * to "(123/min)" doesn't push the rest of the pill row. */
                <span className="small"
                      style={{ marginLeft: 6, display: "inline-block",
                               minWidth: 70, textAlign: "left" }}>
                  ({Math.round(dropsPerMin).toLocaleString()}/min)
                </span>
              )}
            </div>
          )}
          {stats.db_first_seen != null && stats.db_first_seen > 0 && (
            <div
              title={`Time since the first peer was observed in this DB. Stable across daemon restarts; resets only if observe.db is deleted. First seen: ${new Date(stats.db_first_seen * 1000).toLocaleString()}`}
              style={{ color: "#a0a8b0" }}
            >
              <b>observing for</b>{fmtUptime(stats.db_first_seen)}
            </div>
          )}
        </div>
      )}
      <nav className="tabs">
        {TABS.map(t => (
          <NavLink
            key={t.to}
            to={t.to}
            className={({ isActive }) => (isActive ? "active" : "")}
          >
            {t.label}
          </NavLink>
        ))}
      </nav>
      <Outlet />
    </div>
  );
}
