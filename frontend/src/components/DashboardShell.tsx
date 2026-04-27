/*
 * Wraps the live crawler dashboard. Header + live-badge + stats panel
 * + tab nav, with <Outlet /> for the active tab page.
 *
 * Marked noindex via SEO — the data is real-time and not citable.
 */

import { useEffect, useState } from "react";
import { NavLink, Outlet, Link } from "react-router-dom";
import SEO from "./SEO";
import { stream } from "../ws";

type Stats = {
  peers: number;
  peers_v4?: number;
  peers_v6?: number;
  peers_alive_6h?: number;
  peers_alive_24h?: number;
  peers_stale?: number;
  queries: number;
  infohashes: number;
  bep44_items: number;
  queries_per_min: number;
};

const TABS: { to: string; label: string }[] = [
  { to: "/dashboard/peers",      label: "peers" },
  { to: "/dashboard/queries",    label: "queries" },
  { to: "/dashboard/infohashes", label: "infohashes" },
  { to: "/dashboard/bep44",      label: "bep44" },
  { to: "/dashboard/graph",      label: "graph" },
];

export default function DashboardShell() {
  const [up, setUp]       = useState(false);
  const [stats, setStats] = useState<Stats | null>(null);

  useEffect(() => {
    stream.onStatus = setUp;
    fetch("/api/stats").then(r => r.json()).then(setStats).catch(() => {});
    return stream.subscribe((topic, data) => {
      if (topic === "stats") setStats(data as Stats);
    });
  }, []);

  return (
    <div className="app">
      <SEO
        title="Live DHT Dashboard — Peers, Queries, Infohashes"
        description="Real-time BitTorrent Mainline DHT observation: live peer counts, BEP 51 infohash sampling, classifier scores, and a 3D peer-graph view."
        path="/dashboard"
        noindex
      />
      <header>
        <h1><Link to="/" className="home-link">dht44</Link> <span className="small">crawler</span></h1>
        <span className={"badge-live" + (up ? " on" : "")}>●</span>
        <span className="small">{up ? "connected" : "reconnecting…"}</span>
        <span className="header-spacer" />
        <Link to="/" className="small">← back to site</Link>
      </header>
      {stats && (
        <div className="stats">
          <div title="unique (ip, port) peers observed (cumulative since db opened)">
            <b>peers</b>{stats.peers.toLocaleString()}
            {(stats.peers_v4 != null || stats.peers_v6 != null) && (
              <span className="small" style={{ marginLeft: 6 }}>
                (v4:{(stats.peers_v4 ?? 0).toLocaleString()}
                {" "}· v6:{(stats.peers_v6 ?? 0).toLocaleString()})
              </span>
            )}
          </div>
          {stats.peers_alive_6h != null && (
            <div title="peers whose last_seen is within the last 6 hours"
                 style={{ color: "#9be88a" }}>
              <b>alive 6h</b>{stats.peers_alive_6h.toLocaleString()}
            </div>
          )}
          {stats.peers_alive_24h != null && (
            <div title="peers whose last_seen is within the last 24 hours"
                 style={{ color: "#cfd66c" }}>
              <b>alive 24h</b>{stats.peers_alive_24h.toLocaleString()}
            </div>
          )}
          {stats.peers_stale != null && (
            <div title="peers not seen in over 24h (sweeper still re-pings until --prune-days)"
                 style={{ color: "#a0a8b0" }}>
              <b>stale</b>{stats.peers_stale.toLocaleString()}
            </div>
          )}
          <div><b>queries</b>{stats.queries.toLocaleString()}</div>
          <div><b>infohashes</b>{stats.infohashes.toLocaleString()}</div>
          <div><b>bep44</b>{stats.bep44_items.toLocaleString()}</div>
          <div><b>rate</b>{stats.queries_per_min}/min</div>
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
