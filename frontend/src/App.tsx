import { useEffect, useState } from "react";
import { stream } from "./ws";
import Peers from "./pages/Peers";
import Queries from "./pages/Queries";
import Infohashes from "./pages/Infohashes";
import Bep44 from "./pages/Bep44";
import Graph from "./pages/Graph";

type Stats = {
  peers: number; peers_v4?: number; peers_v6?: number;
  peers_alive_6h?: number; peers_alive_24h?: number; peers_stale?: number;
  queries: number; infohashes: number;
  bep44_items: number; queries_per_min: number;
};

type Tab = "peers" | "queries" | "infohashes" | "bep44" | "graph";

export default function App() {
  const [tab, setTab] = useState<Tab>("peers");
  const [up, setUp]   = useState(false);
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
      <header>
        <h1>dht44 crawler</h1>
        <span className={"badge-live" + (up ? " on" : "")}>●</span>
        <span className="small">{up ? "connected" : "reconnecting…"}</span>
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
        {(["peers", "queries", "infohashes", "bep44", "graph"] as Tab[]).map(t => (
          <button
            key={t}
            className={tab === t ? "active" : ""}
            onClick={() => setTab(t)}
          >
            {t}
          </button>
        ))}
      </nav>
      {tab === "peers"      && <Peers />}
      {tab === "queries"    && <Queries />}
      {tab === "infohashes" && <Infohashes />}
      {tab === "bep44"      && <Bep44 />}
      {tab === "graph"      && <Graph />}
    </div>
  );
}
