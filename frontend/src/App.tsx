import { useEffect, useState } from "react";
import { stream } from "./ws";
import Peers from "./pages/Peers";
import Queries from "./pages/Queries";
import Infohashes from "./pages/Infohashes";
import Bep44 from "./pages/Bep44";

type Stats = {
  peers: number; queries: number; infohashes: number;
  bep44_items: number; queries_per_min: number;
};

type Tab = "peers" | "queries" | "infohashes" | "bep44";

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
          <div><b>peers</b>{stats.peers.toLocaleString()}</div>
          <div><b>queries</b>{stats.queries.toLocaleString()}</div>
          <div><b>infohashes</b>{stats.infohashes.toLocaleString()}</div>
          <div><b>bep44</b>{stats.bep44_items.toLocaleString()}</div>
          <div><b>rate</b>{stats.queries_per_min}/min</div>
        </div>
      )}
      <nav className="tabs">
        {(["peers", "queries", "infohashes", "bep44"] as Tab[]).map(t => (
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
    </div>
  );
}
