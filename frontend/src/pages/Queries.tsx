import { useEffect, useRef, useState } from "react";
import { stream, hex, fmtTs } from "../ws";
import { usePaused } from "../components/HoverPause";

type Row = {
  ts: number;
  ip: string; port: number;
  direction: "in" | "out";
  y: "q" | "r" | "e";
  q: string | null;
  target: string | null;
  raw_size: number;
  v_string?: string | null;
};

const MAX_ROWS = 500;

export default function Queries() {
  const [rows, setRows] = useState<Row[]>([]);
  const [filter, setFilter] = useState("");
  const [paused, setPaused] = useState(false);
  const hoverPaused = usePaused();
  const pausedRef = useRef(paused || hoverPaused);
  pausedRef.current = paused || hoverPaused;

  useEffect(() => {
    fetch("/api/queries?limit=200").then(r => r.json()).then(setRows).catch(() => {});
    return stream.subscribe((topic, data) => {
      if (topic !== "queries" || pausedRef.current) return;
      setRows(prev => {
        const next = [data as Row, ...prev];
        if (next.length > MAX_ROWS) next.length = MAX_ROWS;
        return next;
      });
    });
  }, []);

  const f = filter.toLowerCase();
  const filtered = f
    ? rows.filter(r => {
        const s = [r.ip, r.q, r.direction, r.y, r.target].filter(Boolean).join(" ").toLowerCase();
        return s.includes(f);
      })
    : rows;

  return (
    <>
      <div className="filter">
        <input placeholder="filter by q / ip / target…"
               value={filter} onChange={e => setFilter(e.target.value)} />
        <button style={{ marginLeft: 10 }} onClick={() => setPaused(p => !p)}>
          {paused ? "resume" : "pause"}
        </button>
        <span className="small" style={{ marginLeft: 10 }}>
          {filtered.length} live
        </span>
      </div>
      <table>
        <thead>
          <tr>
            <th>time</th>
            <th>dir</th>
            <th>y</th>
            <th>q</th>
            <th>ip:port</th>
            <th>target</th>
            <th>bytes</th>
          </tr>
        </thead>
        <tbody>
          {filtered.slice(0, 200).map((r, i) => (
            <tr key={r.ts + r.ip + r.port + i}>
              <td>{fmtTs(r.ts)}</td>
              <td className={r.direction === "in" ? "ok" : "dim"}>{r.direction}</td>
              <td>{r.y}</td>
              <td>{r.q || ""}</td>
              <td>{r.ip}:{r.port}</td>
              <td className="hex">{hex(r.target || "", 20)}</td>
              <td>{r.raw_size}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
