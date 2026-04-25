import { useEffect, useRef, useState } from "react";
import { stream, hex, fmtTs } from "../ws";
import { usePaused } from "../components/HoverPause";

type Row = {
  hash: string;
  first_seen: number; last_seen: number;
  times_queried: number;
  source: string | null;
};

export default function Infohashes() {
  const [rows, setRows] = useState<Row[]>([]);
  const [filter, setFilter] = useState("");
  const paused = usePaused();
  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  useEffect(() => {
    fetch("/api/infohashes?limit=500").then(r => r.json()).then(setRows).catch(() => {});
    return stream.subscribe((topic, data) => {
      if (topic !== "infohashes" || pausedRef.current) return;
      // incoming event is { ip,port,target,source,ts }; shoehorn into Row shape
      const d: any = data;
      const newRow: Row = {
        hash: d.target,
        first_seen: d.ts, last_seen: d.ts,
        times_queried: 1,
        source: d.source ?? null,
      };
      setRows(prev => {
        const idx = prev.findIndex(r => r.hash === newRow.hash);
        if (idx >= 0) {
          const copy = prev.slice();
          copy[idx] = { ...copy[idx], last_seen: newRow.last_seen,
                         times_queried: copy[idx].times_queried + 1 };
          return copy;
        }
        return [newRow, ...prev].slice(0, 1000);
      });
    });
  }, []);

  const f = filter.toLowerCase();
  const filtered = f
    ? rows.filter(r => (r.hash + " " + (r.source || "")).toLowerCase().includes(f))
    : rows;

  return (
    <>
      <div className="filter">
        <input placeholder="filter by hash / source…"
               value={filter} onChange={e => setFilter(e.target.value)} />
        <span className="small" style={{ marginLeft: 10 }}>{filtered.length} rows</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>hash</th>
            <th>source</th>
            <th>times</th>
            <th>first</th>
            <th>last</th>
          </tr>
        </thead>
        <tbody>
          {filtered.slice(0, 500).map(r => (
            <tr key={r.hash}>
              <td className="hex" style={{ maxWidth: "none" }}>{r.hash}</td>
              <td>{r.source || <span className="dim">—</span>}</td>
              <td>{r.times_queried}</td>
              <td>{fmtTs(r.first_seen)}</td>
              <td>{fmtTs(r.last_seen)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
