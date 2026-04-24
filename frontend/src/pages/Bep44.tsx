import { useEffect, useState } from "react";
import { stream, hex, fmtTs } from "../ws";

type Row = {
  target: string;
  mutable: number;
  pk: string | null;
  salt: string | null;
  seq: number;
  sig: string | null;
  v: string | null;
  first_seen: number; last_seen: number;
};

export default function Bep44() {
  const [rows, setRows] = useState<Row[]>([]);
  useEffect(() => {
    fetch("/api/bep44?limit=500").then(r => r.json()).then(setRows).catch(() => {});
    return stream.subscribe((topic, data) => {
      if (topic !== "bep44") return;
      const d: any = data;
      const r: Row = {
        target: d.target, mutable: d.mutable, pk: d.pk, salt: d.salt,
        seq: d.seq, sig: d.sig, v: d.v,
        first_seen: d.ts, last_seen: d.ts,
      };
      setRows(prev => {
        const idx = prev.findIndex(x => x.target === r.target);
        if (idx >= 0) { const c = prev.slice(); c[idx] = r; return c; }
        return [r, ...prev].slice(0, 500);
      });
    });
  }, []);

  return (
    <table>
      <thead>
        <tr>
          <th>target</th>
          <th>mut</th>
          <th>pk</th>
          <th>seq</th>
          <th>v</th>
          <th>last</th>
        </tr>
      </thead>
      <tbody>
        {rows.map(r => (
          <tr key={r.target}>
            <td className="hex">{hex(r.target, 24)}</td>
            <td>{r.mutable ? "✓" : ""}</td>
            <td className="hex">{hex(r.pk || "", 16)}</td>
            <td>{r.mutable ? r.seq : ""}</td>
            <td className="hex">{hex(r.v || "", 40)}</td>
            <td>{fmtTs(r.last_seen)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
