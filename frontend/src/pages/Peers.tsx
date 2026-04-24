import { useEffect, useState } from "react";
import { stream, decodeVString, hex, fmtTs } from "../ws";

type Geo = { country?: string; city?: string; asn?: number; asn_org?: string };
type Row = {
  ip: string; port: number;
  node_id: string | null;
  v_string: string | null;
  ro: number | null;
  first_seen: number; last_seen: number;
  rtt_ms: number | null;
  queries_in: number; queries_out: number;
  geo?: Geo;
};

export default function Peers() {
  const [rows, setRows] = useState<Row[]>([]);
  const [filter, setFilter] = useState("");

  useEffect(() => {
    fetch("/api/peers?limit=500").then(r => r.json()).then(setRows).catch(() => {});
    // No dedicated "peers" event topic — reload every 5s while the tab is open.
    const id = setInterval(() => {
      fetch("/api/peers?limit=500").then(r => r.json()).then(setRows).catch(() => {});
    }, 5000);
    return () => clearInterval(id);
  }, []);

  const f = filter.toLowerCase();
  const filtered = f
    ? rows.filter(r => {
        const s = [
          r.ip, r.geo?.country, r.geo?.city, r.geo?.asn_org,
          decodeVString(r.v_string),
        ].filter(Boolean).join(" ").toLowerCase();
        return s.includes(f);
      })
    : rows;

  return (
    <>
      <div className="filter">
        <input placeholder="filter by ip / country / client…"
               value={filter} onChange={e => setFilter(e.target.value)} />
        <span className="small" style={{ marginLeft: 10 }}>
          {filtered.length} / {rows.length} rows
        </span>
      </div>
      <table>
        <thead>
          <tr>
            <th>ip:port</th>
            <th>country</th>
            <th>asn</th>
            <th>client</th>
            <th>rtt</th>
            <th>in / out</th>
            <th>node id</th>
            <th>last seen</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map(r => (
            <tr key={r.ip + ":" + r.port}>
              <td>{r.ip}:{r.port}</td>
              <td className="geo">{r.geo?.country || ""} {r.geo?.city || ""}</td>
              <td className="asn">{r.geo?.asn ? "AS" + r.geo.asn + " " : ""}{r.geo?.asn_org || ""}</td>
              <td>{decodeVString(r.v_string) || <span className="dim">—</span>}</td>
              <td className={r.rtt_ms == null ? "dim" : ""}>
                {r.rtt_ms != null ? r.rtt_ms + "ms" : "—"}
              </td>
              <td>{r.queries_in} / {r.queries_out}</td>
              <td className="hex">{hex(r.node_id || "", 20)}</td>
              <td>{fmtTs(r.last_seen)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
