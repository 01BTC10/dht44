import { useEffect, useState } from "react";
import { stream, decodeVString, hex, fmtTs, countryFlag, countryName } from "../ws";

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

type ClientBucket  = { v_string: string | null; count: number };
type CountryBucket = { iso: string; count: number };

export default function Peers() {
  const [rows, setRows] = useState<Row[]>([]);
  const [total, setTotal] = useState<number | null>(null);
  const [filter, setFilter] = useState("");
  const [clients,   setClients]   = useState<ClientBucket[] | null>(null);
  const [countries, setCountries] = useState<CountryBucket[] | null>(null);
  const [countryKnown,   setCountryKnown]   = useState<number | null>(null);
  const [clientKnown,    setClientKnown]    = useState<number | null>(null);

  useEffect(() => {
    const refresh = () => {
      fetch("/api/peers?limit=500").then(r => r.json()).then(setRows).catch(() => {});
      fetch("/api/stats").then(r => r.json()).then(s => setTotal(s.peers)).catch(() => {});
      fetch("/api/client-stats?limit=12").then(r => r.json()).then((s: any) => {
        setClients(s.clients ?? []);
        setClientKnown(s.known ?? null);
      }).catch(() => {});
      fetch("/api/country-stats?limit=15").then(r => r.json()).then((s: any) => {
        setCountries(s.countries ?? []);
        setCountryKnown(s.known ?? null);
      }).catch(() => {});
    };
    refresh();
    const id = setInterval(refresh, 5000);
    const unsub = stream.subscribe((topic, data) => {
      if (topic === "stats" && data?.peers != null) setTotal(data.peers);
    });
    return () => { clearInterval(id); unsub(); };
  }, []);

  const f = filter.toLowerCase();
  const filtered = f
    ? rows.filter(r => {
        const s = [
          r.ip, r.geo?.country, r.geo?.city, r.geo?.asn_org,
          countryName(r.geo?.country),
          decodeVString(r.v_string),
        ].filter(Boolean).join(" ").toLowerCase();
        return s.includes(f);
      })
    : rows;

  const anyGeo = rows.some(r => r.geo?.country);

  return (
    <>
      <div className="filter">
        <input placeholder="filter by ip / country / client…"
               value={filter} onChange={e => setFilter(e.target.value)} />
        <span className="small" style={{ marginLeft: 10 }}>
          {filtered.length} shown / <b style={{ color: "#8fc0ff" }}>
            {total != null ? total.toLocaleString() : rows.length}
          </b> unique peers seen
        </span>
        {!anyGeo && total != null && (
          <span className="small" style={{ marginLeft: 14, color: "#a87a3a" }}>
            no GeoIP db loaded — flags will appear once --geoip-city is set
          </span>
        )}
      </div>

      <div className="panels">
        <section className="panel">
          <h3>top clients <span className="small">
            {clientKnown != null && total != null
              ? `(${clientKnown}/${total} identified)` : ""}
          </span></h3>
          {clients && clients.length > 0 ? (
            <ul className="bars">
              {clients.map((c) => {
                const name = decodeVString(c.v_string) || c.v_string || "—";
                const max  = clients[0].count;
                const pct  = Math.round((c.count / max) * 100);
                return (
                  <li key={c.v_string ?? "null"}>
                    <span className="bar" style={{ width: pct + "%" }} />
                    <span className="lbl">{name}</span>
                    <span className="n">{c.count}</span>
                  </li>
                );
              })}
            </ul>
          ) : <div className="small dim">waiting for data…</div>}
        </section>

        <section className="panel">
          <h3>top countries <span className="small">
            {countryKnown != null && total != null
              ? `(${countryKnown}/${total} located)` : ""}
          </span></h3>
          {countries && countries.length > 0 ? (
            <ul className="bars">
              {countries.map((c) => {
                const max = countries[0].count;
                const pct = Math.round((c.count / max) * 100);
                return (
                  <li key={c.iso} title={countryName(c.iso)}>
                    <span className="bar cc" style={{ width: pct + "%" }} />
                    <span className="lbl">
                      <span style={{ marginRight: 6 }}>{countryFlag(c.iso)}</span>
                      {countryName(c.iso)}
                    </span>
                    <span className="n">{c.count}</span>
                  </li>
                );
              })}
            </ul>
          ) : (
            <div className="small dim">
              {anyGeo === false
                ? "no GeoIP db loaded"
                : "waiting for data…"}
            </div>
          )}
        </section>
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
          {filtered.map(r => {
            const iso  = r.geo?.country;
            const flag = countryFlag(iso);
            const name = countryName(iso);
            return (
              <tr key={r.ip + ":" + r.port}>
                <td>{r.ip}:{r.port}</td>
                <td className="geo" title={name || undefined}>
                  {flag && <span style={{ marginRight: 6, fontSize: 15 }}>{flag}</span>}
                  {iso || ""}{r.geo?.city ? " · " + r.geo.city : ""}
                </td>
                <td className="asn">
                  {r.geo?.asn ? "AS" + r.geo.asn + " " : ""}
                  {r.geo?.asn_org || ""}
                </td>
                <td>{decodeVString(r.v_string) || <span className="dim">—</span>}</td>
                <td className={r.rtt_ms == null ? "dim" : ""}>
                  {r.rtt_ms != null ? r.rtt_ms + "ms" : "—"}
                </td>
                <td>{r.queries_in} / {r.queries_out}</td>
                <td className="hex">{hex(r.node_id || "", 20)}</td>
                <td>{fmtTs(r.last_seen)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </>
  );
}
