import { useEffect, useRef, useState } from "react";
import { stream, decodeVString, hex, fmtTs, countryFlag, countryName } from "../ws";
import { usePaused } from "../components/HoverPause";
import { CrawlerBadge, CrawlerClass } from "../components/CrawlerBadge";

type Geo = { country?: string; city?: string; asn?: number; asn_org?: string };
type Row = {
  ip: string; port: number;
  node_id: string | null;
  v_string: string | null;
  ro: number | null;
  first_seen: number; last_seen: number;
  rtt_ms: number | null;
  queries_in: number; queries_out: number;
  as_src?: number;
  as_dst?: number;
  same_ip?: number;
  likely_crawler?: number;
  crawler_class?: CrawlerClass;
  crawler_score?: number;
  crawler_signals?: string[];
  crawler_reason?: string;
  supports_bep51?: number | null;
  geo?: Geo;
};

type SourceBucket = { source: string; count: number };

type ClientBucket  = { v_string: string | null; count: number };
type CountryBucket = { iso: string; count: number };

export default function Peers() {
  const [rows, setRows] = useState<Row[]>([]);
  const [total, setTotal] = useState<number | null>(null);
  const [filter, setFilter] = useState("");
  const [bep51Only, setBep51Only] = useState(false);
  const [clients,   setClients]   = useState<ClientBucket[] | null>(null);
  const [countries, setCountries] = useState<CountryBucket[] | null>(null);
  const [sources,   setSources]   = useState<SourceBucket[] | null>(null);
  const [sourcesTotal, setSourcesTotal] = useState<number | null>(null);
  const [countryKnown,   setCountryKnown]   = useState<number | null>(null);
  const [clientKnown,    setClientKnown]    = useState<number | null>(null);
  const paused = usePaused();
  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  useEffect(() => {
    // Apply the pause check both BEFORE firing the fetch (to skip the
    // tick entirely) AND inside each .then() (to honor a pause that
    // started while a fetch was already in flight). Without the second
    // check, hovering a CrawlerBadge tooltip blinks out as soon as the
    // already-in-flight fetch returns and re-renders the table — the
    // tooltip's `open` state survives but its DOM ref points at a new
    // <tr>, and the rapid re-render race closes the portal.
    const guarded = (set: (v: any) => void) => (v: any) => {
      if (pausedRef.current) return;
      set(v);
    };
    const refresh = () => {
      if (pausedRef.current) return;
      fetch("/api/peers?limit=500").then(r => r.json())
        .then(guarded(setRows)).catch(() => {});
      fetch("/api/stats").then(r => r.json())
        .then(guarded((s: any) => setTotal(s.peers))).catch(() => {});
      fetch("/api/client-stats?limit=12").then(r => r.json())
        .then(guarded((s: any) => {
          setClients(s.clients ?? []);
          setClientKnown(s.known ?? null);
        })).catch(() => {});
      fetch("/api/country-stats?limit=15").then(r => r.json())
        .then(guarded((s: any) => {
          setCountries(s.countries ?? []);
          setCountryKnown(s.known ?? null);
        })).catch(() => {});
      fetch("/api/infohash-sources").then(r => r.json())
        .then(guarded((s: any) => {
          setSources(s.sources ?? []);
          setSourcesTotal(s.total ?? null);
        })).catch(() => {});
    };
    refresh();
    const id = setInterval(refresh, 5000);
    const unsub = stream.subscribe((topic, data) => {
      if (pausedRef.current) return;
      if (topic === "stats" && data?.peers != null) setTotal(data.peers);
    });
    return () => { clearInterval(id); unsub(); };
  }, []);

  const f = filter.toLowerCase();
  let filtered = f
    ? rows.filter(r => {
        const s = [
          r.ip, r.geo?.country, r.geo?.city, r.geo?.asn_org,
          countryName(r.geo?.country),
          decodeVString(r.v_string),
        ].filter(Boolean).join(" ").toLowerCase();
        return s.includes(f);
      })
    : rows;
  if (bep51Only) filtered = filtered.filter(r => r.supports_bep51 === 1);

  const bep51Count = rows.filter(r => r.supports_bep51 === 1).length;

  const anyGeo = rows.some(r => r.geo?.country);

  return (
    <>
      <div className="filter">
        <input placeholder="filter by ip / country / client…"
               value={filter} onChange={e => setFilter(e.target.value)} />
        <label style={{ marginLeft: 12, fontSize: 11, color: "#a0a8b0" }}>
          <input type="checkbox" checked={bep51Only}
                 onChange={e => setBep51Only(e.target.checked)}
                 style={{ marginRight: 4 }} />
          BEP 51 only ({bep51Count})
        </label>
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

      {sources && sources.length > 0 && (
        <div className="panels" style={{ gridTemplateColumns: "1fr" }}>
          <section className="panel">
            <h3>infohashes by source <span className="small">
              {sourcesTotal != null ? `(${sourcesTotal} total)` : ""}
            </span></h3>
            <ul className="bars">
              {sources.map((c) => {
                const max = sources[0].count;
                const pct = Math.round((c.count / max) * 100);
                const label = (
                  c.source === "bep51"     ? "BEP 51 sample_infohashes" :
                  c.source === "get_peers" ? "get_peers (asked about)" :
                  c.source === "announce"  ? "announce_peer" :
                  c.source === "find_node" ? "find_node target" :
                  c.source === "bep44"     ? "BEP 44 put" :
                  c.source === "query"     ? "BEP 44 get"    : c.source
                );
                return (
                  <li key={c.source}>
                    <span className="bar" style={{ width: pct + "%" }} />
                    <span className="lbl">{label}</span>
                    <span className="n">{c.count}</span>
                  </li>
                );
              })}
            </ul>
          </section>
        </div>
      )}

      <table>
        <thead>
          <tr>
            <th>ip:port</th>
            <th>country</th>
            <th>asn</th>
            <th>client</th>
            <th title="BEP 51 sample_infohashes capable">BEP 51</th>
            <th>rtt</th>
            <th>in / out</th>
            <th>edges s/d</th>
            <th>node id</th>
            <th>last seen</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map(r => {
            const iso  = r.geo?.country;
            const flag = countryFlag(iso);
            const name = countryName(iso);
            const cls  = (r.crawler_class ?? (r.likely_crawler ? "crawler" : "ok")) as CrawlerClass;
            return (
              <tr key={r.ip + ":" + r.port}>
                <td>
                  {r.ip}:{r.port}
                  {cls !== "ok" && (
                    <CrawlerBadge cls={cls}
                                  score={r.crawler_score ?? 0}
                                  signals={r.crawler_signals ?? []}
                                  reason={r.crawler_reason ?? ""} />
                  )}
                </td>
                <td className="geo" title={name || undefined}>
                  {flag && <span style={{ marginRight: 6, fontSize: 15 }}>{flag}</span>}
                  {iso || ""}{r.geo?.city ? " · " + r.geo.city : ""}
                </td>
                <td className="asn">
                  {r.geo?.asn ? "AS" + r.geo.asn + " " : ""}
                  {r.geo?.asn_org || ""}
                </td>
                <td>{decodeVString(r.v_string) || <span className="dim">—</span>}</td>
                <td className={r.supports_bep51 === 1 ? "ok" : "dim"}
                    title={r.supports_bep51 === 1
                      ? "replied to sample_infohashes"
                      : "not yet confirmed"}>
                  {r.supports_bep51 === 1 ? "✓" : "?"}
                </td>
                <td className={r.rtt_ms == null ? "dim" : ""}>
                  {r.rtt_ms != null ? r.rtt_ms + "ms" : "—"}
                </td>
                <td>{r.queries_in} / {r.queries_out}</td>
                <td className={r.as_dst === 0 && (r.as_src ?? 0) > 0 ? "bad" : "dim"}>
                  {r.as_src ?? 0} / {r.as_dst ?? 0}
                </td>
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
