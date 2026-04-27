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

const ALL_CLASSES: CrawlerClass[] = ["ok", "crawler", "monitor", "honeypot"];
const PAGE_SIZES = [50, 100, 250, 500, 1000];

export default function Peers() {
  const [rows, setRows] = useState<Row[]>([]);
  const [total, setTotal] = useState<number | null>(null);
  const [filter, setFilter] = useState("");
  const [bep51Only, setBep51Only] = useState(false);
  const [pageSize, setPageSize] = useState<number>(100);
  const [classFilter, setClassFilter] = useState<Set<CrawlerClass>>(
    new Set(ALL_CLASSES),
  );
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

  // Class filter: only rows whose tag is in the selected set.
  const peerCls = (r: Row): CrawlerClass =>
    (r.crawler_class ?? (r.likely_crawler ? "crawler" : "ok")) as CrawlerClass;
  let filtered: Row[] = classFilter.size < ALL_CLASSES.length
    ? rows.filter(r => classFilter.has(peerCls(r)))
    : rows;

  const f = filter.toLowerCase();
  if (f) {
    filtered = filtered.filter(r => {
      // Search text now also covers the classifier tag and any crawler
      // signal names ("port_farm_strong", "silent_taker", …) so users
      // can type "honeypot", "monitor", "port_farm", etc.
      const s = [
        r.ip, r.geo?.country, r.geo?.city, r.geo?.asn_org,
        countryName(r.geo?.country),
        decodeVString(r.v_string),
        peerCls(r),
        ...(r.crawler_signals ?? []),
      ].filter(Boolean).join(" ").toLowerCase();
      return s.includes(f);
    });
  }
  if (bep51Only) filtered = filtered.filter(r => r.supports_bep51 === 1);

  // Cap rendered rows at pageSize. The full filtered set is what we
  // count for "X shown / Y matched / Z total"; only the first pageSize
  // are turned into <tr> elements. Keeping the DOM small is the
  // single biggest factor in keeping CrawlerBadge tooltips snappy
  // across live re-renders.
  const matchedCount = filtered.length;
  const visibleRows = filtered.slice(0, pageSize);

  const bep51Count = rows.filter(r => r.supports_bep51 === 1).length;

  const anyGeo = rows.some(r => r.geo?.country);

  const toggleClass = (c: CrawlerClass) => {
    setClassFilter(prev => {
      const next = new Set(prev);
      if (next.has(c)) next.delete(c); else next.add(c);
      // Don't allow zero classes — fall back to all.
      if (next.size === 0) return new Set(ALL_CLASSES);
      return next;
    });
  };
  const allClasses = classFilter.size === ALL_CLASSES.length;

  return (
    <>
      <div className="filter" style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 10 }}>
        <input placeholder="filter by ip / country / client / tag / signal…"
               value={filter} onChange={e => setFilter(e.target.value)}
               style={{ flex: "1 1 260px" }} />

        <label style={{ fontSize: 11, color: "#a0a8b0" }}>
          show
          <select
            value={pageSize}
            onChange={e => setPageSize(Number(e.target.value))}
            style={{
              marginLeft: 4, marginRight: 4,
              background: "#0f1316", color: "#d8dee6",
              border: "1px solid #232a31", padding: "3px 6px",
              fontFamily: "inherit", fontSize: 11,
            }}
          >
            {PAGE_SIZES.map(n => <option key={n} value={n}>{n}</option>)}
          </select>
          rows
        </label>

        <span style={{ display: "inline-flex", gap: 4, fontSize: 11 }}>
          {ALL_CLASSES.map(c => {
            const active = classFilter.has(c);
            const lonely = active && classFilter.size === 1;
            return (
              <button
                key={c}
                onClick={() => toggleClass(c)}
                title={lonely
                  ? `clearing the last class chip resets to all`
                  : `toggle ${c}`}
                style={{
                  background: active && !allClasses ? "#1f2a36" : "#14181d",
                  color: active ? "#8fc0ff" : "#556066",
                  border: `1px solid ${active && !allClasses ? "#8fc0ff" : "#232a31"}`,
                  padding: "2px 8px", borderRadius: 2, cursor: "pointer",
                  font: "inherit", fontSize: 11,
                }}
              >
                {c}
              </button>
            );
          })}
        </span>

        <label style={{ fontSize: 11, color: "#a0a8b0" }}>
          <input type="checkbox" checked={bep51Only}
                 onChange={e => setBep51Only(e.target.checked)}
                 style={{ marginRight: 4 }} />
          BEP 51 only ({bep51Count})
        </label>

        <span className="small" style={{ marginLeft: "auto" }}>
          showing <b style={{ color: "#8fc0ff" }}>{visibleRows.length}</b>
          {" "}of {matchedCount.toLocaleString()} matched
          {" / "}
          <b style={{ color: "#8fc0ff" }}>
            {total != null ? total.toLocaleString() : rows.length}
          </b> unique peers
        </span>

        {!anyGeo && total != null && (
          <span className="small" style={{ width: "100%", color: "#a87a3a" }}>
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
          {visibleRows.map(r => {
            const iso  = r.geo?.country;
            const flag = countryFlag(iso);
            const name = countryName(iso);
            const cls  = peerCls(r);
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
