import { useEffect, useMemo, useRef, useState } from "react";
import ForceGraph3D from "react-force-graph-3d";
import type { ForceGraph3DInstance } from "3d-force-graph";
import { countryFlag, countryName, decodeVString, hex } from "../ws";
import PeerSidePanel from "../components/PeerSidePanel";
import type { CrawlerClass } from "../components/CrawlerBadge";

/*
 * Bubble graph: nodes are peers, an edge A→B means A returned B in a
 * compact-nodes response (i.e. B is in A's routing table per A's own view).
 *
 * Three.js + WebGL force-directed layout via react-force-graph-3d. The
 * library handles the simulation (d3-force-3d), camera controls, and
 * raycast-based hover.
 */

export type Geo = {
  country?: string; city?: string;
  asn?: number; asn_org?: string;
  lat?: number; lon?: number;
};

export type Node = {
  id: string;
  ip: string;
  port: number;
  deg: number;
  v_string?: string | null;
  node_id?: string | null;
  country?: string | null;
  geo?: Geo;
  as_src?: number;
  as_dst?: number;
  same_ip?: number;
  first_seen?: number;
  last_seen?: number;
  queries_in?: number;
  queries_out?: number;
  rtt_ms?: number | null;
  ro?: number | null;
  bep42_ok?: number | null;
  supports_bep51?: number | null;
  likely_crawler?: number;
  crawler_class?: CrawlerClass;
  crawler_score?: number;
  crawler_signals?: string[];
  crawler_reason?: string;
  /* runtime fields written by force-graph */
  x?: number; y?: number; z?: number;
};

type Link = { source: string; target: string };

/* Deterministic string → CSS hsl color. Used for both ASN org and country. */
function hashHsl(s: string, sat = 62, light = 60): string {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < s.length; i++) {
    h = (h ^ s.charCodeAt(i)) >>> 0;
    h = Math.imul(h, 16777619) >>> 0;
  }
  return `hsl(${h % 360}, ${sat}%, ${light}%)`;
}

/* Color preference: ASN org > country > neutral grey. ASN groups hosting
 * clusters (Hetzner / OVH / Contabo) into one visible blob. */
function colorByAsn(node: Node): string {
  const org = node.geo?.asn_org;
  if (org && org.length > 0) return hashHsl(org);
  const iso = node.country;
  if (iso && iso.length === 2) return hashHsl(iso, 50, 55);
  return "hsl(210, 10%, 60%)";
}

/* Highest-bit-of-XOR-distance bucket index. node_id and ours are 40-hex
 * strings (20 bytes). Returns 0..159 (0 = identical-up-to-this-bit, 159 =
 * differ in topmost bit), or null if either id is missing/invalid. */
function kbucket(node_id: string | null | undefined, ours: string | null): number | null {
  if (!node_id || !ours) return null;
  if (node_id.length < 40 || ours.length < 40) return null;
  for (let i = 0; i < 20; i++) {
    const a = parseInt(node_id.substr(i * 2, 2), 16);
    const b = parseInt(ours.substr(i * 2, 2), 16);
    const x = a ^ b;
    if (x === 0) continue;
    /* Highest set bit position 7..0 within this byte. */
    let bit = 7;
    while (bit > 0 && (x & (1 << bit)) === 0) bit--;
    return 159 - (i * 8 + (7 - bit));
  }
  return 0;     /* identical */
}

/* Color by k-bucket index. 0 = closest (red end), 159 = farthest (cyan end). */
function colorByBucket(node: Node, ours: string | null): string {
  const b = kbucket(node.node_id, ours);
  if (b == null) return "hsl(210, 10%, 60%)";
  /* Spread the visible range over the buckets that actually populate. */
  const hue = ((159 - b) * 2.25) % 360;
  return `hsl(${hue.toFixed(0)}, 70%, 55%)`;
}

/* /24 (IPv4) or /48 (IPv6) network prefix — used for sybil-cluster
 * highlighting when a node is selected. */
function netPrefix(ip: string): string {
  if (ip.includes(":")) {
    /* /48 — first three hextet groups */
    const parts = ip.split(":");
    return parts.slice(0, 3).join(":");
  }
  const parts = ip.split(".");
  return parts.slice(0, 3).join(".");
}

/* (escHTML helper removed: tooltip now renders via JSX which auto-escapes.
 * Kept the import lightweight — peer-derived strings like v_string,
 * country, asn_org now flow through React's text-rendering path and
 * never touch innerHTML. See SPA security audit FIND-001/FIND-002.) */

export default function Graph() {
  const fgRef = useRef<ForceGraph3DInstance | undefined>(undefined);
  const wrapRef = useRef<HTMLDivElement>(null);
  const tipRef = useRef<HTMLDivElement>(null);

  const [limit, setLimit] = useState(100);
  const [fetching, setFetching] = useState(false);
  const [settling, setSettling] = useState(false);
  const settleTimer = useRef<number | null>(null);
  const busy = fetching || settling;
  const [data, setData]   = useState<{ nodes: Node[]; links: Link[] }>({ nodes: [], links: [] });
  const [counts, setCounts] = useState<{ nodes: number; links: number } | null>(null);
  const [showLegend, setShowLegend] = useState(true);
  const [selected, setSelected] = useState<Node | null>(null);

  /* Filter + search state */
  type AliveFilter = "all" | "6h" | "24h" | "stale";
  type FamilyFilter = "all" | "v4" | "v6";
  const [aliveFilter,  setAliveFilter]  = useState<AliveFilter>("all");
  const [familyFilter, setFamilyFilter] = useState<FamilyFilter>("all");
  const ALL_CLASSES: CrawlerClass[] = ["ok", "seedbox", "crawler", "monitor", "honeypot"];
  const [classFilter, setClassFilter] = useState<Set<CrawlerClass>>(new Set(ALL_CLASSES));
  const [bep51Only,   setBep51Only]   = useState(false);
  const [search, setSearch]   = useState("");
  const [hilite, setHilite] = useState<Set<string>>(new Set());
  const [colorMode, setColorMode] = useState<"asn" | "kbucket">("asn");
  const [ourNodeId, setOurNodeId] = useState<string | null>(null);

  /* Fetch our daemon's node_id once; used by the k-bucket coloring mode. */
  useEffect(() => {
    fetch("/api/node-id").then(r => r.json())
      .then(j => setOurNodeId((j.node_id ?? "").toLowerCase() || null))
      .catch(() => {});
  }, []);

  /* Track viewport size so the graph re-fits the container. */
  const [size, setSize] = useState<{ w: number; h: number }>({ w: 800, h: 600 });

  /* Derive filtered/searched data. Also rebuild the link list to drop edges
   * whose endpoints fell out — otherwise force-graph crashes on dangling
   * source/target ids. */
  const displayed = useMemo(() => {
    const now = Date.now() / 1000;
    const wantClass = (n: Node) => classFilter.has((n.crawler_class ?? "ok") as CrawlerClass);
    const wantAlive = (n: Node) => {
      if (aliveFilter === "all") return true;
      const ls = n.last_seen ?? 0;
      const age = now - ls;
      if (aliveFilter === "6h")    return age <= 6 * 3600;
      if (aliveFilter === "24h")   return age <= 24 * 3600;
      /* stale */                   return age > 24 * 3600;
    };
    const wantFamily = (n: Node) => {
      if (familyFilter === "all") return true;
      const v6 = n.ip.includes(":");
      return familyFilter === "v6" ? v6 : !v6;
    };
    const wantBep51 = (n: Node) => !bep51Only || n.supports_bep51 === 1;

    const nodes = data.nodes.filter(n =>
      wantClass(n) && wantAlive(n) && wantFamily(n) && wantBep51(n));
    const ids = new Set(nodes.map(n => n.id));
    const links = data.links.filter(l => {
      const s = typeof l.source === "string" ? l.source : (l.source as any).id;
      const t = typeof l.target === "string" ? l.target : (l.target as any).id;
      return ids.has(s) && ids.has(t);
    });
    return { nodes, links };
  }, [data, aliveFilter, familyFilter, classFilter, bep51Only]);

  /* Sybil cluster: when a node is selected, highlight others sharing its
   * /24 (or /48 for v6) AND/OR its ASN. Two indicators of the same hosting
   * presence — clusters jump out instantly when you click a candidate. */
  const siblings = useMemo(() => {
    if (!selected) return new Set<string>();
    const net  = netPrefix(selected.ip);
    const asn  = selected.geo?.asn;
    const out  = new Set<string>();
    for (const n of displayed.nodes) {
      if (n.id === selected.id) continue;
      const sameNet = netPrefix(n.ip) === net;
      const sameAsn = asn != null && n.geo?.asn === asn;
      if (sameNet || sameAsn) out.add(n.id);
    }
    return out;
  }, [selected, displayed.nodes]);

  const clearSettleTimer = () => {
    if (settleTimer.current != null) {
      window.clearTimeout(settleTimer.current);
      settleTimer.current = null;
    }
  };

  const load = async () => {
    clearSettleTimer();
    setFetching(true);
    setSettling(true);              /* assume there will be a settle phase */
    try {
      const r = await fetch(`/api/graph?limit=${limit}`);
      const g = await r.json();
      const nodes: Node[] = (g.nodes ?? []);
      // Daemon shipped both shapes historically: legacy {src,dst}
      // (still in older deployments) and current {source,target}
      // (post-redaction-fix). Accept either; drop dangling/self-loops.
      const links: Link[] = (g.links ?? [])
        .map((e: any) => ({
          source: e.source ?? e.src,
          target: e.target ?? e.dst,
        }))
        .filter((e: Link) =>
          e.source && e.target && e.source !== e.target);
      setData({ nodes, links });
      setCounts({ nodes: nodes.length, links: links.length });
      if (nodes.length === 0) setSettling(false);
      else {
        /* Safety net — onEngineStop is the canonical signal but force-graph
         * occasionally swallows it on rapid reloads. Drop the overlay after
         * 30s no matter what so the page never appears stuck. */
        settleTimer.current = window.setTimeout(() => setSettling(false), 30000);
      }
    } catch (e) {
      setSettling(false);
    }
    setFetching(false);
  };

  useEffect(() => { load(); /* eslint-disable-next-line */ }, [limit]);

  /* Track the wrapper size for the 3D canvas. */
  useEffect(() => {
    const refresh = () => {
      const r = wrapRef.current?.getBoundingClientRect();
      if (r) setSize({ w: r.width, h: r.height });
    };
    refresh();
    window.addEventListener("resize", refresh);
    return () => window.removeEventListener("resize", refresh);
  }, []);

  /* Hover state. The tooltip CONTENT renders via JSX (auto-escaped) so
   * peer-controlled fields (v_string, country, asn_org) can never become
   * an XSS vector even if a malicious DHT peer announces hostile bytes.
   * Position is updated imperatively via ref + a mousemove listener —
   * mutating left/top doesn't go through React, so the (heavy) graph
   * never re-renders on cursor moves. */
  const [hovered, setHovered] = useState<Node | null>(null);
  const onNodeHover = (node: Node | null) => setHovered(node);

  /* Track cursor for tooltip placement. */
  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      const tip = tipRef.current;
      if (!tip || tip.style.display === "none") return;
      tip.style.left = (e.clientX + 12) + "px";
      tip.style.top  = (e.clientY + 12) + "px";
    };
    window.addEventListener("mousemove", onMove);
    return () => window.removeEventListener("mousemove", onMove);
  }, []);

  /* Esc closes the side panel. */
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setSelected(null);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  /* Search → flash matching nodes + fly camera to first match. */
  const runSearch = () => {
    const q = search.trim().toLowerCase();
    if (!q) { setHilite(new Set()); return; }
    const matches = displayed.nodes.filter(n => {
      if (n.ip.toLowerCase().includes(q)) return true;
      if (n.id.toLowerCase().includes(q)) return true;
      if (n.node_id && n.node_id.toLowerCase().startsWith(q)) return true;
      const v = n.v_string ? decodeVString(n.v_string).toLowerCase() : "";
      if (v.includes(q)) return true;
      const org = (n.geo?.asn_org ?? "").toLowerCase();
      if (org.includes(q)) return true;
      return false;
    });
    setHilite(new Set(matches.map(m => m.id)));
    const first: any = matches[0];
    if (first && fgRef.current && first.x != null) {
      const dist = 80;
      const r = Math.hypot(first.x, first.y, first.z) || 1;
      const k = (r + dist) / r;
      fgRef.current.cameraPosition(
        { x: first.x * k, y: first.y * k, z: first.z * k },
        first, 1500);
    }
  };

  /* Edge fade by camera zoom: at large node counts, only show the link if
   * either endpoint is near the camera. Cheap; runs per frame per link. */
  const linkVisibility = (l: any): boolean => {
    if (displayed.nodes.length <= 1500) return true;
    const cam: any = (fgRef.current as any)?.camera?.();
    if (!cam) return true;
    const a = l.source, b = l.target;
    if (!a || a.x == null) return true;
    const da = Math.hypot(a.x - cam.position.x, a.y - cam.position.y, a.z - cam.position.z);
    if (da < 700) return true;
    if (b && b.x != null) {
      const db = Math.hypot(b.x - cam.position.x, b.y - cam.position.y, b.z - cam.position.z);
      if (db < 700) return true;
    }
    return false;
  };

  const Chip = ({ active, onClick, children, color }:
    { active: boolean; onClick: () => void; children: React.ReactNode; color?: string }) => (
    <button onClick={onClick}
            style={{
              padding: "2px 9px", fontSize: 11, marginRight: 4,
              borderRadius: 11, cursor: "pointer",
              background: active ? (color ?? "#1f2a36") : "#14181d",
              border: `1px solid ${active ? (color ?? "#8fc0ff") : "#232a31"}`,
              color: active ? "#fff" : "#8892a0",
            }}>{children}</button>
  );

  const toggleClass = (c: CrawlerClass) => {
    setClassFilter(prev => {
      const next = new Set(prev);
      if (next.has(c)) next.delete(c); else next.add(c);
      return next;
    });
  };

  return (
    <>
      <div className="filter" style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 6 }}>
        <label>
          nodes:{" "}
          <select value={limit} onChange={e => setLimit(parseInt(e.target.value))}>
            <option value={100}>100</option>
            <option value={500}>500</option>
            <option value={1000}>1,000</option>
            <option value={2500}>2,500</option>
            <option value={5000}>5,000</option>
            <option value={10000}>10,000</option>
          </select>
        </label>
        <button style={{ marginLeft: 6 }} onClick={load} disabled={busy}>
          {busy ? "loading…" : "reload"}
        </button>
        <button onClick={() => fgRef.current?.zoomToFit(800)}>fit</button>
        <input
          placeholder="search ip / asn / node-id / client…"
          value={search}
          onChange={e => setSearch(e.target.value)}
          onKeyDown={e => { if (e.key === "Enter") runSearch(); }}
          style={{ background: "#0f1316", color: "#d8dee6",
                   border: "1px solid #232a31", padding: "3px 8px",
                   borderRadius: 2, width: 220, marginLeft: 8 }}
        />
        <button onClick={runSearch}>find</button>
        {hilite.size > 0 && (
          <button onClick={() => { setHilite(new Set()); setSearch(""); }}>clear</button>
        )}
        <span style={{ marginLeft: 12, fontSize: 10, color: "#8892a0" }}>alive:</span>
        {(["all","6h","24h","stale"] as const).map(a => (
          <Chip key={a} active={aliveFilter === a} onClick={() => setAliveFilter(a)}>
            {a}
          </Chip>
        ))}
        <span style={{ marginLeft: 6, fontSize: 10, color: "#8892a0" }}>family:</span>
        {(["all","v4","v6"] as const).map(f => (
          <Chip key={f} active={familyFilter === f} onClick={() => setFamilyFilter(f)}>
            {f}
          </Chip>
        ))}
        <span style={{ marginLeft: 6, fontSize: 10, color: "#8892a0" }}>class:</span>
        <Chip active={classFilter.has("ok")} color="#3a4a3a" onClick={() => toggleClass("ok")}>ok</Chip>
        <Chip active={classFilter.has("crawler")}  color="#8a3e54" onClick={() => toggleClass("crawler")}>crawler</Chip>
        <Chip active={classFilter.has("monitor")}  color="#8a6a2e" onClick={() => toggleClass("monitor")}>monitor</Chip>
        <Chip active={classFilter.has("honeypot")} color="#8a2e2e" onClick={() => toggleClass("honeypot")}>honeypot</Chip>
        <Chip active={bep51Only} onClick={() => setBep51Only(b => !b)}>BEP 51 only</Chip>
        <span style={{ marginLeft: 6, fontSize: 10, color: "#8892a0" }}>color:</span>
        <Chip active={colorMode === "asn"}
              onClick={() => setColorMode("asn")}>ASN</Chip>
        <Chip active={colorMode === "kbucket"}
              onClick={() => setColorMode("kbucket")}
              color={ourNodeId ? "#3a4a6a" : "#3a3a3a"}>
          k-bucket{!ourNodeId && " (no id)"}
        </Chip>
        <span className="small" style={{ marginLeft: 8 }}>
          {counts
            ? `${displayed.nodes.length.toLocaleString()} / ${counts.nodes.toLocaleString()} nodes · ${displayed.links.length.toLocaleString()} / ${counts.links.toLocaleString()} edges`
            : ""}
        </span>
      </div>

      <div ref={wrapRef}
           style={{ position: "relative", width: "100%",
                    height: "calc(100vh - 170px)",
                    background: "#0a0c0f", border: "1px solid #232a31",
                    borderRadius: 3, overflow: "hidden" }}>
        <ForceGraph3D
          ref={fgRef as any}
          width={size.w}
          height={size.h}
          backgroundColor="#0a0c0f"
          graphData={displayed}
          nodeId="id"
          nodeVal={(n: any) => Math.max(1, Math.sqrt(n.deg || 1) * 1.4)}
          nodeColor={(n: any) => {
            if (n.id === selected?.id) return "#ffffff";
            if (hilite.has(n.id))      return "#ffeb3b";
            if (siblings.has(n.id))    return "#ff7ad9";
            return colorMode === "kbucket"
              ? colorByBucket(n, ourNodeId)
              : colorByAsn(n);
          }}
          nodeOpacity={0.95}
          nodeResolution={8}        /* sphere segments — lower = faster */
          linkColor={() => "rgba(160,195,235,0.6)"}
          linkOpacity={0.55}
          linkWidth={1.2}
          linkVisibility={linkVisibility as any}
          enableNodeDrag={false}    /* dragging triggers extra simulation */
          showNavInfo={false}
          warmupTicks={50}
          cooldownTicks={200}        /* stop simulation after N ticks */
          onNodeHover={onNodeHover as any}
          onNodeClick={(n: any) => setSelected(n as Node)}
          onEngineStop={() => { clearSettleTimer(); setSettling(false); }}
        />

        {busy && (
          <div style={{
            position: "absolute", inset: 0,
            display: "flex", alignItems: "center", justifyContent: "center",
            background: "rgba(10,12,15,0.65)",
            backdropFilter: "blur(2px)",
            zIndex: 20, pointerEvents: "none",
          }}>
            <div style={{
              background: "#14181d", border: "1px solid #2a3642",
              borderRadius: 4, padding: "14px 22px",
              boxShadow: "0 6px 24px rgba(0,0,0,0.55)",
              display: "flex", alignItems: "center", gap: 14,
              color: "#d8dee6", fontSize: 13,
            }}>
              <span className="graph-spinner" />
              {fetching
                ? "loading graph…"
                : `rendering ${(counts?.nodes ?? 0).toLocaleString()} nodes · ${(counts?.links ?? 0).toLocaleString()} edges…`}
            </div>
          </div>
        )}

        {/* Hover tooltip — content rendered via JSX so React auto-escapes
         * every peer-derived string. Position is updated by the ref-based
         * mousemove listener above, not by React state, so the cursor stays
         * smooth even when sweeping over many nodes. */}
        <div
          ref={tipRef}
          style={{
            position: "fixed", display: hovered ? "block" : "none", left: 0, top: 0,
            background: "#14181d", border: "1px solid #2a3642", borderRadius: 3,
            padding: "6px 10px", pointerEvents: "none", maxWidth: 320,
            fontSize: 12, color: "#d8dee6",
            boxShadow: "0 4px 14px rgba(0,0,0,0.5)", zIndex: 10
          }}
        >
          {hovered && (() => {
            const cn      = hovered.country ? countryName(hovered.country) : "";
            const flag    = hovered.country ? countryFlag(hovered.country) : "";
            const cliText = hovered.v_string ? decodeVString(hovered.v_string) : "";
            const silent  = hovered.as_dst === 0 && (hovered.as_src ?? 0) >= 50;
            const multiPort = (hovered.same_ip ?? 0) >= 3;
            return (
              <>
                <div style={{ color: "#8fc0ff" }}>
                  {hovered.ip}:{hovered.port}
                </div>
                <div>
                  {flag && (
                    <span style={{ marginRight: 6 }} title={cn}>
                      {flag} {hovered.country}
                    </span>
                  )}
                  {cliText
                    ? <span style={{ color: "#ddd" }}>{cliText}</span>
                    : <span style={{ color: "#556066" }}>unknown client</span>}
                </div>
                <div style={{ color: "#556066", fontSize: 11 }}>
                  degree {hovered.deg}
                  {hovered.as_src != null && hovered.as_dst != null
                    && ` · s:${hovered.as_src} d:${hovered.as_dst}`}
                  {(hovered.same_ip ?? 0) >= 2 && ` · ${hovered.same_ip} ports/ip`}
                </div>
                {hovered.likely_crawler ? (
                  <div style={{ color: "#ff9bb5", marginTop: 3 }}>
                    likely crawler
                    {silent && " — silent taker"}
                    {multiPort && " — multi-port host"}
                  </div>
                ) : null}
                {hovered.supports_bep51 === 1 && (
                  <div style={{ color: "#6edd8a", marginTop: 3 }}>✓ BEP 51 capable</div>
                )}
                <div style={{ color: "#556066", fontSize: 11 }}>{hex(hovered.id, 28)}</div>
              </>
            );
          })()}
        </div>

        {/* Collapsible legend */}
        <div style={{
          position: "absolute", top: 10, right: 10,
          background: "rgba(20,24,29,0.94)", border: "1px solid #2a3642",
          borderRadius: 3, padding: showLegend ? "8px 12px" : "4px 10px",
          fontSize: 11, color: "#d8dee6", maxWidth: 260, lineHeight: 1.45,
          boxShadow: "0 4px 14px rgba(0,0,0,0.4)", zIndex: 5
        }}>
          <div onClick={() => setShowLegend(s => !s)}
               style={{ display: "flex", alignItems: "center",
                        justifyContent: "space-between", gap: 10,
                        cursor: "pointer", color: "#8fc0ff",
                        textTransform: "uppercase", letterSpacing: 0.5, fontSize: 10 }}>
            <span>legend (3d)</span>
            <span style={{ color: "#8892a0" }}>{showLegend ? "−" : "+"}</span>
          </div>
          {showLegend && (
            <div style={{ marginTop: 8 }}>
              <div style={{ color: "#a0a8b0", marginBottom: 8 }}>
                <b style={{ color: "#8fc0ff" }}>sphere size</b>
                <br/>= sqrt(degree). Bigger = more connected.
              </div>
              <div style={{ color: "#a0a8b0", marginBottom: 8 }}>
                <b style={{ color: "#8fc0ff" }}>color</b>
                <br/>ASN mode: hosting cluster (Hetzner / OVH /
                Constant Co. each one color).
                <br/>k-bucket mode: XOR distance from our node id —
                close peers same color (rare), most cluster in the
                far buckets.
              </div>
              <div style={{ color: "#a0a8b0", marginBottom: 8 }}>
                <b style={{ color: "#ffffff" }}>white</b>
                <br/>= currently selected node.
              </div>
              <div style={{ color: "#a0a8b0", marginBottom: 8 }}>
                <b style={{ color: "#ff7ad9" }}>pink</b>
                <br/>= shares /24 or ASN with selected (sybil cluster).
              </div>
              <div style={{ color: "#a0a8b0", marginBottom: 8 }}>
                <b style={{ color: "#ffeb3b" }}>yellow</b>
                <br/>= search match (find).
              </div>
              <div style={{ color: "#a0a8b0", marginBottom: 8 }}>
                <b style={{ color: "#8fc0ff" }}>click a node</b>
                <br/>= open detail panel + cluster highlight
                (Esc closes).
              </div>
              <div style={{ color: "#a0a8b0", marginBottom: 8 }}>
                <b style={{ color: "#8fc0ff" }}>line</b>
                <br/>one peer returned the other in a find_node
                reply (direction not drawn).
              </div>
              <div style={{ color: "#8fc0ff", fontSize: 10, letterSpacing: 0.5,
                             marginTop: 8, textTransform: "uppercase" }}>controls</div>
              <div style={{ color: "#a0a8b0" }}>
                left-drag = orbit · right-drag = pan · scroll = zoom · fit = reset
              </div>
              <div style={{ color: "#8892a0", marginTop: 8, fontSize: 10,
                             borderTop: "1px solid #232a31", paddingTop: 6 }}>
                Powered by Three.js + d3-force-3d via react-force-graph-3d.
              </div>
            </div>
          )}
        </div>
      </div>

      {selected && <PeerSidePanel node={selected} onClose={() => setSelected(null)} />}
    </>
  );
}
