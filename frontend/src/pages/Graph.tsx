import { useEffect, useRef, useState } from "react";
import ForceGraph3D from "react-force-graph-3d";
import type { ForceGraph3DInstance } from "3d-force-graph";
import { countryFlag, countryName, decodeVString, hex } from "../ws";

/*
 * Bubble graph: nodes are peers, an edge A→B means A returned B in a
 * compact-nodes response (i.e. B is in A's routing table per A's own view).
 *
 * Three.js + WebGL force-directed layout via react-force-graph-3d. The
 * library handles the simulation (d3-force-3d), camera controls, and
 * raycast-based hover.
 */

type Node = {
  id: string;
  ip: string;
  port: number;
  deg: number;
  v_string?: string | null;
  country?: string | null;
  as_src?: number;
  as_dst?: number;
  same_ip?: number;
  likely_crawler?: number;
  supports_bep51?: number | null;
  /* runtime fields written by force-graph */
  x?: number; y?: number; z?: number;
};

type Link = { source: string; target: string };

/* Deterministic ISO → CSS hsl color string */
function colorFor(iso?: string | null): string {
  if (!iso || iso.length !== 2) return "hsl(210, 10%, 60%)";
  let hash = 0;
  for (let i = 0; i < iso.length; i++) hash = (hash * 31 + iso.charCodeAt(i)) >>> 0;
  return `hsl(${hash % 360}, 62%, 60%)`;
}

function escHTML(s: string | null | undefined): string {
  if (s == null) return "";
  return String(s).replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" } as any)[c]);
}

export default function Graph() {
  const fgRef = useRef<ForceGraph3DInstance | undefined>(undefined);
  const wrapRef = useRef<HTMLDivElement>(null);
  const tipRef = useRef<HTMLDivElement>(null);

  const [limit, setLimit] = useState(1000);
  const [loading, setLoading] = useState(false);
  const [data, setData]   = useState<{ nodes: Node[]; links: Link[] }>({ nodes: [], links: [] });
  const [counts, setCounts] = useState<{ nodes: number; links: number } | null>(null);
  const [showLegend, setShowLegend] = useState(true);

  /* Track viewport size so the graph re-fits the container. */
  const [size, setSize] = useState<{ w: number; h: number }>({ w: 800, h: 600 });

  const load = async () => {
    setLoading(true);
    try {
      const r = await fetch(`/api/graph?limit=${limit}`);
      const g = await r.json();
      const nodes: Node[] = (g.nodes ?? []);
      const links: Link[] = (g.links ?? [])
        .map((e: any) => ({ source: e.src, target: e.dst }))
        .filter((e: Link) => e.source !== e.target);
      setData({ nodes, links });
      setCounts({ nodes: nodes.length, links: links.length });
    } catch (e) { /* ignore */ }
    setLoading(false);
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

  /* Imperative hover tooltip — same trick as before. The library hands us
   * the node object on mouse-over; we update DOM directly so React doesn't
   * re-render the (heavy) graph wrapper. */
  const onNodeHover = (node: Node | null) => {
    const tip = tipRef.current;
    if (!tip) return;
    if (!node) { tip.style.display = "none"; return; }
    tip.style.display = "block";
    const flag = node.country ? countryFlag(node.country) : "";
    const cn   = node.country ? countryName(node.country) : "";
    const cli  = node.v_string ? decodeVString(node.v_string)
                               : `<span style="color:#556066">unknown client</span>`;
    let extras = `degree ${node.deg}`;
    if (node.as_src != null && node.as_dst != null)
      extras += ` · s:${node.as_src} d:${node.as_dst}`;
    if ((node.same_ip ?? 0) >= 2) extras += ` · ${node.same_ip} ports/ip`;
    let crawler = "";
    if (node.likely_crawler) {
      const why =
        (node.as_dst === 0 && (node.as_src ?? 0) >= 50 ? " — silent taker" : "") +
        ((node.same_ip ?? 0) >= 3 ? " — multi-port host" : "");
      crawler = `<div style="color:#ff9bb5;margin-top:3px">likely crawler${escHTML(why)}</div>`;
    }
    const bep51 = node.supports_bep51 === 1
      ? `<div style="color:#6edd8a;margin-top:3px">✓ BEP 51 capable</div>`
      : "";
    tip.innerHTML =
      `<div style="color:#8fc0ff">${escHTML(node.ip)}:${node.port}</div>` +
      `<div>` +
        (flag ? `<span style="margin-right:6px" title="${escHTML(cn)}">${flag} ${escHTML(node.country!)}</span>` : "") +
        `<span style="color:#ddd">${cli}</span>` +
      `</div>` +
      `<div style="color:#556066;font-size:11px">${extras}</div>` +
      crawler + bep51 +
      `<div style="color:#556066;font-size:11px">${escHTML(hex(node.id, 28))}</div>`;
  };

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

  return (
    <>
      <div className="filter">
        <label>
          nodes:{" "}
          <select value={limit} onChange={e => setLimit(parseInt(e.target.value))}>
            <option value={100}>100</option>
            <option value={500}>500</option>
            <option value={1000}>1,000</option>
            <option value={2500}>2,500</option>
            <option value={5000}>5,000 (max)</option>
          </select>
        </label>
        <button style={{ marginLeft: 10 }} onClick={load} disabled={loading}>
          {loading ? "loading…" : "reload"}
        </button>
        <button style={{ marginLeft: 6 }}
                onClick={() => fgRef.current?.zoomToFit(800)}>
          fit
        </button>
        <span className="small" style={{ marginLeft: 14 }}>
          {counts
            ? `${counts.nodes.toLocaleString()} nodes · ${counts.links.toLocaleString()} edges (drag to orbit, scroll to zoom)`
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
          graphData={data}
          nodeId="id"
          nodeVal={(n: any) => Math.max(1, Math.sqrt(n.deg || 1) * 1.4)}
          nodeColor={(n: any) => colorFor(n.country)}
          nodeOpacity={0.95}
          nodeResolution={8}        /* sphere segments — lower = faster */
          linkColor={() => "rgba(160,195,235,0.6)"}
          linkOpacity={0.55}
          linkWidth={1.2}
          enableNodeDrag={false}    /* dragging triggers extra simulation */
          showNavInfo={false}
          warmupTicks={50}
          cooldownTicks={200}        /* stop simulation after N ticks */
          onNodeHover={onNodeHover as any}
        />

        {loading && (
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
              loading graph…
            </div>
          </div>
        )}

        {/* Imperative tooltip */}
        <div
          ref={tipRef}
          style={{
            position: "fixed", display: "none", left: 0, top: 0,
            background: "#14181d", border: "1px solid #2a3642", borderRadius: 3,
            padding: "6px 10px", pointerEvents: "none", maxWidth: 320,
            fontSize: 12, color: "#d8dee6",
            boxShadow: "0 4px 14px rgba(0,0,0,0.5)", zIndex: 10
          }}
        />

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
                <br/>= peer's country (ISO → HSL hash).
              </div>
              <div style={{ color: "#a0a8b0", marginBottom: 8 }}>
                <b style={{ color: "#8fc0ff" }}>line</b>
                <br/>A → B = A returned B in a find_node response.
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
    </>
  );
}
