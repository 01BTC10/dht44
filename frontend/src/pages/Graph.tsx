import { useEffect, useRef, useState } from "react";
import { Cosmograph, prepareCosmographData } from "@cosmograph/react";
import type { CosmographConfig, CosmographRef } from "@cosmograph/react";
import { countryFlag, countryName, decodeVString, hex } from "../ws";

/*
 * Bubble graph: nodes are peers, an edge A→B means A returned B in a
 * compact-nodes response (i.e. B is in A's routing table per A's own view).
 *
 * GPU-rendered via Cosmograph (WebGL) so it scales to ~100k+ nodes at 60fps.
 */

type RawNode = {
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
};

type RawLink = { src: string; dst: string; source?: string; target?: string };

/* Deterministic ISO → hex color string. Cosmograph's "direct" point-color
 * strategy expects hex strings like "#ff8040", not the rgba(...) form. */
function colorFor(iso?: string | null): string {
  let h = 210, s = 10, l = 50;
  if (iso && iso.length === 2) {
    let hash = 0;
    for (let i = 0; i < iso.length; i++) hash = (hash * 31 + iso.charCodeAt(i)) >>> 0;
    h = hash % 360;
    s = 62;
    l = 55;
  }
  /* HSL → RGB */
  const c = (1 - Math.abs(2 * (l/100) - 1)) * (s/100);
  const x = c * (1 - Math.abs(((h/60) % 2) - 1));
  const m = (l/100) - c / 2;
  let r = 0, g = 0, b = 0;
  if (h < 60)       { r = c; g = x; }
  else if (h < 120) { r = x; g = c; }
  else if (h < 180) { g = c; b = x; }
  else if (h < 240) { g = x; b = c; }
  else if (h < 300) { r = x; b = c; }
  else              { r = c; b = x; }
  const R = Math.round((r + m) * 255);
  const G = Math.round((g + m) * 255);
  const B = Math.round((b + m) * 255);
  const hx = (n: number) => n.toString(16).padStart(2, "0");
  return `#${hx(R)}${hx(G)}${hx(B)}`;
}

/* Stable container style — defined outside the component so the prop ref
 * doesn't change between renders. Cosmograph is React.memo'd; if `style`
 * is an inline literal it sees a new prop every render and re-runs its
 * setConfig pipeline (which can lock up at 10k+ nodes). */
const FILL: React.CSSProperties = { width: "100%", height: "100%" };

function escHTML(s: string | null | undefined): string {
  if (s == null) return "";
  return String(s).replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" } as any)[c]);
}

/* Render the tooltip body for a peer. Plain HTML so it can be assigned
 * imperatively to tipRef.current.innerHTML without React. */
function renderTipHTML(n: RawNode): string {
  const flag = n.country ? countryFlag(n.country) : "";
  const cn   = n.country ? countryName(n.country) : "";
  const cli  = n.v_string ? decodeVString(n.v_string)
                          : `<span style="color:#556066">unknown client</span>`;
  let extras = `degree ${n.deg}`;
  if (n.as_src != null && n.as_dst != null)
    extras += ` · s:${n.as_src} d:${n.as_dst}`;
  if ((n.same_ip ?? 0) >= 2)
    extras += ` · ${n.same_ip} ports/ip`;

  let crawler = "";
  if (n.likely_crawler) {
    const why =
      (n.as_dst === 0 && (n.as_src ?? 0) >= 50 ? " — silent taker" : "") +
      ((n.same_ip ?? 0) >= 3 ? " — multi-port host" : "");
    crawler = `<div style="color:#ff9bb5;margin-top:3px">likely crawler${escHTML(why)}</div>`;
  }
  let bep51 = "";
  if (n.supports_bep51 === 1) {
    bep51 = `<div style="color:#6edd8a;margin-top:3px">✓ BEP 51 (sample_infohashes) capable</div>`;
  }
  return (
    `<div style="color:#8fc0ff">${escHTML(n.ip)}:${n.port}</div>` +
    `<div>` +
      (flag ? `<span style="margin-right:6px" title="${escHTML(cn)}">${flag} ${escHTML(n.country!)}</span>` : "") +
      `<span style="color:#ddd">${cli}</span>` +
    `</div>` +
    `<div style="color:#556066;font-size:11px">${extras}</div>` +
    crawler +
    bep51 +
    `<div style="color:#556066;font-size:11px">${escHTML(hex(n.id, 28))}</div>`
  );
}

export default function Graph() {
  const cosmoRef     = useRef<CosmographRef>(null);
  const tipRef       = useRef<HTMLDivElement>(null);
  const [limit, setLimit]       = useState(1000);
  const [loading, setLoading]   = useState(false);
  const [config, setConfig]     = useState<CosmographConfig>({});
  const [counts, setCounts]     = useState<{ nodes: number; links: number } | null>(null);
  const [showLegend, setShowLegend] = useState(true);

  /* Refs that survive renders without triggering them. The cosmograph
   * hover callbacks read from these instead of from a stale closure.
   * The tooltip is updated imperatively via tipRef so hover never
   * triggers a React render — at 10k+ nodes any re-render of <Graph>
   * cascades through the cosmograph wrapper and locks the page. */
  const pointsRef     = useRef<RawNode[]>([]);
  const lastHoverIdx  = useRef<number>(-1);

  const load = async () => {
    setLoading(true);
    try {
      const r = await fetch(`/api/graph?limit=${limit}`);
      const g = await r.json();
      const points: RawNode[] = (g.nodes ?? []).map((n: RawNode) => ({
        ...n,
        /* Pre-compute per-point color + size as fields Cosmograph can read.
         * Cosmograph applies pointColorBy/pointSizeBy without further code. */
      }));
      /* Cosmograph needs source/target keys, not src/dst. */
      const links: RawLink[] = (g.links ?? [])
        .map((e: RawLink) => ({ source: e.src, target: e.dst }))
        .filter((e: RawLink) => e.source !== e.target);

      /* Inject precomputed color + size + index into each row.
       * Cosmograph requires pointIndexBy (a 0..N numeric); without
       * prepareCosmographData we have to assign it ourselves. */
      const idx = new Map<string, number>();
      for (let i = 0; i < points.length; i++) {
        const n = points[i] as any;
        n._idx = i;
        n._color = colorFor(n.country);
        n._size  = Math.max(4, Math.min(32, 4 + Math.sqrt(n.deg || 1) * 2.2));
        idx.set(n.id, i);
      }
      /* Cosmograph also wants links to reference points by *index*, not
       * just by string id. Add linkSourceIndexBy / linkTargetIndexBy. */
      for (const e of links as any[]) {
        const si = idx.get(e.source);
        const ti = idx.get(e.target);
        e._sidx = si ?? -1;
        e._tidx = ti ?? -1;
      }
      pointsRef.current = points;

      /* Skip prepareCosmographData — it strips columns not declared in
       * the data config (so _color/_size never reach the renderer).
       * Pass the raw arrays directly with column mapping inline. */
      setConfig({
        points: points as any,
        links:  links as any,
        pointIdBy:           "id",
        pointIndexBy:        "_idx",
        linkSourceBy:        "source",
        linkTargetBy:        "target",
        linkSourceIndexBy:   "_sidx",
        linkTargetIndexBy:   "_tidx",

        /* visual style. With strategy=direct cosmograph reads the value
         * from pointColorBy / pointSizeBy and passes it to the *ByFn
         * accessor (it does NOT use the value as-is). We use the raw
         * pre-baked _color / _size columns plus identity functions, so
         * effectively the column value IS the color/size. */
        backgroundColor:        "#0a0c0f",
        pointColorBy:           "_color",
        pointColorStrategy:     "direct",
        pointColorByFn:         (c: string) => c || "#888",
        pointSizeBy:            "_size",
        pointSizeStrategy:      "direct",
        pointSizeByFn:          (s: number) => s ?? 6,
          /* Multiplier on top of _size so hub peers are very visible, and
           * grow them with zoom so dense clusters stay readable when you
           * zoom in. */
          pointSizeScale:         2.0,
          scalePointsOnZoom:      true,
          linkColor:              "rgba(160,195,235,0.42)",
          linkWidth:              0.6,
          linkArrows:             false,

          /* simulation tuning — dimensionless 0..1 in cosmograph */
          simulationGravity:      0.06,
          simulationCenter:       0.0,
          simulationRepulsion:    1.0,
          simulationLinkSpring:   0.4,
          simulationLinkDistance: 6,
          simulationFriction:     0.86,

          /* Imperative tooltip — no React state churn. Cosmograph fires
           * onPointMouseOver on every frame the cursor sits over a point
           * (with a moving simulation, that's *constant*). Updating React
           * state for that flood locks up the page at 10k+ nodes. */
          onPointMouseOver: (i: number, _pos: [number, number], ev: any) => {
            const n = pointsRef.current[i];
            if (!n) return;
            const me = ev as MouseEvent;
            const tip = tipRef.current;
            if (!tip) return;
            /* Update position every frame (cheap — just two style writes). */
            tip.style.left = (me.clientX + 12) + "px";
            tip.style.top  = (me.clientY + 12) + "px";
            /* Only rebuild contents when the hovered index changes. */
            if (lastHoverIdx.current === i) return;
            lastHoverIdx.current = i;
            tip.style.display = "block";
            tip.innerHTML = renderTipHTML(n);
          },
          onPointMouseOut: () => {
            if (lastHoverIdx.current === -1) return;
            lastHoverIdx.current = -1;
            const tip = tipRef.current;
            if (tip) tip.style.display = "none";
          },
      });
      setCounts({ nodes: points.length, links: links.length });
    } catch (e) { /* ignore */ }
    setLoading(false);
  };

  useEffect(() => { load(); /* eslint-disable-next-line */ }, [limit]);

  return (
    <>
      <div className="filter">
        <label>
          nodes:{" "}
          <select value={limit} onChange={e => setLimit(parseInt(e.target.value))}>
            <option value={100}>100</option>
            <option value={500}>500</option>
            <option value={1000}>1,000</option>
            <option value={5000}>5,000</option>
            <option value={10000}>10,000 (max)</option>
          </select>
        </label>
        <button style={{ marginLeft: 10 }} onClick={load} disabled={loading}>
          {loading ? "loading…" : "reload"}
        </button>
        <button style={{ marginLeft: 6 }} onClick={() => cosmoRef.current?.fitView()}>
          fit
        </button>
        <span className="small" style={{ marginLeft: 14 }}>
          {counts
            ? `${counts.nodes.toLocaleString()} nodes · ${counts.links.toLocaleString()} edges (drag to pan, scroll to zoom)`
            : ""}
        </span>
      </div>

      <div style={{ position: "relative", width: "100%",
                    height: "calc(100vh - 170px)",
                    background: "#0a0c0f", border: "1px solid #232a31",
                    borderRadius: 3, overflow: "hidden" }}>
        <Cosmograph
          ref={cosmoRef as any}
          {...config}
          style={FILL}
        />

        {/* Persistent tooltip — never re-rendered by React. The cosmograph
         * hover handler writes directly to ref.innerHTML + style.left/top. */}
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


        {/* collapsible legend overlay (kept as-is from canvas version) */}
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
            <span>legend (GPU)</span>
            <span style={{ color: "#8892a0" }}>{showLegend ? "−" : "+"}</span>
          </div>
          {showLegend && (
            <div style={{ marginTop: 8 }}>
              <div style={{ color: "#a0a8b0", marginBottom: 8 }}>
                <b style={{ color: "#8fc0ff" }}>bubble size</b>
                <br/>= log(degree). Larger = more edges touch this peer.
              </div>
              <div style={{ color: "#a0a8b0", marginBottom: 8 }}>
                <b style={{ color: "#8fc0ff" }}>color</b>
                <br/>= peer's country (ISO → HSL hash). Same color = same country.
              </div>
              <div style={{ color: "#a0a8b0", marginBottom: 8 }}>
                <b style={{ color: "#8fc0ff" }}>line</b>
                <br/>A → B = A returned B in a find_node response.
              </div>
              <div style={{ color: "#8fc0ff", fontSize: 10, letterSpacing: 0.5,
                             marginTop: 8, textTransform: "uppercase" }}>controls</div>
              <div style={{ color: "#a0a8b0" }}>
                drag = pan · scroll = zoom · fit button = reset
              </div>
              <div style={{ color: "#8892a0", marginTop: 8, fontSize: 10,
                             borderTop: "1px solid #232a31", paddingTop: 6 }}>
                Powered by Cosmograph (WebGL). Layout runs on GPU; this
                view scales smoothly to 100k+ nodes.
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
