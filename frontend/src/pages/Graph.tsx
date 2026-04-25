import { useEffect, useRef, useState } from "react";
import { countryFlag, countryName, decodeVString, hex } from "../ws";

/*
 * Bubble graph: nodes are peers, an edge A→B means A returned B in a
 * compact-nodes response (i.e. B is in A's routing table per A's own view).
 * Canvas-based force-directed layout — no external dep.
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

  /* sim state */
  x: number; y: number; vx: number; vy: number; r: number;
};

type Link = { src: string; dst: string };

/* Simple deterministic palette from ISO code → HSL */
function colorFor(iso?: string | null): string {
  if (!iso) return "hsl(210 10% 50%)";
  let h = 0;
  for (let i = 0; i < iso.length; i++) h = (h * 31 + iso.charCodeAt(i)) >>> 0;
  return `hsl(${h % 360} 62% 55%)`;
}

export default function Graph() {
  const canvasRef  = useRef<HTMLCanvasElement>(null);
  const wrapRef    = useRef<HTMLDivElement>(null);
  const [limit, setLimit]       = useState(300);
  const [loading, setLoading]   = useState(false);
  const [counts, setCounts]     = useState<{ nodes: number; links: number } | null>(null);
  const [hover, setHover]       = useState<Node | null>(null);
  const [showLegend, setShowLegend] = useState(true);
  const mouse                    = useRef({ x: 0, y: 0, dragging: false, dragNode: null as Node | null });
  const view                     = useRef({ tx: 0, ty: 0, k: 1 });

  /* Live simulation state lives in refs, not React state — ~60 fps. */
  const sim    = useRef<{ nodes: Node[]; links: Link[] }>({ nodes: [], links: [] });
  /* Alpha cools each frame; energy injected on user interaction. */
  const alpha  = useRef(1.0);

  const load = async () => {
    setLoading(true);
    try {
      const r = await fetch(`/api/graph?limit=${limit}`);
      const g = await r.json();
      /* Spread nodes out more for larger graphs so initial repulsion doesn't
       * spike from dense overlap. */
      const N = g.nodes?.length || 1;
      const R = 120 + Math.sqrt(N) * 30;
      const nodes: Node[] = (g.nodes || []).map((n: any, i: number) => ({
        id: n.id, ip: n.ip, port: n.port, deg: n.deg,
        v_string: n.v_string, country: n.country,
        as_src: n.as_src, as_dst: n.as_dst, same_ip: n.same_ip,
        likely_crawler: n.likely_crawler,
        supports_bep51: n.supports_bep51,
        x: Math.cos((i / N) * Math.PI * 2) * R * (0.6 + 0.4 * Math.random()),
        y: Math.sin((i / N) * Math.PI * 2) * R * (0.6 + 0.4 * Math.random()),
        vx: 0, vy: 0,
        r: Math.max(3, Math.min(18, 2 + Math.sqrt(n.deg || 1) * 1.4)),
      }));
      const links: Link[] = (g.links || []).filter(
        (e: Link) => e.src !== e.dst
      );
      sim.current = { nodes, links };
      alpha.current = 1.0;          /* fresh heat for new layout */
      setCounts({ nodes: nodes.length, links: links.length });
    } catch (e) { /* ignore */ }
    setLoading(false);
  };

  useEffect(() => { load(); /* eslint-disable-next-line */ }, [limit]);

  /* Force simulation + render loop */
  useEffect(() => {
    const canvas = canvasRef.current!;
    const ctx    = canvas.getContext("2d")!;
    let raf = 0;
    let running = true;

    const resize = () => {
      const r = wrapRef.current!.getBoundingClientRect();
      canvas.width  = r.width;
      canvas.height = r.height;
    };
    resize();
    window.addEventListener("resize", resize);

    const step = () => {
      if (!running) return;
      const { nodes, links } = sim.current;
      const W = canvas.width, H = canvas.height;
      const byId = new Map(nodes.map(n => [n.id, n]));
      const a_ = alpha.current;

      /* Spatial grid for O(n) repulsion: each node only pushes against
       * neighbours in its own cell + the 8 adjacent cells. A larger cell
       * means clusters feel each other from further away and drift apart
       * instead of bunching in the middle. */
      const CELL = 320;
      const cells = new Map<string, Node[]>();
      for (const n of nodes) {
        const k = Math.floor(n.x / CELL) + "," + Math.floor(n.y / CELL);
        let c = cells.get(k);
        if (!c) { c = []; cells.set(k, c); }
        c.push(n);
      }

      /* Scale repulsion strength down with density so big graphs don't blow
       * up. The base strength is high so non-connected peers actually push
       * each other apart across cluster boundaries. */
      const REP = 5500 * Math.min(1, 300 / Math.max(50, nodes.length));

      for (const n of nodes) {
        const gx = Math.floor(n.x / CELL), gy = Math.floor(n.y / CELL);
        for (let dx = -1; dx <= 1; dx++) {
          for (let dy = -1; dy <= 1; dy++) {
            const bucket = cells.get((gx + dx) + "," + (gy + dy));
            if (!bucket) continue;
            for (const m of bucket) {
              if (m === n) continue;
              let rx = n.x - m.x, ry = n.y - m.y;
              let d2 = rx * rx + ry * ry;
              if (d2 < 0.01) { rx = Math.random() - 0.5; ry = Math.random() - 0.5; d2 = 1; }
              if (d2 > CELL * CELL) continue;        /* outside neighbourhood */
              const d = Math.sqrt(d2);
              const f = (REP / d2) * a_;
              n.vx += (rx / d) * f;
              n.vy += (ry / d) * f;
            }
          }
        }
      }

      /* Springs along edges. Weaker than before: a single cross-cluster edge
       * won't yank two whole clusters together, but dense clusters still pull
       * their members into a readable ball. */
      for (const e of links) {
        const a = byId.get(e.src), b = byId.get(e.dst);
        if (!a || !b) continue;
        const dx = b.x - a.x, dy = b.y - a.y;
        const d  = Math.sqrt(dx * dx + dy * dy) || 1;
        const target = 80;
        const f = (d - target) * 0.025 * a_;
        const fx = (dx / d) * f, fy = (dy / d) * f;
        a.vx += fx; a.vy += fy;
        b.vx -= fx; b.vy -= fy;
      }
      /* Bounded gravity: zero pull inside the comfort radius, a gentle
       * centripetal force only when a node drifts outside. Clusters can
       * spread freely until they reach the boundary, which prevents the
       * "everything collapses to origin" problem without letting the graph
       * escape the viewport. */
      const COMFORT = 600;
      for (const n of nodes) {
        const r2 = n.x * n.x + n.y * n.y;
        if (r2 > COMFORT * COMFORT) {
          const r = Math.sqrt(r2);
          const pull = (r - COMFORT) * 0.004 * a_;
          n.vx -= (n.x / r) * pull;
          n.vy -= (n.y / r) * pull;
        }
      }
      /* integrate with damping + hard velocity cap to prevent runaway */
      const drag = mouse.current.dragNode;
      const VMAX = 12;
      for (const n of nodes) {
        if (n === drag) continue;
        n.vx *= 0.82; n.vy *= 0.82;
        /* clamp magnitude */
        const sp2 = n.vx * n.vx + n.vy * n.vy;
        if (sp2 > VMAX * VMAX) {
          const k = VMAX / Math.sqrt(sp2);
          n.vx *= k; n.vy *= k;
        }
        n.x += n.vx; n.y += n.vy;
      }
      /* cool the simulation so it settles instead of jittering forever */
      if (alpha.current > 0.05) alpha.current *= 0.9965;

      /* === render === */
      ctx.clearRect(0, 0, W, H);
      ctx.save();
      ctx.translate(W / 2 + view.current.tx, H / 2 + view.current.ty);
      ctx.scale(view.current.k, view.current.k);

      /* Edges: brighter base color, and highlight edges touching the
       * hovered/dragged node so the graph stays readable in dark mode. */
      const focus = (drag ?? hover) as Node | null;
      ctx.lineWidth = 0.8;
      ctx.strokeStyle = "rgba(160, 195, 235, 0.42)";
      for (const e of links) {
        const a = byId.get(e.src), b = byId.get(e.dst);
        if (!a || !b) continue;
        if (focus && (a === focus || b === focus)) continue;    /* draw last */
        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(b.x, b.y);
        ctx.stroke();
      }
      if (focus) {
        ctx.lineWidth = 1.4;
        ctx.strokeStyle = "rgba(255, 220, 120, 0.95)";
        for (const e of links) {
          const a = byId.get(e.src), b = byId.get(e.dst);
          if (!a || !b) continue;
          if (a !== focus && b !== focus) continue;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }

      for (const n of nodes) {
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
        ctx.fillStyle = colorFor(n.country);
        ctx.fill();
        /* Crawler ring: dashed red outline on peers flagged by the heuristic. */
        if (n.likely_crawler) {
          ctx.lineWidth = 1.6;
          ctx.strokeStyle = "rgba(255, 90, 120, 0.95)";
          ctx.setLineDash([3, 2]);
          ctx.stroke();
          ctx.setLineDash([]);
        }
        if (n === hover || n === drag) {
          ctx.lineWidth = 1.4;
          ctx.strokeStyle = "#fff";
          ctx.stroke();
        }
      }
      ctx.restore();

      raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);

    return () => {
      running = false;
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", resize);
    };
  }, [hover]);

  /* Convert screen coords → world coords (inverse of our transform). */
  const toWorld = (sx: number, sy: number) => {
    const W = canvasRef.current!.width, H = canvasRef.current!.height;
    return {
      x: (sx - W / 2 - view.current.tx) / view.current.k,
      y: (sy - H / 2 - view.current.ty) / view.current.k,
    };
  };

  const hit = (wx: number, wy: number): Node | null => {
    for (const n of sim.current.nodes) {
      const dx = n.x - wx, dy = n.y - wy;
      if (dx * dx + dy * dy <= (n.r + 2) * (n.r + 2)) return n;
    }
    return null;
  };

  const onDown = (e: React.MouseEvent) => {
    const rect = canvasRef.current!.getBoundingClientRect();
    const sx = e.clientX - rect.left, sy = e.clientY - rect.top;
    mouse.current.x = sx; mouse.current.y = sy;
    mouse.current.dragging = true;
    const w = toWorld(sx, sy);
    mouse.current.dragNode = hit(w.x, w.y);
    alpha.current = Math.max(alpha.current, 0.4);
  };
  const onMove = (e: React.MouseEvent) => {
    const rect = canvasRef.current!.getBoundingClientRect();
    const sx = e.clientX - rect.left, sy = e.clientY - rect.top;
    const prev = { x: mouse.current.x, y: mouse.current.y };
    mouse.current.x = sx; mouse.current.y = sy;
    const w = toWorld(sx, sy);

    if (mouse.current.dragging) {
      if (mouse.current.dragNode) {
        mouse.current.dragNode.x = w.x;
        mouse.current.dragNode.y = w.y;
        mouse.current.dragNode.vx = 0;
        mouse.current.dragNode.vy = 0;
      } else {
        view.current.tx += sx - prev.x;
        view.current.ty += sy - prev.y;
      }
    } else {
      setHover(hit(w.x, w.y));
    }
  };
  const onUp = () => { mouse.current.dragging = false; mouse.current.dragNode = null; };
  const onWheel = (e: React.WheelEvent) => {
    const factor = Math.pow(1.0015, -e.deltaY);
    const nk = Math.max(0.2, Math.min(5, view.current.k * factor));
    view.current.k = nk;
  };

  return (
    <>
      <div className="filter">
        <label>
          nodes:{" "}
          <select value={limit} onChange={e => setLimit(parseInt(e.target.value))}>
            <option value={100}>100</option>
            <option value={200}>200</option>
            <option value={300}>300</option>
            <option value={500}>500</option>
            <option value={1000}>1000</option>
            <option value={2500}>2500</option>
            <option value={10000}>all (10k cap)</option>
          </select>
        </label>
        <button style={{ marginLeft: 10 }} onClick={load} disabled={loading}>
          {loading ? "loading…" : "reload"}
        </button>
        <span className="small" style={{ marginLeft: 14 }}>
          {counts
            ? `${counts.nodes} nodes · ${counts.links} edges (drag bubbles, drag bg to pan, scroll to zoom)`
            : ""}
        </span>
      </div>

      <div
        ref={wrapRef}
        style={{ position: "relative", width: "100%",
                 /* fill the remaining viewport: viewport minus everything
                  * above (app header, stats bar, tab nav, graph toolbar). */
                 height: "calc(100vh - 170px)",
                 background: "#0a0c0f", border: "1px solid #232a31",
                 borderRadius: 3, overflow: "hidden" }}
      >
        <canvas
          ref={canvasRef}
          onMouseDown={onDown} onMouseMove={onMove} onMouseUp={onUp}
          onMouseLeave={onUp}  onWheel={onWheel}
          style={{ display: "block", width: "100%", height: "100%",
                   cursor: mouse.current.dragging ? "grabbing" : "default" }}
        />
        {hover && (
          <div style={{
            position: "absolute", left: mouse.current.x + 12, top: mouse.current.y + 12,
            background: "#14181d", border: "1px solid #2a3642", borderRadius: 3,
            padding: "6px 10px", pointerEvents: "none", maxWidth: 280, fontSize: 12,
            boxShadow: "0 4px 14px rgba(0,0,0,0.5)"
          }}>
            <div style={{ color: "#8fc0ff" }}>{hover.ip}:{hover.port}</div>
            <div>
              {hover.country && (
                <span style={{ marginRight: 6 }} title={countryName(hover.country)}>
                  {countryFlag(hover.country)} {hover.country}
                </span>
              )}
              <span style={{ color: "#ddd" }}>
                {hover.v_string ? decodeVString(hover.v_string) : <span className="dim">unknown client</span>}
              </span>
            </div>
            <div className="small">
              degree {hover.deg}
              {hover.as_src != null && hover.as_dst != null &&
                ` · s:${hover.as_src} d:${hover.as_dst}`}
              {(hover.same_ip ?? 0) >= 2 && ` · ${hover.same_ip} ports/ip`}
            </div>
            {!!hover.likely_crawler && (
              <div style={{ color: "#ff9bb5", marginTop: 3 }}>
                likely crawler
                {hover.as_dst === 0 && (hover.as_src ?? 0) >= 50
                  ? " — silent taker" : ""}
                {(hover.same_ip ?? 0) >= 3
                  ? " — multi-port host" : ""}
              </div>
            )}
            {hover.supports_bep51 === 1 && (
              <div style={{ color: "#6edd8a", marginTop: 3 }}>
                ✓ BEP 51 (sample_infohashes) capable
              </div>
            )}
            <div className="small">{hex(hover.id, 28)}</div>
          </div>
        )}

        {/* Collapsible legend overlay */}
        <div style={{
          position: "absolute", top: 10, right: 10,
          background: "rgba(20,24,29,0.94)", border: "1px solid #2a3642",
          borderRadius: 3, padding: showLegend ? "8px 12px" : "4px 10px",
          fontSize: 11, color: "#d8dee6", maxWidth: 280, lineHeight: 1.45,
          boxShadow: "0 4px 14px rgba(0,0,0,0.4)"
        }}>
          <div style={{
            display: "flex", alignItems: "center", justifyContent: "space-between",
            gap: 10, cursor: "pointer", color: "#8fc0ff",
            textTransform: "uppercase", letterSpacing: 0.5, fontSize: 10
          }}
               onClick={() => setShowLegend(s => !s)}>
            <span>legend</span>
            <span style={{ color: "#8892a0" }}>{showLegend ? "−" : "+"}</span>
          </div>

          {showLegend && (
            <div style={{ marginTop: 8 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
                <span style={{
                  display: "inline-block", width: 6, height: 6, borderRadius: "50%",
                  background: "hsl(210 62% 55%)"
                }} />
                <span style={{
                  display: "inline-block", width: 12, height: 12, borderRadius: "50%",
                  background: "hsl(210 62% 55%)"
                }} />
                <span style={{
                  display: "inline-block", width: 18, height: 18, borderRadius: "50%",
                  background: "hsl(210 62% 55%)"
                }} />
                <b style={{ color: "#8fc0ff", marginLeft: 4 }}>bubble size</b>
              </div>
              <div style={{ color: "#a0a8b0", marginBottom: 8 }}>
                = log(degree). Larger = referenced by more peers.
                Degree is how many edges touch this peer.
              </div>

              <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
                <span style={{ display: "inline-block", width: 12, height: 12, borderRadius: "50%", background: "hsl(20 62% 55%)" }} />
                <span style={{ display: "inline-block", width: 12, height: 12, borderRadius: "50%", background: "hsl(110 62% 55%)" }} />
                <span style={{ display: "inline-block", width: 12, height: 12, borderRadius: "50%", background: "hsl(260 62% 55%)" }} />
                <b style={{ color: "#8fc0ff", marginLeft: 4 }}>color</b>
              </div>
              <div style={{ color: "#a0a8b0", marginBottom: 8 }}>
                = peer's country (ISO → HSL hash). Same color = same country.
                Grey-ish = GeoIP miss.
              </div>

              <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
                <svg width="32" height="10"><line x1="0" y1="5" x2="32" y2="5"
                  stroke="rgba(160,195,235,.6)" strokeWidth="1"/></svg>
                <b style={{ color: "#8fc0ff", marginLeft: 4 }}>line</b>
              </div>
              <div style={{ color: "#a0a8b0", marginBottom: 8 }}>
                A → B means A returned B in a find_node response
                (B is in A's routing table).
              </div>

              <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
                <svg width="32" height="10"><line x1="0" y1="5" x2="32" y2="5"
                  stroke="rgba(255,220,120,.95)" strokeWidth="1.6"/></svg>
                <b style={{ color: "#8fc0ff", marginLeft: 4 }}>amber</b>
              </div>
              <div style={{ color: "#a0a8b0", marginBottom: 8 }}>
                hover/drag a bubble → its edges light up
                to show that peer's neighbors.
              </div>

              <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
                <svg width="20" height="16">
                  <circle cx="10" cy="8" r="6" fill="hsl(210 62% 55%)"
                          stroke="rgba(255,90,120,.95)" strokeWidth="1.5"
                          strokeDasharray="3,2"/>
                </svg>
                <b style={{ color: "#ff9bb5", marginLeft: 4 }}>red ring</b>
              </div>
              <div style={{ color: "#a0a8b0", marginBottom: 8 }}>
                likely crawler: never kept by others (as_dst=0)
                AND answered us 50+ times, or ≥3 source ports
                from one IP.
              </div>

              <div style={{ color: "#8fc0ff", fontSize: 10, letterSpacing: 0.5,
                             marginTop: 8, textTransform: "uppercase" }}>controls</div>
              <div style={{ color: "#a0a8b0" }}>
                drag bubble = pin · drag bg = pan · scroll = zoom
              </div>

              <div style={{ color: "#8892a0", marginTop: 8, fontSize: 10,
                             borderTop: "1px solid #232a31", paddingTop: 6 }}>
                positions are emergent from a live force sim
                (repulsion + edge springs + gravity). clusters mean
                peers that reference each other.
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
