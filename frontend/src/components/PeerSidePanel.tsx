import { useEffect } from "react";
import { countryFlag, countryName, decodeVString, fmtTs, hex } from "../ws";
import { CrawlerBadge, CrawlerClass } from "./CrawlerBadge";
import type { Node } from "../pages/Graph";

export default function PeerSidePanel(
  { node, onClose }: { node: Node; onClose: () => void },
) {
  /* Click anywhere outside the panel closes it (besides Esc, handled in
   * Graph.tsx). Mounted as effect so we can clean up. */
  useEffect(() => {
    const onDown = (e: MouseEvent) => {
      const t = e.target as HTMLElement | null;
      if (t && t.closest("[data-peer-panel]")) return;
      /* Don't close on graph canvas clicks — those just deselect via the
       * library's own onNodeClick=null. */
      if (t && t.closest("canvas")) return;
      onClose();
    };
    /* Defer one tick so the click that opened the panel doesn't immediately
     * close it. */
    const id = window.setTimeout(
      () => window.addEventListener("mousedown", onDown), 0);
    return () => {
      window.clearTimeout(id);
      window.removeEventListener("mousedown", onDown);
    };
  }, [onClose]);

  const iso  = node.geo?.country ?? node.country ?? "";
  const flag = countryFlag(iso);
  const name = countryName(iso);
  const cli  = node.v_string ? decodeVString(node.v_string) : null;
  const cls  = (node.crawler_class ?? (node.likely_crawler ? "crawler" : "ok")) as CrawlerClass;
  const v6   = node.ip.includes(":");
  const ago  = node.last_seen
    ? Math.max(0, Math.floor(Date.now() / 1000 - node.last_seen))
    : null;
  const agoStr = ago == null ? "—"
    : ago < 60 ? `${ago}s ago`
    : ago < 3600 ? `${Math.floor(ago / 60)}m ago`
    : ago < 86400 ? `${Math.floor(ago / 3600)}h ago`
    : `${Math.floor(ago / 86400)}d ago`;

  return (
    <div data-peer-panel
         style={{
           position: "fixed",
           top: 0, right: 0, bottom: 0, width: 380, maxWidth: "100vw",
           background: "#0f1316",
           borderLeft: "1px solid #2a3642",
           color: "#d8dee6",
           fontSize: 12,
           padding: "14px 16px",
           overflowY: "auto",
           zIndex: 30,
           boxShadow: "-6px 0 20px rgba(0,0,0,0.55)",
         }}>
      <div style={{ display: "flex", justifyContent: "space-between",
                    alignItems: "flex-start", gap: 8, marginBottom: 6 }}>
        <div>
          <div style={{ color: "#8fc0ff", fontSize: 14 }}>
            {node.ip}:{node.port}
            <span style={{ color: "#556066", marginLeft: 8, fontSize: 10 }}>
              {v6 ? "IPv6" : "IPv4"}
            </span>
          </div>
          <div style={{ marginTop: 2 }}>
            {flag && <span style={{ marginRight: 6, fontSize: 14 }}>{flag}</span>}
            <span style={{ color: "#e0a648" }}>{name || iso || "unknown"}</span>
            {node.geo?.city && (
              <span style={{ color: "#a0a8b0" }}> · {node.geo.city}</span>
            )}
          </div>
          {node.geo?.asn_org && (
            <div style={{ color: "#c27fe0", marginTop: 2 }}>
              AS{node.geo.asn} {node.geo.asn_org}
            </div>
          )}
        </div>
        <button onClick={onClose}
                style={{ background: "transparent", color: "#a0a8b0",
                         border: "1px solid #2a3642", borderRadius: 2,
                         padding: "0 7px", cursor: "pointer", fontSize: 14,
                         lineHeight: "20px" }}>
          ×
        </button>
      </div>

      {cls !== "ok" && (
        <div style={{ margin: "8px 0" }}>
          <CrawlerBadge cls={cls}
                        score={node.crawler_score ?? 0}
                        signals={node.crawler_signals ?? []}
                        reason={node.crawler_reason ?? ""} />
          <span style={{ marginLeft: 8, color: "#8892a0", fontSize: 11 }}>
            (hover the tag for the full reason)
          </span>
        </div>
      )}

      <div style={{ marginTop: 8, marginBottom: 4, color: "#8fc0ff",
                    fontSize: 10, letterSpacing: 0.5,
                    textTransform: "uppercase" }}>
        client
      </div>
      <div>{cli || <span style={{ color: "#556066" }}>unknown</span>}</div>

      <div style={{ marginTop: 12, display: "grid",
                    gridTemplateColumns: "auto 1fr", rowGap: 4, columnGap: 12 }}>
        <span style={{ color: "#8892a0" }}>last seen</span>
        <span>{node.last_seen ? `${fmtTs(node.last_seen)} (${agoStr})` : "—"}</span>
        <span style={{ color: "#8892a0" }}>first seen</span>
        <span>{node.first_seen ? fmtTs(node.first_seen) : "—"}</span>
        <span style={{ color: "#8892a0" }}>queries in / out</span>
        <span>{(node.queries_in ?? 0).toLocaleString()} / {(node.queries_out ?? 0).toLocaleString()}</span>
        <span style={{ color: "#8892a0" }}>RTT (EWMA)</span>
        <span>{node.rtt_ms != null ? `${node.rtt_ms} ms` : <span style={{ color: "#556066" }}>—</span>}</span>
        <span style={{ color: "#8892a0" }}>edge count</span>
        <span>in {node.as_dst ?? 0} · out {node.as_src ?? 0} · in-result {node.deg}</span>
        <span style={{ color: "#8892a0" }}>ports on this IP</span>
        <span>{node.same_ip ?? 1}</span>
        <span style={{ color: "#8892a0" }}>BEP 51</span>
        <span style={{ color: node.supports_bep51 === 1 ? "#6edd8a" : "#556066" }}>
          {node.supports_bep51 === 1 ? "✓ replied to sample_infohashes" : "not confirmed"}
        </span>
        <span style={{ color: "#8892a0" }}>read-only flag</span>
        <span style={{ color: node.ro === 1 ? "#ff9bb5" : "#556066" }}>
          {node.ro === 1 ? "yes (BEP 5 ro=1)" : node.ro === 0 ? "no" : "—"}
        </span>
        <span style={{ color: "#8892a0" }}>BEP 42 ID check</span>
        <span style={{ color: node.bep42_ok === 0 ? "#ffc578" : "#556066" }}>
          {node.bep42_ok === 1 ? "✓ ok" : node.bep42_ok === 0 ? "fail" : "—"}
        </span>
      </div>

      <div style={{ marginTop: 12, color: "#8fc0ff", fontSize: 10,
                    letterSpacing: 0.5, textTransform: "uppercase",
                    marginBottom: 4 }}>
        node id (BEP 5)
      </div>
      <div style={{ fontFamily: "monospace", color: "#8892a0",
                    fontSize: 11, wordBreak: "break-all" }}>
        {node.node_id ? hex(node.node_id, 40) : <span style={{ color: "#556066" }}>—</span>}
      </div>
    </div>
  );
}
