import { useState } from "react";
import { HoverPause } from "./HoverPause";

export type CrawlerClass = "ok" | "crawler" | "monitor" | "honeypot";

const STYLES: Record<CrawlerClass, { bg: string; fg: string; border: string; label: string }> = {
  ok:       { bg: "transparent", fg: "transparent", border: "transparent", label: "" },
  crawler:  { bg: "#3a2230", fg: "#ff9bb5", border: "#8a3e54", label: "crawler?" },
  monitor:  { bg: "#3a2e1a", fg: "#ffc578", border: "#8a6a2e", label: "monitor?" },
  honeypot: { bg: "#3a1a1a", fg: "#ff7878", border: "#8a2e2e", label: "honeypot?" },
};

const SIGNAL_LABELS: Record<string, string> = {
  silent_taker:     "silent taker",
  port_farm_mild:   "port farm (mild)",
  port_farm_strong: "port farm (strong)",
  port_farm_mass:   "port farm (datacenter)",
  read_only:        "read-only flag",
  bep42_bad:        "bad BEP 42",
  asymmetric_in:    "asymmetric inbound",
  no_v_string:      "no client id",
};

function prettySignal(raw: string): string {
  const colon = raw.indexOf(":");
  if (colon < 0) return SIGNAL_LABELS[raw] ?? raw;
  const tag = raw.slice(0, colon);
  const arg = raw.slice(colon + 1);
  if (tag === "monitor_asn") return `monitor ASN: ${arg}`;
  if (tag === "dc_asn")      return `datacenter ASN: ${arg}`;
  return raw;
}

export function CrawlerBadge(
  { cls, score, signals, reason }:
  { cls: CrawlerClass; score: number; signals: string[]; reason: string },
) {
  const [open, setOpen] = useState(false);
  if (cls === "ok") return null;
  const s = STYLES[cls];

  return (
    <HoverPause
      style={{ position: "relative", marginLeft: 6, display: "inline-block" }}
    >
      <span
        onMouseEnter={() => setOpen(true)}
        onMouseLeave={() => setOpen(false)}
        style={{
          padding: "1px 5px",
          background: s.bg,
          color: s.fg,
          borderRadius: 2,
          fontSize: 10,
          border: `1px solid ${s.border}`,
          cursor: "default",
        }}
      >
        {s.label}
      </span>
      {open && (
        <div
          onMouseEnter={() => setOpen(true)}
          onMouseLeave={() => setOpen(false)}
          style={{
            position: "absolute",
            top: "calc(100% + 4px)",
            left: 0,
            zIndex: 100,
            background: "#0f1316",
            border: `1px solid ${s.border}`,
            borderRadius: 3,
            padding: "8px 10px",
            minWidth: 280,
            maxWidth: 420,
            color: "#d8dee6",
            fontSize: 11,
            lineHeight: 1.5,
            boxShadow: "0 4px 12px rgba(0,0,0,0.5)",
            whiteSpace: "normal",
          }}
        >
          <div style={{ color: s.fg, fontWeight: 600, marginBottom: 4 }}>
            {s.label.replace("?", "")} (score {score})
          </div>
          {signals.length > 0 ? (
            <ul style={{ margin: 0, padding: 0, listStyle: "none" }}>
              {signals.map((sig) => {
                const parts = reason.split(" · ");
                const i = signals.indexOf(sig);
                const text = parts[i] ?? prettySignal(sig);
                return (
                  <li key={sig} style={{ padding: "2px 0" }}>
                    <span style={{ color: s.fg, marginRight: 6 }}>•</span>
                    <span style={{ color: "#8892a0", marginRight: 6 }}>
                      {prettySignal(sig)}:
                    </span>
                    {text}
                  </li>
                );
              })}
            </ul>
          ) : (
            <div style={{ color: "#556066" }}>{reason || "(no reason)"}</div>
          )}
          <div style={{ marginTop: 6, color: "#556066", fontSize: 10 }}>
            feed paused while hovering
          </div>
        </div>
      )}
    </HoverPause>
  );
}
