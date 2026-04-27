import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
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

const POP_W = 360;
const POP_GAP = 6;

// Delay before closing the popup after the cursor leaves both the badge
// and the popup itself. Lets the cursor traverse the 6px gap between
// them without flicker, and absorbs micro-jitter on re-render. Bumped
// from 140 → 250 ms because filter-driven re-flows of the table can
// briefly leave the cursor outside the badge's new bounds.
const CLOSE_DELAY_MS = 250;

// Module-level singleton: only one badge popup is ever open. When a
// new badge opens, it calls the previous one's close handler. This
// prevents stale popups from previous hovers sticking around when
// the cursor moves to a new badge or live refreshes change the
// rendered set of rows.
let activeClose: (() => void) | null = null;

export function CrawlerBadge(
  { cls, score, signals, reason }:
  { cls: CrawlerClass; score: number; signals: string[]; reason: string },
) {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number; placement: "below" | "above" } | null>(null);
  const badgeRef = useRef<HTMLSpanElement | null>(null);
  const closeTimer = useRef<number | null>(null);
  // Per-instance closer — captured by ref so the singleton can call it
  // without going through React state. Always points at the latest
  // close logic (cancelClose + setOpen(false) + clearActive).
  const myCloser = useRef<() => void>(() => {});

  const cancelClose = () => {
    if (closeTimer.current != null) {
      window.clearTimeout(closeTimer.current);
      closeTimer.current = null;
    }
  };

  // Re-bind the closer every render (closes over current setOpen).
  myCloser.current = () => {
    cancelClose();
    setOpen(false);
    if (activeClose === myCloser.current) activeClose = null;
  };

  const requestOpen  = () => {
    cancelClose();
    // If a different badge is currently open, close it first. This is
    // the singleton enforcement: at most one popup visible.
    if (activeClose && activeClose !== myCloser.current) activeClose();
    activeClose = myCloser.current;
    setOpen(true);
  };
  const requestClose = () => {
    cancelClose();
    closeTimer.current = window.setTimeout(() => {
      setOpen(false);
      closeTimer.current = null;
      if (activeClose === myCloser.current) activeClose = null;
    }, CLOSE_DELAY_MS);
  };

  // Cleanup on unmount — important because the popup is portaled to
  // document.body and would outlive a row that gets removed by a live
  // refresh otherwise. Also surrender the singleton so a freshly-mounted
  // badge can claim it.
  useEffect(() => () => {
    cancelClose();
    if (activeClose === myCloser.current) activeClose = null;
  }, []);

  // Re-measure the popup position on every render while open. The
  // table re-renders every 5s under live updates; even with same-key
  // reconciliation, the badge's DOM rect can shift if rows above it
  // change height. Without re-measure, the popup ends up detached
  // from the badge after the first refresh. The setPos guard avoids
  // a render loop when the rect didn't actually change.
  useLayoutEffect(() => {
    if (!open || !badgeRef.current) {
      if (pos !== null) setPos(null);
      return;
    }
    const r = badgeRef.current.getBoundingClientRect();
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    const left = Math.min(Math.max(8, r.left), vw - POP_W - 8);
    const spaceBelow = vh - r.bottom;
    const placement: "below" | "above" = spaceBelow < 200 ? "above" : "below";
    const top = placement === "below" ? r.bottom + POP_GAP : r.top - POP_GAP;
    if (!pos || pos.top !== top || pos.left !== left || pos.placement !== placement) {
      setPos({ top, left, placement });
    }
  });

  if (cls === "ok") return null;
  const s = STYLES[cls];

  return (
    <HoverPause style={{ marginLeft: 6, display: "inline-block" }}>
      <span
        ref={badgeRef}
        onMouseEnter={requestOpen}
        onMouseLeave={requestClose}
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
      {open && pos && createPortal(
        <div
          onMouseEnter={requestOpen}
          onMouseLeave={requestClose}
          style={{
            position: "fixed",
            top: pos.top,
            left: pos.left,
            transform: pos.placement === "above" ? "translateY(-100%)" : undefined,
            zIndex: 9999,
            width: POP_W,
            background: "#0f1316",
            border: `1px solid ${s.border}`,
            borderRadius: 3,
            padding: "8px 10px",
            color: "#d8dee6",
            fontSize: 11,
            lineHeight: 1.5,
            boxShadow: "0 4px 12px rgba(0,0,0,0.6)",
            whiteSpace: "normal",
            pointerEvents: "auto",
          }}
        >
          <div style={{ color: s.fg, fontWeight: 600, marginBottom: 4 }}>
            {s.label.replace("?", "")} (score {score})
          </div>
          {signals.length > 0 ? (
            <ul style={{ margin: 0, padding: 0, listStyle: "none" }}>
              {signals.map((sig, i) => {
                const parts = reason.split(" · ");
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
        </div>,
        document.body,
      )}
    </HoverPause>
  );
}
