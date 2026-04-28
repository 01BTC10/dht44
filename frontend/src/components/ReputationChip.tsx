import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { HoverPause } from "./HoverPause";

/* Shape matches the daemon's `reputation` JSON object: the keys are
 * source names ("iblocklist", "tor", "greynoise") and each value carries
 * at least a `label`. */
export type RepEntry = { label: string; queried_at?: number };
export type Reputation = Record<string, RepEntry>;

/* Visual taxonomy. Mirrors http_ws.c's classify_peer:
 *   strong (red)   — anti-P2P, bogons, honeypots, hijacks; +3 score
 *   benign (green) — GreyNoise: known research scanner; 0 score
 *   tor (purple)   — Tor exit; +1 score
 *   info (grey)    — generic blocklist hit; 0 score */
type Tone = "strong" | "benign" | "tor" | "info";

const STRONG_PREFIXES = [
  "AP2P", "Anti-P2P", "Bogon", "Honeypot",
  "Hijacked", "Spider", "Brute Force", "Spambot",
];
const OPERATOR_NEEDLES = [
  "markmonitor", "ip-echelon", "ip echelon", "irdeto", "nagra",
  "friend mts", "opsec", "ceg tek", "rightscorp", "excipio",
  "trident media guard", "tmg",
  "bayshore", "media protector", "antipiracy", "anti-piracy",
  "swarm", "honeyswarm",
];

function toneFor(src: string, label: string): Tone {
  if (src === "tor") return "tor";
  if (src === "greynoise") {
    if (label.startsWith("malicious")) return "strong";
    if (label.startsWith("benign"))    return "benign";
    return "info";
  }
  if (src === "iblocklist") {
    if (STRONG_PREFIXES.some(p => label.startsWith(p))) return "strong";
    const L = label.toLowerCase();
    if (OPERATOR_NEEDLES.some(n => L.includes(n)))      return "strong";
    return "info";
  }
  return "info";
}

const PALETTE: Record<Tone, { bg: string; fg: string; border: string }> = {
  strong: { bg: "#3a1a22", fg: "#ff9bb5", border: "#562a36" },
  benign: { bg: "#1a2f1a", fg: "#9be0a8", border: "#264a26" },
  tor:    { bg: "#2a1a3a", fg: "#c8a8e8", border: "#412a5a" },
  info:   { bg: "#1d2530", fg: "#a0a8b0", border: "#2a3642" },
};

/* Short visible text. The chip lives in a `td { white-space: nowrap;
 * overflow: hidden; text-overflow: ellipsis }` cell on the Peers page
 * so we keep it under ~12 chars. The full source:label rides in the
 * portal popup. */
function shortText(src: string, label: string, tone: Tone): string {
  if (src === "tor") return "tor exit";
  if (src === "greynoise") {
    if (label.startsWith("benign:")) return "gn:" + label.slice(7);
    if (label === "malicious")        return "gn:mal";
    if (label === "suspicious")       return "gn:susp";
    return "gn:" + label.slice(0, 6);
  }
  if (src === "iblocklist") {
    if (tone === "strong") return "anti-P2P";
    return "blocklist";
  }
  return src;
}

const POP_W = 280;
const POP_GAP = 6;
const CLOSE_DELAY_MS = 250;

let activeClose: (() => void) | null = null;

export default function ReputationChip(
  { source, entry }: { source: string; entry: RepEntry },
) {
  const tone = toneFor(source, entry.label);
  const colors = PALETTE[tone];
  const text = shortText(source, entry.label, tone);

  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number; placement: "below" | "above" } | null>(null);
  const ref = useRef<HTMLSpanElement | null>(null);
  const closeTimer = useRef<number | null>(null);

  /* Stable per-instance closer; same lifecycle pattern as CrawlerBadge. */
  const myCloser = useRef<() => void>();
  if (!myCloser.current) {
    myCloser.current = () => {
      if (closeTimer.current != null) {
        window.clearTimeout(closeTimer.current);
        closeTimer.current = null;
      }
      setOpen(false);
      if (activeClose === myCloser.current) activeClose = null;
    };
  }
  const cancelClose = () => {
    if (closeTimer.current != null) {
      window.clearTimeout(closeTimer.current);
      closeTimer.current = null;
    }
  };
  const requestOpen = () => {
    cancelClose();
    if (activeClose && activeClose !== myCloser.current) activeClose();
    activeClose = myCloser.current!;
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
  useEffect(() => () => {
    cancelClose();
    if (activeClose === myCloser.current) activeClose = null;
  }, []);

  useLayoutEffect(() => {
    if (!open || !ref.current) {
      if (pos !== null) setPos(null);
      return;
    }
    const r = ref.current.getBoundingClientRect();
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    const left = Math.min(Math.max(8, r.left), vw - POP_W - 8);
    const placement: "below" | "above" = vh - r.bottom < 140 ? "above" : "below";
    const top = placement === "below" ? r.bottom + POP_GAP : r.top - POP_GAP;
    if (!pos || pos.top !== top || pos.left !== left || pos.placement !== placement) {
      setPos({ top, left, placement });
    }
  });

  const since = entry.queried_at
    ? Math.max(0, Math.floor(Date.now() / 1000 - entry.queried_at))
    : null;
  const sinceStr = since == null ? null
    : since < 60   ? `${since}s ago`
    : since < 3600 ? `${Math.floor(since / 60)}m ago`
    : since < 86400 ? `${Math.floor(since / 3600)}h ago`
    : `${Math.floor(since / 86400)}d ago`;

  return (
    <HoverPause style={{ marginLeft: 6, display: "inline-block" }}>
      <span ref={ref}
            onMouseEnter={requestOpen}
            onMouseLeave={requestClose}
            style={{
              background: colors.bg, color: colors.fg,
              border: `1px solid ${colors.border}`,
              borderRadius: 3, padding: "1px 6px",
              fontSize: 10, lineHeight: "14px",
              cursor: "default", verticalAlign: "middle",
              whiteSpace: "nowrap",
            }}>
        {text}
      </span>
      {open && pos && createPortal(
        <div style={{
          position: "fixed",
          top: pos.top, left: pos.left,
          transform: pos.placement === "above" ? "translateY(-100%)" : undefined,
          zIndex: 9999, width: POP_W,
          background: "#0f1316",
          border: `1px solid ${colors.border}`, borderRadius: 3,
          padding: "8px 10px", color: "#d8dee6",
          fontSize: 11, lineHeight: 1.5,
          boxShadow: "0 4px 12px rgba(0,0,0,0.6)",
          whiteSpace: "normal",
          /* CrawlerBadge note: the popup must not steal pointer events
           * — keeps the chip underneath responsive when the cursor
           * moves over it. */
          pointerEvents: "none",
        }}>
          <div style={{ color: colors.fg, fontWeight: 600,
                        marginBottom: 4, textTransform: "uppercase",
                        letterSpacing: 0.5, fontSize: 10 }}>
            {source}
          </div>
          <div style={{ wordBreak: "break-word" }}>{entry.label}</div>
          {sinceStr && (
            <div style={{ marginTop: 6, color: "#556066", fontSize: 10 }}>
              queried {sinceStr}
            </div>
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
