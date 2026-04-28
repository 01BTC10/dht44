import { useEffect, useRef, useState } from "react";
import { stream, fmtTs } from "../ws";
import { usePaused } from "../components/HoverPause";

type Row = {
  target: string;
  mutable: number;
  pk: string | null;
  salt: string | null;
  seq: number;
  sig: string | null;
  v: string | null;
  first_seen: number; last_seen: number;
};

/* If `v` is a bencoded UTF-8 string ("<len>:<content>") and the
 * content is fully printable, return the decoded text. Otherwise
 * null — caller falls back to hex. Bencoded ints/lists/dicts also
 * fall through. */
function tryDecodeBencodeString(hexStr: string | null): string | null {
  if (!hexStr || hexStr.length === 0 || hexStr.length % 2 !== 0) return null;
  const bytes = new Uint8Array(hexStr.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    const b = parseInt(hexStr.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(b)) return null;
    bytes[i] = b;
  }
  let colon = -1;
  for (let i = 0; i < Math.min(bytes.length, 12); i++) {
    if (bytes[i] === 0x3a) { colon = i; break; }
    if (bytes[i] < 0x30 || bytes[i] > 0x39) return null;
  }
  if (colon <= 0) return null;
  const lenStr = new TextDecoder().decode(bytes.slice(0, colon));
  const len = parseInt(lenStr, 10);
  if (!Number.isFinite(len) || len !== bytes.length - colon - 1) return null;
  try {
    const s = new TextDecoder("utf-8", { fatal: true }).decode(bytes.slice(colon + 1));
    if (/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(s)) return null;
    return s;
  } catch {
    return null;
  }
}

export default function Bep44() {
  const [rows, setRows] = useState<Row[]>([]);
  const paused = usePaused();
  const pausedRef = useRef(paused);
  pausedRef.current = paused;
  useEffect(() => {
    fetch("/api/bep44?limit=500").then(r => r.json()).then(setRows).catch(() => {});
    return stream.subscribe((topic, data) => {
      if (topic !== "bep44" || pausedRef.current) return;
      const d: any = data;
      const r: Row = {
        target: d.target, mutable: d.mutable, pk: d.pk, salt: d.salt,
        seq: d.seq, sig: d.sig, v: d.v,
        first_seen: d.ts, last_seen: d.ts,
      };
      setRows(prev => {
        const idx = prev.findIndex(x => x.target === r.target);
        if (idx >= 0) { const c = prev.slice(); c[idx] = r; return c; }
        return [r, ...prev].slice(0, 500);
      });
    });
  }, []);

  /* Override the default <td> truncation for the hex columns: the
   * target hash is the addressable identity of an item and gets cited
   * verbatim by other tools (curl, dht44 get --target ...), so showing
   * the full 40-char hex is more useful than ellipsizing. Public keys
   * (32 bytes / 64 hex chars) get the same treatment. The `v` column
   * tries to render printable bencoded strings as plaintext with the
   * raw hex available on hover. */
  const cellHexFull: React.CSSProperties = {
    maxWidth: "none",
    whiteSpace: "normal",
    wordBreak: "break-all",
    fontFamily: "ui-monospace, SFMono-Regular, monospace",
    fontSize: 11,
    color: "#8892a0",
  };

  return (
    <table>
      <thead>
        <tr>
          <th>target</th>
          <th>mut</th>
          <th>pk</th>
          <th>seq</th>
          <th>v</th>
          <th>last</th>
        </tr>
      </thead>
      <tbody>
        {rows.map(r => {
          const decodedV = tryDecodeBencodeString(r.v);
          return (
            <tr key={r.target}>
              <td style={cellHexFull}>{r.target}</td>
              <td>{r.mutable ? "✓" : ""}</td>
              <td style={cellHexFull}>{r.pk || ""}</td>
              <td>{r.mutable ? r.seq : ""}</td>
              <td style={cellHexFull}>
                {decodedV != null ? (
                  <span title={r.v ?? ""} style={{ color: "#8fc0ff" }}>
                    "{decodedV}"
                  </span>
                ) : (
                  r.v || ""
                )}
              </td>
              <td>{fmtTs(r.last_seen)}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
