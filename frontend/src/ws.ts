type Listener = (topic: string, data: any) => void;

export class Stream {
  private ws: WebSocket | null = null;
  private listeners: Listener[] = [];
  private connected = false;
  onStatus: (up: boolean) => void = () => {};

  constructor(private url: string) { this.connect(); }

  private connect() {
    try {
      this.ws = new WebSocket(this.url, "dht44-stream");
    } catch {
      setTimeout(() => this.connect(), 2000);
      return;
    }
    this.ws.onopen    = () => { this.connected = true; this.onStatus(true); };
    this.ws.onclose   = () => {
      this.connected = false; this.onStatus(false);
      setTimeout(() => this.connect(), 2000);
    };
    this.ws.onerror   = () => { this.ws?.close(); };
    this.ws.onmessage = (ev) => {
      try {
        const m = JSON.parse(ev.data);
        if (m && m.topic) this.listeners.forEach(l => l(m.topic, m.data));
      } catch {}
    };
  }

  subscribe(l: Listener) {
    this.listeners.push(l);
    return () => { this.listeners = this.listeners.filter(x => x !== l); };
  }

  isConnected() { return this.connected; }
}

export const stream = new Stream(
  (location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/stream"
);

export function fmtTs(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString();
}
export function hex(s: string | null | undefined, n = 16): string {
  if (!s) return "";
  return s.slice(0, n) + (s.length > n ? "…" : "");
}
export function decodeVString(hex: string | null | undefined): string {
  if (!hex || hex.length !== 8) return "";
  let s = "";
  let name = "";
  for (let i = 0; i < 8; i += 2) {
    const c = parseInt(hex.slice(i, i + 2), 16);
    s += c >= 32 && c < 127 ? String.fromCharCode(c) : ".";
  }
  name = s.slice(0, 2);
  const ver = parseInt(hex.slice(4), 16);
  const known: Record<string, string> = {
    "LT": "libtorrent", "UT": "µTorrent", "qB": "qBittorrent",
    "TR": "Transmission", "DH": "dht44", "JB": "jech-dht",
    "Az": "Azureus", "BI": "BitComet", "BX": "BittorrentX",
    "AZ": "Azureus", "BF": "BitFlu",
  };
  const label = known[name] || s;
  return `${label} ${ver}`;
}
