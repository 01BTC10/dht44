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
export function countryFlag(iso2: string | null | undefined): string {
  if (!iso2 || iso2.length !== 2) return "";
  const code = iso2.toUpperCase();
  // Skip non-letters (some GeoIP rows carry "XX", "EU", etc. which still
  // map to something; let the caller decide whether to render).
  const a = code.charCodeAt(0), b = code.charCodeAt(1);
  if (a < 65 || a > 90 || b < 65 || b > 90) return "";
  const OFFSET = 0x1f1e6 - 65;
  return String.fromCodePoint(a + OFFSET, b + OFFSET);
}

const regionNames: Intl.DisplayNames | null =
  typeof Intl !== "undefined" && (Intl as any).DisplayNames
    ? new Intl.DisplayNames(["en"], { type: "region" })
    : null;

export function countryName(iso2: string | null | undefined): string {
  if (!iso2) return "";
  try {
    return regionNames?.of(iso2.toUpperCase()) ?? iso2;
  } catch {
    return iso2;
  }
}

/* BEP 20 / de-facto client id prefixes.
 * Sources: https://wiki.theory.org/BitTorrent/Client_Peer_ID_Convention
 * + empirical v-strings observed on Mainline DHT.
 * Case matters: libtorrent-rasterbar uses "LT" (caps), rTorrent uses "lt". */
const KNOWN_CLIENTS: Record<string, string> = {
  /* --- capitalized (BEP 20 registry + common de-facto) --- */
  "A2": "aria2",
  "AG": "Ares",
  "AR": "Arctic",
  "AT": "Artemis",
  "AV": "Avicora",
  "AX": "BitPump",
  "AZ": "Azureus", "Az": "Azureus",
  "BB": "BitBuddy",
  "BC": "BitComet", "BI": "BitComet", "BL": "BitCometLite",
  "BF": "BitFlu", "BT": "BitTorrent", "Bt": "BitTorrent",
  "BN": "Baidu Netdisk",
  "BS": "BTSlave",
  "BX": "BittorrentX",
  "CD": "Enhanced CTorrent",
  "CT": "CTorrent",
  "DE": "Deluge",
  "DH": "dht44",
  "DP": "Propagate Data Client",
  "EB": "EBit",
  "ES": "electric sheep",
  "FC": "FileCroc", "FL": "Folx", "FX": "Freebox BT",
  "G3": "G3 Torrent", "GR": "GetRight", "GS": "GSTorrent",
  "HK": "Hekate", "HL": "Halite", "HN": "Hydranode",
  "JB": "jech-dht",
  "KG": "KGet", "KN": "KTorrent-Net?", "KT": "KTorrent",
  "LC": "LeechCraft",
  "LH": "LH-ABC", "LP": "Lphant", "LT": "libtorrent",
  "LW": "LimeWire",
  "MG": "MediaGet",
  "MK": "Meerkat", "ML": "MLdonkey", "MO": "MonoTorrent",
  "MP": "MooPolice", "MR": "Miro", "MT": "MoonlightTorrent",
  "NB": "Net BitTorrent", "NE": "BT Next Evolution",
  "NP": "BitTorrent Next Pro", "NX": "Net Transport",
  "OS": "OneSwarm", "OT": "OmegaTorrent",
  "PD": "Pando", "PI": "PicoTorrent",
  "qB": "qBittorrent", "QD": "QQDownload", "QT": "Qt4 Torrent",
  "RT": "Retriever", "RZ": "RezTorrent",
  "S~": "Shareaza (alpha/beta)",
  "SB": "SwiftBit", "SD": "Xunlei", "SM": "SoMud",
  "SS": "SwarmScope", "ST": "SharkTorrent", "SZ": "Shareaza",
  "TB": "Torch",
  "TL": "Tribler",
  "TN": "TorrentDotNET", "TR": "Transmission", "TS": "TorrentStorm",
  "TT": "TuoTu", "TX": "Torrentix",
  "UE": "µTorrent Embedded", "UL": "uLeecher",
  "UM": "µTorrent Mac", "UT": "µTorrent", "UW": "µTorrent Web",
  "VG": "Vagaa",
  "WT": "BitLet", "WW": "WebTorrent", "WY": "FireTorrent",
  "XF": "Xfplay", "XL": "Xunlei", "XT": "XanTorrent", "XX": "XTorrent",
  "ZO": "Zona", "ZT": "ZipTorrent",

  /* --- lowercase variants (different client family conventions) --- */
  "lt": "rTorrent",          /* Jari Sundell's C++ client */
  "qb": "qBittorrent",
  "ml": "MLdonkey", "mL": "MLdonkey",
  "tr": "Transmission",
};

function printable(byte: number): string {
  return byte >= 32 && byte < 127 ? String.fromCharCode(byte) : ".";
}

/* Decode a bencode-KRPC `v` field (hex-encoded). Handles any byte length:
 *   - 4 bytes (the common case): "LT\x01\x00" → "libtorrent 256"
 *   - others: fall back to the best-effort printable form.
 * Unknown prefixes are rendered as raw-printable + version, e.g.
 *   "6c740d60" → "lt.` 3424"   (lt decodes to rTorrent now that it's in the map)
 *   "4b4e0000" → "KN.. 0"      (still unknown prefix; printable form shown)
 */
/* Render the "prefix" portion of an unknown v-string in the cleanest way.
 * - If both bytes are printable: "A2"      → "A2"
 * - If only first is printable:  [z, \0]   → "z"     (drop the NUL noise)
 * - If neither is printable:     [0xff,0x01] → "??"
 */
function prettyPrefix(bytes: number[]): string {
  const a = bytes[0], b = bytes[1];
  const pA = a >= 32 && a < 127;
  const pB = b >= 32 && b < 127;
  if (pA && pB) return String.fromCharCode(a, b);
  if (pA)       return String.fromCharCode(a);
  return "??";
}

export function decodeVString(hex: string | null | undefined): string {
  if (!hex || hex.length < 4 || hex.length % 2 !== 0) return "";
  const bytes: number[] = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.slice(i, i + 2), 16));
  }
  const ascii = bytes.map(printable).join("");
  const prefix2 = ascii.slice(0, 2);
  const label = KNOWN_CLIENTS[prefix2];

  if (bytes.length === 4) {
    const ver = (bytes[2] << 8) | bytes[3];
    return label ? `${label} ${ver}` : `${prettyPrefix(bytes)} ${ver}`;
  }
  if (bytes.length === 2) {
    return label || prettyPrefix(bytes);
  }
  // variable-length v (rare): show label + raw tail, or just the ASCII
  const tail = ascii.slice(2);
  return label ? `${label} ${tail}` : ascii;
}
