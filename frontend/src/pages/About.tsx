import SEO from "../components/SEO";
import ArticleLayout from "../components/ArticleLayout";

export default function About() {
  return (
    <>
      <SEO
        title="About dht44 — Kademlia DHT Research Toolkit in C"
        description="dht44 is a C implementation of the BitTorrent Mainline DHT (BEP 5) and BEP 44 mutable items, with a live crawler dashboard. MIT licensed, no SaaS."
        path="/about"
        type="article"
      />
      <ArticleLayout
        crumbs={[{ label: "Home", to: "/" }, { label: "About" }]}
        title="About dht44"
        lede="An open-source toolkit for the BitTorrent Mainline DHT, written in C and MIT licensed."
      >
        <h2>What it provides</h2>
        <ul>
          <li>
            <strong>dht44</strong>: a CLI plus long-running daemon for storing
            and retrieving BEP 44 items (mutable + immutable) on the live
            Mainline DHT.
          </li>
          <li>
            <strong>libbep44</strong>: an embeddable static C library that
            exposes the same DHT engine behind a small async API
            (<code>bep44_open</code>, <code>bep44_step</code>,
            <code>bep44_put_*</code>, <code>bep44_get_*</code> plus key
            management). Lives on the <code>libbep44</code> branch.
          </li>
          <li>
            <strong>Live crawler dashboard</strong>: a React frontend served by
            the daemon, watching every observed packet and classifying peers
            (crawler / monitor / honeypot / ok).
          </li>
        </ul>

        <h2>Built on</h2>
        <ul>
          <li><a href="https://github.com/jech/dht">jech/dht</a> (vendored at <code>vendor/jech-dht/</code>) — BEP 5 routing table and base DHT engine, MIT licensed.</li>
          <li><a href="https://libsodium.org/">libsodium</a> for Ed25519, OpenSSL EVP for SHA-1.</li>
          <li><a href="http://miniupnp.free.fr/">libminiupnpc</a> for NAT traversal.</li>
          <li><a href="https://digip.org/jansson/">jansson</a> for JSON, <a href="https://www.sqlite.org/">sqlite3</a> for the observation store.</li>
          <li><a href="https://libwebsockets.org/">libwebsockets</a> for the HTTP + WebSocket server.</li>
        </ul>

        <h2>Author and contact</h2>
        <p>
          Tayaout Labelle-Kuberek — <a href="mailto:tayaoutlk@gmail.com">tayaoutlk@gmail.com</a>.
          Source code at <a href="https://github.com/01BTC10/dht44">github.com/01BTC10/dht44</a>.
        </p>

        <h2>Design goals</h2>
        <ul>
          <li><strong>Minimal dependencies.</strong> A clean Arch box runs the daemon out of the standard repos — <code>libsodium</code>, <code>openssl</code>, <code>miniupnpc</code>, <code>jansson</code>, plus <code>sqlite</code>/<code>libwebsockets</code>/<code>libmaxminddb</code> for the crawler.</li>
          <li><strong>No telemetry from the daemon.</strong> The C process talks to the public DHT and nothing else.</li>
          <li><strong>Honest about what's hard.</strong> The protocol explainers cover the gotchas — strict bencode key ordering, BEP 44 signable bytes with no outer dict, the ~2h republish window — that bit prior implementations.</li>
        </ul>

        <h2>License</h2>
        <p>
          MIT — see <a href="https://github.com/01BTC10/dht44/blob/main/LICENSE">LICENSE</a>.
          The vendored copy of <code>jech/dht</code> retains its upstream MIT license.
        </p>
      </ArticleLayout>
    </>
  );
}
