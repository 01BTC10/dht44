import { Link } from "react-router-dom";
import SEO from "../components/SEO";
import ArticleLayout from "../components/ArticleLayout";

export default function LibLanding() {
  return (
    <>
      <SEO
        title="libbep44 — Embeddable BEP 44 / DHT C Library"
        description="A small async C library: bep44_open / put / get plus key management. Hides the DHT engine behind a clean API. MIT, libsodium, ~1500 LOC."
        path="/lib"
        type="article"
      />
      <ArticleLayout
        crumbs={[{ label: "Home", to: "/intro" }, { label: "Library" }]}
        title="libbep44"
        lede="A small async C library that embeds the BitTorrent Mainline DHT and BEP 44 mutable + immutable items into your program. You bring the event loop; the library brings the network."
      >
        <h2>At a glance</h2>
        <pre><code className="language-c">{`bep44_opts_t opts = {
    .port = 6881,
    .state_dir = "./state",
    .bootstrap_routers = 1,
    .use_upnp = 1,
    .republish_minutes = 60,
};
bep44_ctx_t *ctx = bep44_open(&opts);
bep44_keypair_t kp; bep44_keygen(&kp);
bep44_put_mutable(ctx, &kp, NULL, 0, 1, -1,
                  (uint8_t *)"5:hello", 7, on_put, NULL);
while (running) bep44_step(ctx, 250);
bep44_close(ctx);`}</code></pre>

        <h2>Read on</h2>
        <dl className="ref-list">
          <dt><Link to="/lib/quickstart">Quickstart</Link></dt>
          <dd>End-to-end working example, copy-pastable.</dd>

          <dt><Link to="/lib/api">API reference</Link></dt>
          <dd>Every public function: signature, description, example, errors.</dd>

          <dt><Link to="/lib/persistence">Persistence and republish</Link></dt>
          <dd>Why BEP 44 items expire after ~2h, and how the library handles it.</dd>
        </dl>

        <h2>What you get</h2>
        <ul>
          <li><strong>Full DHT engine, hidden.</strong> The library binds the UDP socket, runs the Kademlia routing table, drives iterative lookups, and parses KRPC. You never see those.</li>
          <li><strong>Inbound serving.</strong> Your node responds to other peers' <code>get</code>/<code>put</code> queries — full BEP 44 server, signature-verified, seq + CAS enforced.</li>
          <li><strong>Auto-republish</strong> every 60 minutes (configurable) so your value doesn't age out of peer caches.</li>
          <li><strong>UPnP IGD</strong> port mapping (best-effort, opt-in).</li>
          <li><strong>Tiny dependency surface:</strong> libsodium, OpenSSL, jansson, miniupnpc.</li>
          <li><strong>~1500 LOC</strong> excluding the vendored <code>jech/dht</code> Kademlia substrate.</li>
        </ul>

        <h2>Source</h2>
        <p>
          <a href="https://github.com/01BTC10/dht44/tree/libbep44">github.com/01BTC10/dht44 — <code>libbep44</code> branch</a>.
          MIT licensed.
        </p>
      </ArticleLayout>
    </>
  );
}
