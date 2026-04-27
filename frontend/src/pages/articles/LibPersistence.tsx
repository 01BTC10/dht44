import { Link } from "react-router-dom";
import SEO from "../../components/SEO";
import ArticleLayout from "../../components/ArticleLayout";
import { techArticle } from "./_helpers";

const PATH = "/lib/persistence";
const TITLE = "Persistence and Republish in libbep44";
const DESC = "Why BEP 44 items expire from peer caches after ~2 hours, what state_dir holds, and how libbep44's republish loop keeps your value alive without you doing anything.";

export default function LibPersistence() {
  return (
    <>
      <SEO
        title={TITLE} description={DESC} path={PATH} type="article"
        jsonLd={techArticle(PATH, TITLE, DESC,
          "bep 44, republish, libbep44, bittorrent dht, expiry, persistence, upnp")}
      />
      <ArticleLayout
        crumbs={[
          { label: "Home", to: "/" },
          { label: "Library", to: "/lib" },
          { label: "Persistence" },
        ]}
        title={TITLE}
        lede="BEP 44 items don't live on the network forever. This page explains the storage lifetime, what libbep44 persists locally, and how the built-in republish loop covers the gap."
      >
        <h2>The 2-hour expiry, in one paragraph</h2>
        <p>
          When you publish a BEP 44 item, it's stored on the 8 peers in
          the network closest to its target hash by XOR distance.
          Those storers cache it for about <strong>2 hours</strong> and
          then drop it unless somebody re-pushes the same value. If you
          publish once and then sleep for 3 hours, your value is gone
          from the network — even though the publisher's process is
          still up. This is how the protocol limits storage abuse.
        </p>

        <h2>Two consequences</h2>
        <ol>
          <li><strong>Put-then-immediate-get from a different process is
            unreliable.</strong> The 8 peers your put hit may not be in
            the get's freshly-bootstrapped routing table, so the
            lookup converges elsewhere. (You'll see "stored on 15
            nodes" then "not found" from a separate process. This is
            normal.)</li>
          <li><strong>Long-lived publication needs a long-lived
            process.</strong> Whoever wants their value to stay
            reachable has to keep re-pushing it.</li>
        </ol>

        <h2>What libbep44 does for you</h2>
        <p>The library handles both consequences automatically:</p>
        <ul>
          <li>Every put — yours via{" "}
            <Link to="/lib/api#bep44_put_mutable"><code>bep44_put_mutable</code></Link>{" "}
            and{" "}
            <Link to="/lib/api#bep44_put_immutable"><code>bep44_put_immutable</code></Link>,
            and any peer-origin put your inbound server accepts — is
            persisted to <code>state_dir/items/&lt;target&gt;.json</code>.</li>
          <li>Every <code>republish_minutes</code> (default 60) the
            library walks that directory and re-issues each item's
            put. For peer-origin items it re-emits the stored signed
            bytes verbatim, so no key access is needed.</li>
          <li>For self-origin items it does the same — the signature
            you made at put-time is still valid because the seq,
            value, and salt didn't change.</li>
        </ul>

        <h2>Tuning notes</h2>
        <ul>
          <li>The default of 60 minutes is intentionally well below
            the ~2-hour peer expiry. Going lower than ~15 min is
            wasteful; going above 90 min flirts with the expiry
            window.</li>
          <li>Set <code>opts.republish_minutes = -1</code> to opt out
            (e.g. you're going to call <code>bep44_put_*</code>{" "}
            yourself on a custom schedule with bumped seq).</li>
          <li><strong>You must keep your process running and calling{" "}
            <Link to="/lib/api#bep44_step"><code>bep44_step</code></Link>.</strong>{" "}
            A short-lived <code>--put</code>-then-exit publishes
            once and leaves no agent behind. If that's your pattern,
            plan to invoke the publisher again before 2h pass — or
            run a long-lived agent (snippet below).</li>
        </ul>

        <h2>Long-lived publisher</h2>
        <pre><code>{`bep44_opts_t opts = {
    .port = 6881,
    .state_dir = "./state",
    .bootstrap_routers = 1,
    .use_upnp = 1,
    .republish_minutes = 60,
};
bep44_ctx_t *ctx = bep44_open(&opts);

/* Publish once. */
bep44_keypair_t kp;     /* loaded or generated */
bep44_put_mutable(ctx, &kp, NULL, 0, 1, -1,
                  (uint8_t *)"5:hello", 7, on_put, NULL);

/* Drive the loop forever. The library republishes every 60 min on
 * its own; you don't have to call put again. */
while (running) bep44_step(ctx, 250);`}</code></pre>
        <p>
          The republish sweep runs at most 4 lookups concurrently per
          cycle, so holding many items doesn't burst the network —
          large collections spread across a few seconds.
        </p>

        <h2>State directory layout</h2>
        <p>The <code>state_dir</code> you pass to <code>bep44_open</code> accumulates:</p>
        <ul>
          <li><code>node_id.bin</code> — 20-byte persistent DHT node ID.
            Generated on first open and never rotated. Deleting it
            makes you a different node to the rest of the network and
            discards all your routing-table presence.</li>
          <li><code>nodes.bin</code> — compact IPv4 node list saved on
            close. On the next <code>bep44_open</code> these are
            inserted as warm-bootstrap peers, so a restart converges
            faster.</li>
          <li><code>items/&lt;40-hex-target&gt;.json</code> — items
            other peers asked you to store, plus any items you've put
            yourself. The library serves these to inbound{" "}
            <code>get</code> queries from other peers (full BEP 44
            server, sig + seq + CAS validated) and uses them to honor
            CAS / seq invariants on inbound puts.</li>
        </ul>

        <h3>Item file format</h3>
        <p>Mutable example (binary fields are hex-encoded JSON):</p>
        <pre><code>{`{
  "mutable": true,
  "origin": "self",
  "pk":  "ce8526ccda8d5a3f487df0d38ff355b2667cea2832df027603c7a00a832ac1e4",
  "seq": 1777252270,
  "sig": "a0958aa6296319be5ac7421b0577c19a3075dc3cba28f4a91e814719f4ced06f...",
  "v":   "31393a68656c6c6f2d66726f6d2d6c69626265703434"
}`}</code></pre>
        <p>
          The <code>v</code> field stores the BENCODED form (e.g.
          <code>5:hello</code> as hex), not the raw value. This is
          required for the get-response builder which re-emits the
          bytes verbatim. The format is intentionally human-readable
          for debugging — <code>jq .</code> works.
        </p>

        <h3>Origin field</h3>
        <ul>
          <li><code>"self"</code> — you put it via libbep44.</li>
          <li><code>"peer"</code> — another peer put it through your
            inbound server. You re-publish these too because you might
            be one of the 8 closest storers and dropping your copy
            would shrink the storer set.</li>
        </ul>

        <h2>NAT traversal (UPnP)</h2>
        <p>
          If you're behind a NAT — typical home or office machine —
          your node can reach the public DHT outbound but other peers
          can't reach you inbound. That means:
        </p>
        <ul>
          <li><strong>Your puts still work</strong> (outbound).</li>
          <li><strong>Peers can't ask you for what you've stored</strong>{" "}
            (inbound). You don't show up in others' routing tables
            long-term, can't serve as a storer for arbitrary peer
            items, and your own value lives only on the original 8
            closest peers (with the usual ~2h expiry).</li>
        </ul>
        <p>
          Set <code>opts.use_upnp = 1</code> and the library asks your
          gateway to forward your UDP port via UPnP IGD on open,
          refreshes the lease every <code>upnp_lifetime_sec / 2</code>,
          and tears the mapping down on{" "}
          <Link to="/lib/api#bep44_close"><code>bep44_close</code></Link>.
          Failures (no IGD, IGD refused) are logged and non-fatal.
        </p>
        <p>UPnP only works when:</p>
        <ul>
          <li>Your gateway has UPnP enabled (most home routers do; many corporate networks don't).</li>
          <li>You passed a fixed <code>opts.port</code> (UPnP needs a known external port).</li>
          <li>libminiupnpc is linked (it is by default in the Makefile).</li>
        </ul>

        <h2>If UPnP fails</h2>
        <p>
          Options: configure a manual port forward on your router, run
          on a public IP, or accept that you work as an outbound-only
          client (your puts still propagate via the 8 chosen storers).
        </p>

        <h2>See also</h2>
        <ul>
          <li><Link to="/protocol/bep44">BEP 44 in depth</Link> — the
            wire format and why republish-on-the-publisher is the
            only mechanism for long-lived storage.</li>
          <li><Link to="/blog/embed-dht-c-app">Embedding a DHT in your C app</Link>{" "}
            — the long-lived-process story for real applications.</li>
          <li><Link to="/lib/api">API reference</Link> — exact function
            signatures and error codes.</li>
        </ul>
      </ArticleLayout>
    </>
  );
}
