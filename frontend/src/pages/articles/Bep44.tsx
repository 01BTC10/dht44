import { Link } from "react-router-dom";
import SEO from "../../components/SEO";
import ArticleLayout from "../../components/ArticleLayout";
import { techArticle } from "./_helpers";

const PATH = "/protocol/bep44";
const TITLE = "BEP 44 Mutable & Immutable DHT Items, In Depth";
const DESC = "The full BEP 44 wire format: SHA1(pk‖salt) targeting, Ed25519 signing, sequence monotonicity, CAS, and republish — with sign/verify examples in C.";

export default function Bep44() {
  return (
    <>
      <SEO
        title={TITLE} description={DESC} path={PATH} type="article"
        jsonLd={techArticle(PATH, TITLE, DESC,
          "bep 44, bittorrent dht, mutable items, immutable items, ed25519, sha1, cas, sequence number, republish")}
      />
      <ArticleLayout
        crumbs={[
          { label: "Home", to: "/intro" },
          { label: "Protocol", to: "/protocol" },
          { label: "BEP 44" },
        ]}
        title={TITLE}
        lede="BEP 44 turns the BitTorrent DHT into a small key-value store: up to 1000 bytes per value, signed by Ed25519 (or unsigned and content-addressed). It's how clients publish self-issued metadata over the same routing table they already use for swarm discovery."
      >
        <h2>Two namespaces</h2>
        <dl>
          <dt>Immutable</dt>
          <dd>Target = <code>SHA1(v_bencoded)</code>. The value is
            self-authenticating — the only value that hashes to that
            target IS that value. Anyone can publish or retrieve;
            nobody can update.</dd>

          <dt>Mutable</dt>
          <dd>Target = <code>SHA1(public_key ‖ salt)</code>. Holder of
            the matching Ed25519 secret key can publish updates;
            others can verify because every value carries an
            attached signature. Updates are gated by a monotonically
            increasing 64-bit sequence number.</dd>
        </dl>

        <h2>The wire format</h2>

        <h3><code>get</code></h3>
        <p>
          Same shape as BEP 5's <code>get_peers</code>, with
          <code>target</code> instead of <code>info_hash</code>:
        </p>
        <pre><code>{`Q: d 1:a d 2:id 20:<our>
              6:target 20:<target>
              3:seq i<known-seq>e   (optional; only return if newer)
              4:want l 2:n4 2:n6 e
            e
          1:q 3:get
          1:t 2:aa
          1:y 1:q
        e

R-mutable:
   d 1:r d 2:id 20:<their>
              1:k    32:<pubkey>
              5:nodes <closer nodes>
              3:seq i<seq>e
              3:sig 64:<signature>
              5:token 8:<for subsequent put>
              1:v <bencoded value>
            e
            1:t 2:aa 1:y 1:r e

R-immutable: same but no k/seq/sig.

R-empty:
   d 1:r d 2:id 20:<their>
              5:nodes <closer nodes>
              5:token 8:<for subsequent put>
            e
            1:t 2:aa 1:y 1:r e`}</code></pre>

        <h3><code>put</code></h3>
        <p>
          For mutable items the <code>a</code> sub-dict is, in
          alphabetical order: <code>cas?, id, k, salt?, seq, sig,
          token, v</code>. (Notice <code>cas</code> sorts before
          <code>id</code> because lowercase 'c' &lt; 'i'.) For immutable
          items: <code>id, token, v</code>.
        </p>
        <pre><code>{`Q-mutable: d 1:a d
              3:cas i<expected-current-seq>e    (optional)
              2:id 20:<our>
              1:k 32:<pubkey>
              4:salt N:<salt>                    (optional, ≤ 64 B)
              3:seq i<new-seq>e
              3:sig 64:<signature>
              5:token 8:<from prior get>
              1:v <bencoded value>
            e
          1:q 3:put 1:t 2:aa 1:y 1:q
        e

R: d 1:r d 2:id 20:<their> e 1:t 2:aa 1:y 1:r e`}</code></pre>

        <h2>The signable bytes — easy to get wrong</h2>
        <p>
          The signature is over a specific concatenation of bencode
          key/value pairs, with <strong>no outer dict wrapper</strong>:
        </p>
        <pre><code>{`[4:salt<L>:<salt>] 3:seqi<seq>e 1:v<v_bencoded>`}</code></pre>
        <p>
          Notes that bite implementations:
        </p>
        <ul>
          <li>The <code>salt</code> section is omitted entirely when
            salt_len == 0 — not <code>4:salt0:</code>.</li>
          <li><code>v</code> is signed in its <em>bencoded</em> form. If
            your value is the string "hello", you sign over
            <code>1:v5:hello</code>, not <code>1:vhello</code>.</li>
          <li>There is NO outer <code>d ... e</code>. Just three
            (or two) bencode key/value pairs catenated. Easy to
            instinctively wrap a dict around them and produce a
            signature that nobody else's verifier accepts.</li>
        </ul>
        <p>
          dht44's <code>bep44_signable()</code> emits these bytes; the
          test suite verifies it byte-for-byte against a libtorrent
          reference vector.
        </p>

        <h2>Spec limits</h2>
        <ul>
          <li><strong>Value</strong>: 1000 bytes maximum (bencoded form).</li>
          <li><strong>Salt</strong>: 64 bytes maximum.</li>
          <li><strong>Signature</strong>: 64 bytes (Ed25519, fixed).</li>
          <li><strong>Public key</strong>: 32 bytes (Ed25519, fixed).</li>
          <li><strong>Sequence number</strong>: 64-bit signed integer,
            strictly increasing for updates. Initial value is implementation
            choice — Unix timestamps are common (one publish/sec ceiling
            for that key).</li>
        </ul>

        <h2>Compare-and-swap (<code>cas</code>)</h2>
        <p>
          Optional. The publisher includes <code>cas: N</code> meaning
          "only accept this update if the current stored seq equals N".
          A storer who has stored seq != N replies with{" "}
          <code>e: [301, "CAS mismatch"]</code> and rejects the put.
          Used to make atomic edits without races.
        </p>
        <p>
          Without <code>cas</code>, the only invariant is monotonicity:
          new_seq must be {`>`} stored_seq. Equal seq is rejected
          (err 302).
        </p>

        <h2>Storage lifetime</h2>
        <p>
          Storers expire items after roughly 2 hours unless re-published.
          BEP 44 doesn't specify the exact TTL; libtorrent uses 7200
          seconds, jech doesn't store at all (BEP 44 isn't its concern),
          dht44 follows libtorrent. A long-running publisher should
          re-issue the put every 60 minutes — see{" "}
          <Link to="/lib/persistence">persistence and republish</Link>.
        </p>

        <h2>BEP 44 error codes</h2>
        <p>Standard codes the spec defines:</p>
        <dl>
          <dt>201</dt> <dd>generic error</dd>
          <dt>203</dt> <dd>protocol error / bad request</dd>
          <dt>205</dt> <dd>message too big (you exceeded the 1000-byte v limit)</dd>
          <dt>206</dt> <dd>invalid signature</dd>
          <dt>301</dt> <dd>CAS hash mismatch</dd>
          <dt>302</dt> <dd>seq less than current</dd>
          <dt>303</dt> <dd>missing k or sig</dd>
          <dt>304 / 305</dt> <dd>salt issues (length, missing required, etc.)</dd>
          <dt>426</dt> <dd>immutable item too big</dd>
        </dl>

        <h2>End-to-end: publish a mutable string in C</h2>
        <p>
          Using <Link to="/lib">libbep44</Link> (the embeddable
          BEP-44 library version of dht44):
        </p>
        <pre><code>{`bep44_keypair_t kp;
bep44_keygen(&kp);                       /* fresh Ed25519 pair */

bep44_opts_t opts = {
    .port = 6881,
    .state_dir = "./state",
    .bootstrap_routers = 1,
    .republish_minutes = 60,
};
bep44_ctx_t *ctx = bep44_open(&opts);

/* Wait for the routing table to populate. */
while (bep44_good_nodes(ctx) < 4) bep44_step(ctx, 250);

/* Bencode "hello" as a string ("5:hello") and publish. */
bep44_put_mutable(ctx, &kp, NULL, 0,
                  /*seq=*/ 1, /*cas=*/ -1,
                  (uint8_t *)"5:hello", 7,
                  on_put_callback, NULL);

/* Pump the event loop; the library handles iterative lookup,
   signing, sending, retrying, and republishing every hour. */
while (running) bep44_step(ctx, 250);`}</code></pre>
        <p>
          The signing happens inside <code>bep44_put_mutable</code> —
          same function the dht44 CLI uses. The library never lets the
          secret key leave the calling thread.
        </p>

        <h2>End-to-end: retrieve a mutable item</h2>
        <pre><code>{`bep44_get_mutable(ctx, kp.pk, NULL, 0, on_get_callback, NULL);

/* on_get_callback fires once the lookup completes. The library
   has already verified the Ed25519 signature; if no signed
   value was retrievable, result.found == 0. */`}</code></pre>
        <p>
          Note the verification: libbep44 requires the returned
          <code>k</code> to match the requested <code>pk</code> AND the
          signature to verify against (salt, seq, v). Mismatches are
          dropped silently. This defends against unrelated peers
          serving the same target hash with their own values.
        </p>

        <h2>What it's used for in the wild</h2>
        <ul>
          <li><strong>BitTorrent v2 hybrid torrents</strong> publish their
            file tree under a stable mutable target so swarms can update
            metadata.</li>
          <li><strong>Magnet-link supplements</strong> — projects like
            DAT and a few others have used BEP 44 as an evolution layer
            on top of magnet links.</li>
          <li><strong>Identity / blog publishing</strong> — there's been
            on-and-off enthusiasm for using BEP 44 as a Twitter-style
            short-message substrate. The 1000-byte cap and ~2h
            persistence make this thinner than people initially expect.</li>
          <li><strong>Service discovery</strong> for opt-in P2P apps —
            publish a per-app mutable item describing your active
            endpoints.</li>
        </ul>

        <h2>References</h2>
        <ul>
          <li><a href="https://www.bittorrent.org/beps/bep_0044.html">BEP 44</a> — official spec.</li>
          <li><a href="https://github.com/arvidn/libtorrent/blob/master/test/test_dht.cpp"><code>test_dht.cpp</code></a> from libtorrent — golden test vectors we cross-check against.</li>
          <li><a href="https://github.com/webtorrent/bittorrent-dht/blob/master/client.js">bittorrent-dht's client.js</a> — JavaScript reference implementation.</li>
        </ul>
      </ArticleLayout>
    </>
  );
}
