import { Link } from "react-router-dom";
import SEO from "../../components/SEO";
import ArticleLayout from "../../components/ArticleLayout";
import { techArticle } from "./_helpers";

const PATH = "/protocol/bep5";
const TITLE = "BitTorrent's Mainline DHT (BEP 5) in One Page";
const DESC = "The four KRPC queries (ping, find_node, get_peers, announce_peer); bencode framing; transaction IDs; node ID generation; bootstrap routers — with annotated packet examples.";

export default function Bep5() {
  return (
    <>
      <SEO
        title={TITLE} description={DESC} path={PATH} type="article"
        jsonLd={techArticle(PATH, TITLE, DESC,
          "bep 5, bittorrent dht, krpc, find_node, get_peers, announce_peer, mainline dht")}
      />
      <ArticleLayout
        crumbs={[
          { label: "Home", to: "/" },
          { label: "Protocol", to: "/protocol" },
          { label: "BEP 5" },
        ]}
        title={TITLE}
        lede="BEP 5 is the BitTorrent profile of Kademlia. It defines four queries on top of bencode-framed UDP and is the substrate every modern BitTorrent client speaks for trackerless swarm discovery. This page documents the wire format end-to-end."
      >
        <h2>What it is</h2>
        <p>
          The Mainline DHT is a Kademlia overlay (see{" "}
          <Link to="/protocol/kademlia">Kademlia routing explained</Link>)
          using SHA-1 (160-bit) node IDs and infohashes. Messages are
          bencoded dictionaries sent over a single UDP socket — same socket
          for queries and responses, distinguished by a top-level
          <code>y</code> key.
        </p>
        <p>
          Implemented by every major client (qBittorrent, libtorrent,
          uTorrent, Transmission, Deluge) and reachable from any
          Internet-connected host. Estimated 10–20 million online
          participants at any moment in 2026 — see{" "}
          <Link to="/blog/dht-size">how big is the DHT, really?</Link>.
        </p>

        <h2>Key terms</h2>
        <dl>
          <dt>Node ID</dt>
          <dd>A 160-bit identifier, ideally derived per BEP 42 (SHA-1 of
            IP-derived bytes) but historically just random. Same width as
            an infohash so the metric works on both.</dd>

          <dt>Infohash</dt>
          <dd>The SHA-1 hash of the bencoded <code>info</code> dict of a
            torrent. Identifies a swarm. The DHT lets a peer find others
            in the swarm without a tracker.</dd>

          <dt>Transaction ID (<code>t</code>)</dt>
          <dd>Short opaque bytestring — usually 2 bytes — that the
            requester picks per query. The responder echoes it. Lets the
            requester demultiplex concurrent queries on a single socket.</dd>

          <dt>KRPC</dt>
          <dd>"Kademlia RPC". The BEP 5 message format: a bencoded dict
            with <code>y</code> ("q" query / "r" response / "e" error),
            <code>t</code> (transaction id), and a method-specific
            payload (<code>q</code> + <code>a</code> for queries,
            <code>r</code> for responses, <code>e</code> for errors).</dd>

          <dt>Compact node info</dt>
          <dd>Wire-efficient encoding for "node id + IP + port".
            IPv4: 26 bytes (20 + 4 + 2). IPv6: 38 bytes (20 + 16 + 2).
            Concatenated, no separators.</dd>
        </dl>

        <h2>The four queries</h2>

        <h3><code>ping</code></h3>
        <p>Probe whether a node is alive and learn its current ID.</p>
        <pre><code>{`Q: d 1:a d 2:id 20:<our id> e 1:q 4:ping 1:t 2:aa 1:y 1:q e
R: d 1:r d 2:id 20:<their id> e 1:t 2:aa 1:y 1:r e`}</code></pre>
        <p>
          Used by the routing table to confirm a peer is still good before
          inserting (or after the bucket-full eviction policy fires —
          see the Kademlia article).
        </p>

        <h3><code>find_node</code></h3>
        <p>
          "Tell me the {`<=`}8 nodes closest to <code>target</code> that
          you know about."
        </p>
        <pre><code>{`Q: d 1:a d 2:id 20:<our>
              6:target 20:<target>
              4:want l 2:n4 2:n6 e
            e
          1:q 9:find_node
          1:t 2:aa
          1:y 1:q
        e

R: d 1:r d 2:id 20:<their>
            5:nodes  208:<8 × compact-v4>
            6:nodes6 304:<8 × compact-v6>
          e
          1:t 2:aa
          1:y 1:r
        e`}</code></pre>
        <p>
          The optional <code>want</code> list (added by libtorrent in 2014)
          lets dual-stack nodes ask for IPv4 or IPv6 specifically. Without
          <code>want</code>, the responder picks based on the source family.
        </p>

        <h3><code>get_peers</code></h3>
        <p>
          The reason DHT exists for BitTorrent. "Tell me the peers you know
          for <code>info_hash</code>, OR the closest nodes if you don't
          have any."
        </p>
        <pre><code>{`Q: d 1:a d 2:id 20:<our>
              9:info_hash 20:<infohash>
            e
          1:q 9:get_peers
          1:t 2:aa
          1:y 1:q
        e

R-with-peers:
   d 1:r d 2:id 20:<their>
              5:token 8:<opaque>
              6:values l 6:<compact peer> 6:<compact peer> ... e
            e
            1:t 2:aa
            1:y 1:r
          e

R-with-nodes-only:
   d 1:r d 2:id 20:<their>
              5:token 8:<opaque>
              5:nodes 208:<8 × compact node info>
            e
            1:t 2:aa
            1:y 1:r
          e`}</code></pre>
        <p>
          The <code>token</code> is HMAC-style, scoped to the requester's
          IP and the queried infohash, valid for ~10 minutes. The requester
          must echo this token in a subsequent <code>announce_peer</code>
          to prove it received this exact response — defends against
          announce spam.
        </p>
        <p>
          Note "values" is a list of 6-byte (or 18-byte for v6) compact
          PEER addresses, NOT compact node info. No node ID. They're peers
          in a torrent swarm, not DHT nodes.
        </p>

        <h3><code>announce_peer</code></h3>
        <p>
          "Add me to the peer list for <code>info_hash</code>. Here's the
          token you gave me."
        </p>
        <pre><code>{`Q: d 1:a d 2:id 20:<our>
              12:implied_port i1e            (optional; use UDP source port)
              9:info_hash 20:<infohash>
              4:port i6881e                  (or omit if implied_port=1)
              5:token 8:<echoed token>
            e
          1:q 13:announce_peer
          1:t 2:aa
          1:y 1:q
        e

R: d 1:r d 2:id 20:<their> e 1:t 2:aa 1:y 1:r e`}</code></pre>
        <p>
          On accept, the responder records (your IP, port, infohash) for
          ~30 minutes. Subsequent <code>get_peers</code> for that infohash
          returns you in the values list.
        </p>

        <h2>Bencode dict ordering</h2>
        <p>
          KRPC mandates strict alphabetical ordering of dict keys on the
          wire. Implementations that emit out of order will be rejected by
          libtorrent and friends. The four outer-dict orderings are:
        </p>
        <ul>
          <li>Query: <code>a, q, t, y</code></li>
          <li>Response: <code>r, t, y</code></li>
          <li>Error: <code>e, t, y</code></li>
          <li>"Read-only" responses (BEP 43): <code>r, ro, t, y</code></li>
        </ul>
        <p>
          Inside <code>a</code>: keys are also alphabetical. For
          <code>get_peers</code> that's <code>id, info_hash</code>; for
          <code>announce_peer</code> it's <code>id, implied_port?,
          info_hash, port?, token</code>.
        </p>

        <h2>Bootstrap</h2>
        <p>The four canonical public bootstrap routers, all pingable on UDP/6881:</p>
        <ul>
          <li><code>router.bittorrent.com</code></li>
          <li><code>dht.transmissionbt.com</code></li>
          <li><code>router.utorrent.com</code></li>
          <li><code>router.bitcomet.com</code></li>
        </ul>
        <p>
          These are not Kademlia participants in the normal sense — they
          respond to <code>find_node</code> but don't have full routing
          tables. They exist to inject new nodes into the network. After
          bootstrap, drop them and discover peers organically.
        </p>

        <h2>BEP 42: secure node IDs</h2>
        <p>
          Originally node IDs were random. That made Sybil attacks trivial
          — generate enough IDs near a target to dominate it. BEP 42
          requires the first 21 bits of a node's ID to be a CRC32C of its
          IP plus a small entropy byte, so an attacker can't pick arbitrary
          IDs. dht44 implements this; jech/dht implements this; libtorrent
          implements this. Older clients without it are gradually being
          deprioritized in routing tables.
        </p>

        <h2>BEP 43: read-only nodes</h2>
        <p>
          A node behind a NAT that can't accept inbound queries can advertise
          itself as "read-only" by setting <code>ro: 1</code> on its
          responses. Other nodes won't add it to their routing tables. This
          keeps mobile / locked-down clients from polluting the table with
          peers that won't reply.
        </p>

        <h2>BEP 44 layered on top</h2>
        <p>
          BEP 5 only stores swarm-peer triples. BEP 44 reuses the routing
          table to store arbitrary signed (mutable) or content-addressed
          (immutable) values. See{" "}
          <Link to="/protocol/bep44">BEP 44 in depth</Link>.
        </p>

        <h2>BEP 51 layered on top</h2>
        <p>
          For active enumeration of the network's stored infohashes, see{" "}
          <Link to="/protocol/bep51">sample_infohashes</Link>. This is
          optional — most clients don't implement it — but every modern
          DHT crawler does.
        </p>

        <h2>What dht44 does differently</h2>
        <ul>
          <li>Token issuance uses HMAC-SHA1 with a per-process random key,
            8 bytes truncated. Lifetime is whatever the daemon's been
            running, not 10 minutes — simpler, no token expiry table.</li>
          <li>Default port is 6881 (the BitTorrent default), but the
            daemon supports <code>--port 0</code> for ephemeral.</li>
          <li>BEP 42 secure IDs are off by default to keep node-ID
            stable across NAT changes; the operator can opt in.</li>
        </ul>

        <h2>References</h2>
        <ul>
          <li><a href="https://www.bittorrent.org/beps/bep_0005.html">BEP 5</a> — official spec.</li>
          <li><a href="https://www.bittorrent.org/beps/bep_0042.html">BEP 42</a> — secure node IDs.</li>
          <li><a href="https://www.bittorrent.org/beps/bep_0043.html">BEP 43</a> — read-only nodes.</li>
          <li><a href="https://github.com/jech/dht">jech/dht</a> — the C reference implementation we vendor.</li>
        </ul>
      </ArticleLayout>
    </>
  );
}
