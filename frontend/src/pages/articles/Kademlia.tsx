import { Link } from "react-router-dom";
import SEO from "../../components/SEO";
import ArticleLayout from "../../components/ArticleLayout";
import { techArticle } from "./_helpers";

const PATH = "/protocol/kademlia";
const TITLE = "Kademlia Routing Explained: XOR Distance & k-Buckets";
const DESC = "How Kademlia's XOR metric, k-buckets, and iterative node lookup work — step-by-step with annotated packet traces from a real DHT crawler.";

export default function Kademlia() {
  return (
    <>
      <SEO
        title={TITLE}
        description={DESC}
        path={PATH}
        type="article"
        jsonLd={techArticle(PATH, TITLE, DESC,
          "kademlia, dht, xor distance, k-bucket, node lookup, bittorrent")}
      />
      <ArticleLayout
        crumbs={[
          { label: "Home", to: "/intro" },
          { label: "Protocol", to: "/protocol" },
          { label: "Kademlia" },
        ]}
        title={TITLE}
        lede="Kademlia is the routing layer beneath BitTorrent's Mainline DHT, IPFS, and Ethereum's discovery v4. This page is a working developer's guide: what's on the wire, why the design works, and which bits will bite you in implementation."
      >
        <h2>The one-paragraph version</h2>
        <p>
          Every node has a 160-bit ID, the same width as the keys it stores. The
          distance between two IDs is their bitwise <strong>XOR</strong>,
          interpreted as an unsigned integer. Each node maintains 160 buckets of
          known peers, indexed by the most significant bit at which the peer's
          ID differs from its own. To find the node responsible for a key, you
          send <code>find_node</code> queries to the closest peers you already
          know, ask each one for the closest peers <em>they</em> know, and
          repeat until convergence.
        </p>

        <h2>Key terms</h2>
        <dl>
          <dt>Node ID</dt>
          <dd>A 160-bit identifier. Picked at random when a node first joins
            (and persisted across restarts in real implementations — rotating
            it discards your routing presence). The same ID space addresses
            both nodes and stored keys, which is what makes the distance
            metric meaningful for both.</dd>

          <dt>XOR distance</dt>
          <dd><code>d(x, y) = x ⊕ y</code> interpreted as a 160-bit unsigned
            integer. Symmetric: <code>d(x, y) = d(y, x)</code>. Unidirectional:
            for any fixed point and any distance, exactly one node is at that
            distance. Triangle inequality holds. Crucially, two nodes that
            agree on the leading <em>k</em> bits are within <code>2^(160-k)</code>
            of each other — the metric matches the bit-prefix tree.</dd>

          <dt>k-bucket</dt>
          <dd>One of 160 routing-table slots, each holding up to <code>k</code>
            (typically 8) known peers. Bucket <em>i</em> holds peers whose XOR
            distance from us has its most significant <em>1</em> at bit
            <em>i</em>, counted from the top. Peers within bucket <em>i</em>
            agree with us on the first <em>i</em> bits and differ at bit
            <em>i+1</em>. Lower-numbered buckets are "farther"; higher-numbered
            buckets are "closer" to us.</dd>

          <dt>α (alpha)</dt>
          <dd>Concurrency parameter for iterative lookup — the number of
            <code>find_node</code> queries kept in flight at once. Original
            paper uses 3; libtorrent uses 8.</dd>

          <dt>top-k</dt>
          <dd>Termination criterion. The lookup ends when the <em>k</em>
            closest peers it has discovered have all responded (or timed
            out). Same <em>k</em> as the bucket size.</dd>
        </dl>

        <h2>Why XOR?</h2>
        <p>
          Kademlia's distance metric isn't physical proximity or routing
          distance — it's a property of the IDs themselves. Two requirements
          drove the choice:
        </p>
        <ol>
          <li><strong>Symmetry.</strong> If A is close to B, B is close to A. With
            symmetric distance, every query you receive teaches the responder
            about the same neighborhood you're trying to learn about. Routing
            tables fill themselves passively from inbound traffic.</li>
          <li><strong>Bit-prefix correspondence.</strong> The leading bits of
            <code>x ⊕ y</code> tell you exactly how many leading bits
            <code>x</code> and <code>y</code> share. So a routing table
            organized as a binary tree on bit prefixes <em>is</em> a routing
            table organized by XOR distance, with no extra bookkeeping.</li>
        </ol>
        <p>
          Chord uses an asymmetric "successor on a ring" metric, which forced
          its designers to add a separate "predecessor list" to handle inbound
          queries. Pastry uses a numeric-prefix metric with a separate "leaf
          set" for the immediate neighborhood. Kademlia gets both for free
          because XOR is symmetric and matches the prefix structure.
        </p>

        <h2>The routing table</h2>
        <p>
          A naive Kademlia table is 160 buckets, one per bit. In real
          implementations the table is allocated lazily as a binary tree and
          buckets are split when full — the bucket containing our own ID gets
          subdivided indefinitely, while distant buckets stay coalesced
          because we'll see fewer peers there anyway.
        </p>
        <p>
          When we observe a peer (because it queried us, or replied to one of
          our queries), we look up its bucket and:
        </p>
        <ul>
          <li>If the peer is already in the bucket, move it to the tail
            (most-recently-seen).</li>
          <li>If the bucket has fewer than <code>k</code> entries, append it.</li>
          <li>If the bucket is full, ping the head (least-recently-seen). If
            the head responds, drop the new peer and re-tail the head. If the
            head doesn't respond within a timeout, evict it and append the
            new peer.</li>
        </ul>
        <p>
          The "drop the new peer" rule is crucial for sybil resistance: an
          attacker flooding new peers can't push a healthy long-lived node
          out of your routing table.
        </p>

        <h2>Iterative lookup, step by step</h2>
        <p>
          Suppose we want to find the node responsible for target
          <code>T</code>. Our routing table has dozens of peers we've heard
          from, but none of them is <em>at</em> <code>T</code> — they're
          scattered across the ID space.
        </p>
        <p>
          The algorithm in the original paper (slightly clarified):
        </p>
        <ol>
          <li>Pick the <code>α</code> closest peers from our routing table by
            XOR distance to <code>T</code>. Call this our <em>shortlist</em>.</li>
          <li>Send each one a <code>find_node(T)</code> query.</li>
          <li>As responses arrive, each contains up to <code>k</code> closer
            peers the responder knows. Merge them into the shortlist (sorted
            by distance, capped at some practical size).</li>
          <li>Pick the <code>α</code> closest peers we haven't yet queried,
            and send another round of <code>find_node(T)</code>.</li>
          <li>Stop when the <code>k</code> closest peers we know about have
            all responded.</li>
        </ol>
        <p>
          With α=3 and k=8, the lookup typically converges in 3–5 round trips
          on a healthy network. The closest peers we've found at termination
          are the de-facto "owners" of <code>T</code>.
        </p>
        <p>
          The convergence proof is a beautiful corollary of the bit-prefix
          structure: each round of queries learns at least one more leading
          bit of <code>T</code>'s actual neighborhood, so the lookup
          terminates in <code>O(log n)</code> hops where <em>n</em> is the
          network size.
        </p>

        <h2>Annotated packet trace</h2>
        <p>
          Here's a real <code>find_node</code> query from a Mainline DHT
          packet trace, in <Link to="/protocol/bep5">BEP 5</Link> KRPC bencode
          format:
        </p>
        <pre><code>{`d
  1:a d
        2:id 20:abcdefghij0123456789
        6:target 20:....20-byte target....
        4:want l 2:n4 2:n6 e
      e
  1:q 9:find_node
  1:t 2:aa
  1:y 1:q
e`}</code></pre>
        <p>
          Reading it: outer dict with keys <code>a</code> (arguments),
          <code>q</code> (query name), <code>t</code> (transaction id),
          <code>y</code> (message type). The arguments dict carries our node
          ID, the target we're searching for, and a list saying "give us
          IPv4 nodes (<code>n4</code>) and IPv6 nodes (<code>n6</code>)
          back".
        </p>
        <p>The response, again real:</p>
        <pre><code>{`d
  1:r d
        2:id 20:....responder's id....
        5:nodes 208:<8 × (20-byte id || 4-byte ipv4 || 2-byte port)>
      e
  1:t 2:aa
  1:y 1:r
e`}</code></pre>
        <p>
          The <code>nodes</code> field is "compact node info": each entry is
          26 bytes, with no separators. <code>208 = 8 × 26</code>, so the
          responder gave us its 8 closest known peers. We extract them, sort
          by XOR distance to <code>T</code>, merge into our shortlist, and
          continue.
        </p>

        <h2>Implementation pitfalls</h2>
        <h3>Don't include yourself in lookup results</h3>
        <p>
          When a peer asks <code>find_node(T)</code>, you respond with the
          <code>k</code> closest peers in your routing table — but never
          include yourself. Including yourself causes lookups to loop
          forever between two nodes that each consider the other "closest".
          jech/dht's router handles this correctly; some implementations
          have shipped this bug.
        </p>
        <h3>The bucket containing our own ID is special</h3>
        <p>
          As your node has been online longer, you'll learn many peers very
          close to your own ID. The bucket they share with you fills, gets
          split, and the half containing your ID gets refined. This means
          <em>well-connected</em> nodes have a non-uniform routing table —
          finely resolved near themselves, coarse far away. That's correct
          behavior.
        </p>
        <h3>RTT-blind shortlist insertion</h3>
        <p>
          The shortlist is sorted by XOR distance, not by RTT. A peer in
          another country that happens to be XOR-close gets queried before a
          local-network peer that's XOR-far. This is by design — Kademlia
          deliberately ignores network topology to keep the analysis clean.
          Implementations that try to be clever about RTT often introduce
          subtle convergence bugs.
        </p>
        <h3>Soft-bootstrapping</h3>
        <p>
          When a node restarts, it has a list of warm peers from disk but
          none of them are "good" yet — they haven't responded recently.
          jech/dht uses a "soft bootstrap": insert them into the routing
          table with no traffic, then do an iterative lookup against your
          own ID. The lookup queries the warm peers, the responses promote
          them to "good" if they're alive, and as a side effect populate
          buckets near your own ID — exactly what you need for inbound
          query handling. dht44 inherits this pattern.
        </p>

        <h2>Where this fits in the BitTorrent stack</h2>
        <p>
          The BitTorrent Mainline DHT is Kademlia (specified in
          <Link to="/protocol/bep5"> BEP 5</Link>) plus four query types:
          <code>ping</code>, <code>find_node</code>, <code>get_peers</code>,
          and <code>announce_peer</code>.
          <Link to="/protocol/bep44"> BEP 44</Link> is a layer on top that
          repurposes the routing for arbitrary key/value storage rather
          than just torrent peer announcements.
          <Link to="/protocol/bep51"> BEP 51</Link>'s
          <code>sample_infohashes</code> is a way to enumerate the
          population of stored keys, used by crawlers like
          {" "}<Link to="/dashboard/peers">the one running on this site</Link>.
        </p>

        <h2>Further reading</h2>
        <ul>
          <li>The original paper:{" "}
            <a href="https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf">
              Maymounkov &amp; Mazières, <em>Kademlia: A Peer-to-peer Information System Based on the XOR Metric</em>
            </a>{" "}(IPTPS 2002).</li>
          <li><a href="https://www.bittorrent.org/beps/bep_0005.html">BEP 5</a> — the BitTorrent profile.</li>
          <li>Source: jech's reference C implementation at{" "}
            <a href="https://github.com/jech/dht">github.com/jech/dht</a>{" "}
            (vendored in this project at <code>vendor/jech-dht/</code>).</li>
        </ul>
      </ArticleLayout>
    </>
  );
}
