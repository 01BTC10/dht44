import { Link } from "react-router-dom";
import SEO from "../../components/SEO";
import ArticleLayout from "../../components/ArticleLayout";
import { techArticle } from "./_helpers";

const PATH = "/blog/kademlia-vs-chord";
const TITLE = "Kademlia vs Chord vs Pastry: Which One and Why";
const DESC = "Comparative tour of three influential DHT designs. Lookup hops, churn handling, lookup correctness under partial failure, what each one is best at — and why Kademlia won the wider deployments.";

export default function BlogKademliaVsChord() {
  return (
    <>
      <SEO
        title={TITLE} description={DESC} path={PATH} type="article"
        jsonLd={techArticle(PATH, TITLE, DESC,
          "kademlia, chord, pastry, dht, distributed hash table, p2p protocols")}
      />
      <ArticleLayout
        crumbs={[
          { label: "Home", to: "/intro" },
          { label: "Blog", to: "/blog" },
          { label: "Kademlia vs Chord" },
        ]}
        title={TITLE}
        lede="If you're choosing or designing a DHT in 2026, the practical decision is mostly between Kademlia and 'something Kademlia-shaped'. But the original three — Kademlia, Chord, Pastry — got there by different routes and the differences matter for some applications."
      >
        <h2>The three protocols, in one table</h2>
        <table>
          <thead>
            <tr><th></th><th>Kademlia</th><th>Chord</th><th>Pastry</th></tr>
          </thead>
          <tbody>
            <tr><td>Year</td><td>2002</td><td>2001</td><td>2001</td></tr>
            <tr><td>Distance metric</td><td>XOR</td><td>Successor on a ring (asymmetric)</td><td>Numeric prefix on a ring + leaf set</td></tr>
            <tr><td>Routing table size</td><td>O(log n) entries × k</td><td>O(log n) finger table + successor list</td><td>O(log n) routing rows + leaf set + neighborhood set</td></tr>
            <tr><td>Lookup complexity</td><td>O(log n) hops</td><td>O(log n) hops</td><td>O(log n) hops</td></tr>
            <tr><td>Symmetric metric?</td><td>Yes</td><td>No</td><td>Effectively no (prefix-then-leaf-set)</td></tr>
            <tr><td>Iterative or recursive?</td><td>Iterative (originator drives lookup)</td><td>Either; original paper iterative</td><td>Recursive (each hop forwards)</td></tr>
            <tr><td>Production deployments</td><td>BitTorrent, IPFS, Eth Discovery v4, Tox</td><td>Academic only</td><td>FreePastry, Scribe (academic)</td></tr>
          </tbody>
        </table>

        <h2>Where they came from</h2>
        <p>
          All three were proposed within a 12-month window in 2001–2002.
          Each made different assumptions about node behavior, network
          properties, and the cost-vs-correctness tradeoff. Briefly:
        </p>
        <dl>
          <dt><strong>Chord</strong> (Stoica et al., MIT, 2001)</dt>
          <dd>Nodes laid out on a circular ring of 2^160. Each node
            keeps a "finger table" of pointers exponentially around
            the ring (1, 2, 4, ... 2^159 hops away) plus a "successor
            list" of the few clockwise neighbors. Elegant theoretical
            properties; the canonical academic DHT teaching example.</dd>

          <dt><strong>Pastry</strong> (Rowstron &amp; Druschel, Microsoft
            Research, 2001)</dt>
          <dd>Numeric IDs in base 2^b (typically b=4, base 16). Each
            node keeps log(n)/b "routing rows" (one per ID prefix
            length) plus a leaf set (immediate ring neighbors) plus a
            neighborhood set (low-RTT peers). The routing decision at
            each hop chooses based on prefix match; the leaf set is a
            backup for the last few hops.</dd>

          <dt><strong>Kademlia</strong> (Maymounkov &amp; Mazières, NYU, 2002)</dt>
          <dd>XOR-distance metric; routing table organized as a
            log(n)-deep binary tree of buckets. The XOR metric is
            symmetric, so any traffic the node receives passively
            populates its routing table. Iterative lookup, parallel
            queries with parameter α.</dd>
        </dl>

        <h2>Why Kademlia took over</h2>
        <p>Three concrete reasons.</p>

        <h3>1. The metric is symmetric</h3>
        <p>
          In Chord, "A is the successor of B" doesn't tell you "B is the
          successor of A" — the relation is direction-sensitive. Chord
          has to maintain a separate predecessor pointer to handle inbound
          traffic. Pastry's primary metric (prefix length) is symmetric
          in a sense, but distance ties are broken by ring direction,
          which reintroduces asymmetry near leaf-set boundaries.
        </p>
        <p>
          Kademlia's XOR is genuinely symmetric. <code>d(A, B) = d(B, A)</code>{" "}
          identically. This makes the routing table fill itself
          passively from inbound queries — if you ask me about a target,
          I learn that you exist and where you are in my XOR space, and
          I can use that information for my own future lookups. Chord
          and Pastry need active maintenance to keep their tables
          current; Kademlia's table stays fresh as a side effect of
          serving traffic.
        </p>

        <h3>2. Bucket eviction has good Sybil properties</h3>
        <p>
          Kademlia's bucket-replacement rule is "keep long-lived nodes,
          drop new ones if the bucket is full and the head still
          responds." This means a flood of attacker nodes can't push
          out a long-lived honest node. Chord's finger table doesn't
          have this property naturally — the canonical successor of a
          target IS whoever's there, and an attacker who positions
          themselves between you and a target gets the queries.
        </p>
        <p>
          Pastry's leaf-set has explicit bounded membership but the
          eviction policy is FIFO without preferring older nodes.
          Better than Chord, worse than Kademlia.
        </p>

        <h3>3. Iterative lookup is debuggable</h3>
        <p>
          In Pastry's recursive lookup, each hop forwards the query.
          If something goes wrong at hop 3 of 5, the originator has no
          visibility — the query just times out. In Kademlia's iterative
          lookup, the originator sees every responder, every closer
          node returned, every timeout. You can <em>watch</em> a
          Kademlia lookup converge in a packet capture.
        </p>
        <p>
          For real-world implementations, this matters far more than
          the asymptotic complexity (which is identical anyway). Half
          of the bugs in DHT implementations are subtle convergence
          issues that you only catch by tracing a lookup.
        </p>

        <h2>Where Chord still has theoretical appeal</h2>
        <p>
          Chord's correctness proofs are cleaner. Under the original
          paper's assumptions (no Sybil attacks, eventual consistency
          on the successor list), a Chord lookup converges in
          <code>O(log n)</code> hops with high probability under
          arbitrary churn, and the proof fits on one whiteboard. For
          formal-methods work and academic teaching, Chord is still the
          textbook example.
        </p>
        <p>
          What Chord doesn't have is a real-world deployment graph
          showing the proofs hold under adversarial churn, hostile node
          IDs, and the messy Internet. Kademlia got that empirical
          validation by being the substrate of BitTorrent's DHT.
        </p>

        <h2>Where Pastry still has theoretical appeal</h2>
        <p>
          Pastry's "neighborhood set" tracks low-RTT peers explicitly
          and uses them as routing-table supplements. This makes
          single-hop latency lower — every routing decision can prefer
          a closer peer if one is available. For applications where
          per-hop latency dominates (like Scribe's multicast tree),
          Pastry's locality awareness is a genuine win.
        </p>
        <p>
          Kademlia is locality-blind by design. The XOR metric ignores
          RTT entirely, which simplifies the analysis but means
          neighbor lookups can cross continents. For BitTorrent-style
          workloads where the per-hop latency is dominated by network
          path RTT anyway, this doesn't matter much. For real-time
          systems it could.
        </p>

        <h2>The pragmatic recommendation</h2>
        <p>
          Use Kademlia. Specifically, <Link to="/protocol/kademlia">
          plain Kademlia</Link> with{" "}
          <Link to="/protocol/bep5">BEP 5's KRPC framing</Link>. The
          ecosystem (libtorrent, jech/dht, libp2p Kademlia) has had two
          decades of bug-hunting and Sybil-hardening. Reusing it gets
          you a working DHT in an afternoon; designing your own gets
          you to "mostly working under benign conditions" in three
          months.
        </p>
        <p>
          If you're considering Chord or Pastry for a new project in
          2026, the questions to ask yourself:
        </p>
        <ul>
          <li>Is the academic clarity of Chord worth the loss of two
            decades of production hardening? (Almost always: no.)</li>
          <li>Is Pastry's locality awareness worth the extra
            implementation complexity? (For ~99% of P2P apps where
            data is the bottleneck and RTT is in the noise: no.)</li>
        </ul>

        <h2>What gets implemented in the wild now</h2>
        <p>
          All three of the modern Kademlia profiles in production are
          slight variations on the original paper:
        </p>
        <ul>
          <li><strong>BitTorrent Mainline DHT (BEP 5)</strong>: 160-bit
            IDs, k=8, α=8, four query types. Largest deployment.</li>
          <li><strong>libp2p Kademlia (IPFS, etc.)</strong>: 256-bit
            IDs (SHA-256), provider-record extension on top, content
            routing semantics. Multistream multiplexing for the
            transport.</li>
          <li><strong>Ethereum Discovery v4</strong>: Kademlia for node
            discovery; 256-bit IDs derived from node public key.
            Discovery v5 adds session-encrypted KRPC.</li>
        </ul>

        <h2>References</h2>
        <ul>
          <li>The Kademlia paper:{" "}
            <a href="https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf">
              Maymounkov &amp; Mazières, IPTPS 2002</a>.</li>
          <li>The Chord paper:{" "}
            <a href="https://pdos.csail.mit.edu/papers/chord:sigcomm01/chord_sigcomm.pdf">
              Stoica et al., SIGCOMM 2001</a>.</li>
          <li>The Pastry paper:{" "}
            <a href="https://www.freepastry.org/PAST/pastry.pdf">
              Rowstron &amp; Druschel, Middleware 2001</a>.</li>
          <li><Link to="/protocol/kademlia">Kademlia routing
            explained</Link> — the protocol used here.</li>
        </ul>
      </ArticleLayout>
    </>
  );
}
