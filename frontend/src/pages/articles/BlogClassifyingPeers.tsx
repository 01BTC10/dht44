import { Link } from "react-router-dom";
import SEO from "../../components/SEO";
import ArticleLayout from "../../components/ArticleLayout";
import { techArticle } from "./_helpers";

const PATH = "/blog/classifying-peers";
const TITLE = "Detecting Crawlers, Monitors and Honeypots in the DHT";
const DESC = "Classifier signals from running a passive observer on the public BitTorrent DHT: high-pps single sources, lying about node id, refusing announce_peer, ASN heuristics. With per-class peer counts.";

export default function BlogClassifyingPeers() {
  return (
    <>
      <SEO
        title={TITLE} description={DESC} path={PATH} type="article"
        jsonLd={techArticle(PATH, TITLE, DESC,
          "dht crawler, honeypot, monitor, sybil, bittorrent dht, peer classifier")}
      />
      <ArticleLayout
        crumbs={[
          { label: "Home", to: "/intro" },
          { label: "Blog", to: "/blog" },
          { label: "Classifying peers" },
        ]}
        title={TITLE}
        lede="Not everything that talks BEP 5 is a real BitTorrent user. The Mainline DHT carries crawlers, monitors run by anti-piracy firms, honeypots, academic measurement nodes, and several flavors of broken client. Here's what each one looks like on the wire."
      >
        <h2>Why classify</h2>
        <p>
          Treating every observed peer as a "real user" gives you wrong
          numbers (see <Link to="/blog/dht-size">how big is the DHT</Link>).
          Worse, monitors and honeypots can pollute your routing table
          with peers that aggregate inbound queries and never propagate
          them — black holes that look like normal nodes from one query
          away.
        </p>
        <p>
          dht44 maintains four classes per observed peer:{" "}
          <code>ok</code>, <code>crawler</code>, <code>monitor</code>,{" "}
          <code>honeypot</code>. The classifier emits a score plus a
          short list of triggered signals. See the
          {" "}<code>peers.crawler_score</code>,{" "}
          <code>peers.crawler_class</code>,{" "}
          <code>peers.crawler_signals</code>, and{" "}
          <code>peers.crawler_reason</code> columns for details.
        </p>

        <h2>The four classes, by behavior</h2>

        <h3><code>ok</code> — actual BitTorrent users</h3>
        <p>
          Sends a normal mix of <code>find_node</code>,{" "}
          <code>get_peers</code>, and <code>announce_peer</code>.
          Responds to inbound <code>get_peers</code> with peer lists
          (not just empty <code>nodes</code>). Their announced port
          matches the source port of inbound queries, suggesting a
          real client behind NAT or with a port forward. ASN is
          residential ISP. They're the majority of the network.
        </p>

        <h3><code>crawler</code> — passive enumerators (us included)</h3>
        <p>Strong signals:</p>
        <ul>
          <li>High-pps query rate from one source IP. A normal client
            sends a query every few seconds; a crawler sends 10–100/sec
            sustained.</li>
          <li>Heavy use of <code>sample_infohashes</code> (BEP 51).
            Real clients almost never issue this — it's a research /
            enumeration query.</li>
          <li>Random-looking targets across the keyspace, rather than
            the few infohashes a real client cares about.</li>
          <li>Doesn't <code>announce_peer</code>. Crawlers observe but
            don't claim to host content.</li>
          <li>ASN is often datacenter / cloud (Hetzner, OVH, AWS,
            DigitalOcean, etc.). Real clients are residential ISP.</li>
        </ul>

        <h3><code>monitor</code> — anti-piracy / brand-protection firms</h3>
        <p>
          A subset of crawlers with extra fingerprints:
        </p>
        <ul>
          <li><strong>Multiple node IDs from the same IP block.</strong>{" "}
            Sybil flooding to dominate the closest-K of specific
            infohashes. A residential ISP block returning 8 distinct
            "best" peers to a query, all answering with sequential
            ports, is the classic monitor signature.</li>
          <li><strong>Reply with empty <code>get_peers</code>{" "}
            responses</strong> when the monitor knows it's near a
            popular infohash. They're collecting which IPs are looking
            for the content, not propagating it.</li>
          <li><strong>ASN owned by known anti-piracy firms</strong> —
            "Irdeto", "MarkMonitor", "IP Echelon", "Nagra Kudelski",
            "Rightscorp", and a few others publish in their PTR
            records or WHOIS. dht44 keeps a small string-match list.</li>
        </ul>

        <h3><code>honeypot</code> — research / academic / law enforcement</h3>
        <p>Hardest to identify cleanly. Signals:</p>
        <ul>
          <li>Reply pattern doesn't match libtorrent or any known
            BitTorrent client (unusual KRPC error codes, malformed
            <code>v</code> strings, idiosyncratic dict orderings).</li>
          <li>Stable node ID over months from the same /24 — not
            consistent with a normal residential client which
            churns IPs every CGNAT lease.</li>
          <li>Suspicious version <code>v</code> string in KRPC. Real
            clients advertise "LT0d50" (libtorrent), "UT350"
            (uTorrent), etc. Honeypots often present "??1.0" or
            similar non-existent strings, or copy a real string
            verbatim with no minor-version drift.</li>
          <li>Hosted in academic-research IP ranges (NREN networks)
            or known law-enforcement infrastructure.</li>
        </ul>
        <p>
          The classifier is intentionally conservative on this class —
          honeypot vs ok is the most error-prone distinction and
          false-positives have real consequences. We require multiple
          orthogonal signals before flagging.
        </p>

        <h2>Signal scoring, briefly</h2>
        <p>
          Each peer accumulates a score over time as new signals fire.
          Coarse weights (no claim of optimality):
        </p>
        <table>
          <thead>
            <tr><th>Signal</th><th>Weight</th><th>Class hint</th></tr>
          </thead>
          <tbody>
            <tr><td>Sustained pps {`>`} 10 from this source</td><td>+3</td><td>crawler</td></tr>
            <tr><td>Issued sample_infohashes</td><td>+2</td><td>crawler</td></tr>
            <tr><td>Datacenter ASN (no residential ISP)</td><td>+1</td><td>crawler</td></tr>
            <tr><td>≥ 3 node IDs from same /24</td><td>+3</td><td>monitor</td></tr>
            <tr><td>Empty get_peers replies despite many queries</td><td>+2</td><td>monitor</td></tr>
            <tr><td>ASN org matches anti-piracy keyword</td><td>+5</td><td>monitor</td></tr>
            <tr><td>v string doesn't match any known client</td><td>+1</td><td>honeypot</td></tr>
            <tr><td>Stable node id from /24 over &gt; 30 days</td><td>+2</td><td>honeypot</td></tr>
            <tr><td>NREN / law-enforcement IP range</td><td>+4</td><td>honeypot</td></tr>
          </tbody>
        </table>
        <p>
          A peer with score 0–1 is <code>ok</code>. Score 2–4 with
          mostly crawler hints is <code>crawler</code>. Score 5+ with
          monitor signals is <code>monitor</code>. Honeypot needs at
          least two distinct honeypot-class signals.
        </p>

        <h2>Per-class peer counts</h2>
        <p className="placeholder">
          Once the public dashboard is live, embed real per-class
          counts here. Until then: from a sample of academic
          observations, <code>ok</code> peers are typically 75–85% of
          observed nodes, <code>crawler</code> 10–20%, <code>monitor</code>{" "}
          1–5%, <code>honeypot</code> &lt; 1%.
        </p>

        <h2>What this is not</h2>
        <ul>
          <li>Not a way to identify users. We classify peer endpoints
            (an IP+port participating in the DHT) by behavior, not
            humans.</li>
          <li>Not advice for monitor evasion. Monitors care about
            specific infohashes; if you participate in those swarms
            you'll be observed regardless of how good our classifier
            is. We document the signals because understanding them is
            useful research, not because we're trying to teach
            counter-monitoring.</li>
          <li>Not a security boundary. The dashboard is observational.
            A peer flagged as monitor may still be benign; we're
            describing patterns, not adjudicating.</li>
        </ul>

        <h2>References</h2>
        <ul>
          <li><Link to="/blog/dht-size">How big is the DHT, really?</Link>{" "}
            — why classification matters for the headline numbers.</li>
          <li><a href="https://dl.acm.org/doi/10.1145/2068816.2068852">
            Crosby &amp; Wallach, <em>An Analysis of BitTorrent's Two
            Kademlia-based DHTs</em></a> — early academic measurement
            paper that established many of the methods.</li>
          <li>The classifier source lives in <code>src/http_ws.c</code>{" "}
            (function <code>classify_peer</code>) — read it for the
            current weights and signal list.</li>
        </ul>
      </ArticleLayout>
    </>
  );
}
