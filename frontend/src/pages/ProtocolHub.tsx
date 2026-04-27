import { Link } from "react-router-dom";
import SEO from "../components/SEO";
import ArticleLayout from "../components/ArticleLayout";

const faqJsonLd = {
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "@id": "https://dht44.com/protocol#faq",
  mainEntity: [
    {
      "@type": "Question",
      name: "What is the Kademlia DHT?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "Kademlia is a distributed hash table protocol that uses XOR distance to organize node identifiers and locate keys. It's the substrate beneath BitTorrent's Mainline DHT (BEP 5), IPFS, and Ethereum's discovery v4.",
      },
    },
    {
      "@type": "Question",
      name: "How does a Kademlia node lookup work?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "A node sends find_node queries to the α (typically 3-8) closest known peers by XOR distance to a target. Each responder returns its own closest known nodes, the requester repeats with newly discovered peers, and the lookup terminates when the top-k peers (typically 8) have all responded.",
      },
    },
    {
      "@type": "Question",
      name: "What is BEP 44?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "BEP 44 is a BitTorrent Enhancement Proposal that lets the Mainline DHT store small (≤1000 byte bencoded) immutable values addressed by SHA1(value), and signed mutable values addressed by SHA1(public_key‖salt) with monotonically increasing sequence numbers.",
      },
    },
    {
      "@type": "Question",
      name: "How long do BEP 44 items live on the network?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "Items are cached on storers for about two hours unless re-published. A long-running publisher should re-issue the put roughly every 60 minutes to stay below the expiry window.",
      },
    },
    {
      "@type": "Question",
      name: "Can I run a BitTorrent DHT node without joining swarms?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "Yes. The Mainline DHT (BEP 5) is independent from torrent transfer. A node can speak BEP 5 + BEP 44 to publish or retrieve data and never participate in any actual torrent.",
      },
    },
  ],
};

export default function ProtocolHub() {
  return (
    <>
      <SEO
        title="Kademlia & BitTorrent DHT Protocol Reference"
        description="Plain-language reference for Kademlia routing, the Mainline DHT (BEP 5), and BEP 44 mutable items — with diagrams, packet examples, and working C code."
        path="/protocol"
        jsonLd={faqJsonLd}
      />
      <ArticleLayout
        crumbs={[{ label: "Home", to: "/" }, { label: "Protocol" }]}
        title="Protocol reference"
        lede="A field guide to the protocols that make the BitTorrent DHT work — what's on the wire, why it's shaped that way, and the gotchas."
      >
        <h2>Articles</h2>
        <dl className="ref-list">
          <dt><Link to="/protocol/kademlia">Kademlia routing</Link></dt>
          <dd>XOR distance, k-buckets, iterative <code>find_node</code> walk-through.</dd>

          <dt><Link to="/protocol/bep5">BEP 5: the Mainline DHT</Link></dt>
          <dd><code>ping</code>, <code>find_node</code>, <code>get_peers</code>, <code>announce_peer</code> wire formats.</dd>

          <dt><Link to="/protocol/bep44">BEP 44: mutable + immutable items</Link></dt>
          <dd>Signing, seq monotonicity, CAS, the ~2h expiry window.</dd>

          <dt><Link to="/protocol/bep51">BEP 51: <code>sample_infohashes</code></Link></dt>
          <dd>How an active crawler enumerates the live network.</dd>
        </dl>

        <h2>Frequently asked</h2>
        <dl>
          <dt>What is the Kademlia DHT?</dt>
          <dd>A distributed hash table protocol that uses XOR distance to
            organize node identifiers and locate keys. It's the substrate
            beneath BitTorrent's Mainline DHT (BEP 5), IPFS, and Ethereum's
            discovery v4.</dd>

          <dt>How does a Kademlia node lookup work?</dt>
          <dd>A node sends <code>find_node</code> queries to the α (typically
            3–8) closest known peers by XOR distance to a target. Each
            responder returns its own closest known nodes, the requester
            repeats with newly discovered peers, and the lookup terminates
            when the top-k peers (typically 8) have all responded.</dd>

          <dt>What is BEP 44?</dt>
          <dd>A BitTorrent Enhancement Proposal that lets the Mainline DHT
            store small (≤1000-byte bencoded) immutable values addressed by
            <code>SHA1(value)</code>, and signed mutable values addressed by
            <code>SHA1(public_key ‖ salt)</code> with monotonically increasing
            sequence numbers.</dd>

          <dt>How long do BEP 44 items live on the network?</dt>
          <dd>About two hours, unless re-published. A long-running publisher
            should re-issue the <code>put</code> roughly every 60 minutes —
            <Link to="/lib/persistence">libbep44 does this automatically</Link>.</dd>

          <dt>Can I run a BitTorrent DHT node without joining torrents?</dt>
          <dd>Yes. The Mainline DHT is independent from torrent transfer. A
            node can speak BEP 5 + BEP 44 to publish or retrieve data and
            never participate in any actual swarm.</dd>
        </dl>
      </ArticleLayout>
    </>
  );
}
