import { Link } from "react-router-dom";
import SEO from "../components/SEO";
import ArticleLayout from "../components/ArticleLayout";

const posts = [
  {
    to: "/blog/dht-size",
    title: "How big is the BitTorrent DHT, really?",
    summary: "Methodology + live numbers from the dht44 crawler — BEP 51 sampling, dedup window, ASN/country distribution, IPv4 vs IPv6 split.",
  },
  {
    to: "/blog/classifying-peers",
    title: "Detecting crawlers, monitors and honeypots in the DHT",
    summary: "The classifier signals (high-pps from one source, lying-about-id, refusing announce_peer) and per-class peer counts.",
  },
  {
    to: "/blog/embed-dht-c-app",
    title: "Embedding a BitTorrent DHT in your C app",
    summary: "When a daemon isn't what you want — libbep44 quickstart, event-loop pattern, persistence semantics, threading.",
  },
  {
    to: "/blog/kademlia-vs-chord",
    title: "Kademlia vs Chord vs Pastry: which one and why",
    summary: "Comparative tour for students and architects evaluating P2P substrates. Tables of properties, churn handling, lookup correctness.",
  },
];

export default function BlogIndex() {
  return (
    <>
      <SEO
        title="dht44 blog — DHT research, observation, library notes"
        description="Articles on the BitTorrent Mainline DHT, Kademlia routing, BEP 44 items, network observation, and the libbep44 C library."
        path="/blog"
      />
      <ArticleLayout
        crumbs={[{ label: "Home", to: "/" }, { label: "Blog" }]}
        title="Writing"
        lede="Long-form posts on Kademlia, the BitTorrent DHT, BEP 44, and what the live crawler is seeing."
      >
        <ul className="post-list">
          {posts.map(p => (
            <li key={p.to}>
              <h2><Link to={p.to}>{p.title}</Link></h2>
              <p>{p.summary}</p>
            </li>
          ))}
        </ul>
      </ArticleLayout>
    </>
  );
}
