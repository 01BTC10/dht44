import { Link } from "react-router-dom";
import SEO from "../components/SEO";

const homeJsonLd = [
  {
    "@context": "https://schema.org",
    "@type": "WebSite",
    "@id": "https://dht44.com/#website",
    url: "https://dht44.com/",
    name: "dht44",
    alternateName: "libbep44",
    description:
      "Open-source BitTorrent Mainline DHT crawler and BEP 44 C library — live network observability plus a developer-facing protocol reference.",
    inLanguage: "en",
    publisher: { "@id": "https://dht44.com/#org" },
  },
  {
    "@context": "https://schema.org",
    "@type": "Organization",
    "@id": "https://dht44.com/#org",
    name: "dht44",
    url: "https://dht44.com/",
    sameAs: ["https://github.com/01BTC10/dht44"],
  },
];

export default function Home() {
  return (
    <>
      <SEO
        title="dht44 — Live BitTorrent Mainline DHT Observability"
        description="Open-source BitTorrent DHT crawler and BEP 44 toolkit. Live peer/query stream, infohash sampling, and a C library you can embed. Read the protocol, see the network."
        path="/"
        jsonLd={homeJsonLd}
      />
      <section className="hero">
        <h1>dht44</h1>
        <p className="tagline">
          Open-source BitTorrent <strong>Mainline DHT</strong> toolkit — a
          live network crawler, an embeddable BEP 44 C library, and a
          plain-language protocol reference.
        </p>
        <p>
          Written in C on top of <code>jech/dht</code>. MIT licensed. No SaaS, no
          telemetry, no tracking-cookies.
        </p>
        <div className="cta-row">
          <Link to="/protocol" className="cta primary">Read the protocol</Link>
          <Link to="/lib" className="cta">Embed the library</Link>
          <Link to="/dashboard/peers" className="cta">See the live network</Link>
          <a href="https://github.com/01BTC10/dht44"
             className="cta ghost"
             rel="noreferrer noopener">GitHub</a>
        </div>
      </section>

      <section className="three-up">
        <article>
          <h2><Link to="/protocol">Protocol reference</Link></h2>
          <p>
            Plain-language explainers of <Link to="/protocol/kademlia">Kademlia
            routing</Link>, the <Link to="/protocol/bep5">Mainline DHT
            (BEP 5)</Link>, <Link to="/protocol/bep44">BEP 44 mutable
            items</Link>, and <Link to="/protocol/bep51">BEP 51
            sample_infohashes</Link>, with annotated packet traces.
          </p>
        </article>
        <article>
          <h2><Link to="/lib">libbep44</Link></h2>
          <p>
            Embeddable C library: <code>bep44_open</code>, <code>bep44_step</code>,
            keygen, mutable + immutable put/get. Hides the DHT engine behind a
            small async API. Persistence + UPnP + auto-republish included.
          </p>
        </article>
        <article>
          <h2><Link to="/dashboard/peers">Live dashboard</Link></h2>
          <p>
            Real-time observation of the public Mainline DHT — peer counts,
            queries-per-minute, BEP 51 infohash sampling, classifier scores
            (crawler / monitor / honeypot), and a 3D peer-graph view.
          </p>
        </article>
      </section>

      <section className="latest">
        <h2>Recent writing</h2>
        <ul>
          <li><Link to="/blog/dht-size">How big is the BitTorrent DHT, really?</Link> — methodology + live numbers.</li>
          <li><Link to="/blog/classifying-peers">Detecting crawlers, monitors and honeypots in the DHT</Link></li>
          <li><Link to="/blog/embed-dht-c-app">Embedding a BitTorrent DHT in your C app</Link></li>
          <li><Link to="/blog/kademlia-vs-chord">Kademlia vs Chord vs Pastry: which one and why</Link></li>
        </ul>
      </section>
    </>
  );
}
