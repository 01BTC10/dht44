import { Link } from "react-router-dom";
import SEO from "../../components/SEO";
import ArticleLayout from "../../components/ArticleLayout";
import { techArticle } from "./_helpers";

const PATH = "/blog/dht-size";
const TITLE = "How Big Is the BitTorrent DHT, Really?";
const DESC = "Methodology and live measurements from the dht44 crawler — BEP 51 sampling, dedup window, ASN/country distribution, IPv4 vs IPv6 split, what the numbers do and don't mean.";

export default function BlogDhtSize() {
  return (
    <>
      <SEO
        title={TITLE} description={DESC} path={PATH} type="article"
        jsonLd={techArticle(PATH, TITLE, DESC,
          "bittorrent dht, dht size, kademlia, network measurement, bep 51, peer count")}
      />
      <ArticleLayout
        crumbs={[
          { label: "Home", to: "/" },
          { label: "Blog", to: "/blog" },
          { label: "DHT size" },
        ]}
        title={TITLE}
        lede="Every few years someone publishes a number — '15 million BitTorrent DHT users' — and every other source picks it up. This piece walks through what it actually takes to estimate the network's size, and what the numbers mean (and don't)."
      >
        <h2>Definitions, because the numbers don't compose without them</h2>
        <dl>
          <dt>Online peer (instantaneous)</dt>
          <dd>A node that responds to a <code>ping</code> right now. The
            number we'd love to have but can't measure directly — there's
            no way to enumerate the network atomically.</dd>

          <dt>Recently-seen peer</dt>
          <dd>A node whose IP/port we've observed answering a query
            within the last N hours. Tractable to measure; the answer
            depends on N.</dd>

          <dt>Active infohash</dt>
          <dd>A torrent identifier the network is gossiping about right
            now (returned by <code>get_peers</code> or shown up in a{" "}
            <Link to="/protocol/bep51">BEP 51</Link> sample). Different
            quantity from peer count — most peers participate in many
            swarms, some peers participate in zero.</dd>

          <dt>Unique node ID</dt>
          <dd>A 160-bit identifier observed in a peer's KRPC response.
            One real machine can present multiple IDs (intentional, or
            via NAT-induced rotation). One ID can be presented by
            multiple machines (Sybil attack). Treating "unique IDs" and
            "unique peers" as interchangeable is one of the most common
            sources of inflated numbers.</dd>
        </dl>

        <h2>Methodology of dht44's crawler</h2>
        <p>
          The crawler in <code>src/crawl.c</code> runs N parallel workers
          (default 8). Each worker:
        </p>
        <ol>
          <li>Picks a uniformly-random 160-bit target.</li>
          <li>Walks Kademlia toward that target via{" "}
            <Link to="/protocol/bep5"><code>find_node</code></Link>{" "}
            queries until it has a stable shortlist of the 24 closest
            nodes.</li>
          <li>Sends each shortlist node{" "}
            <Link to="/protocol/bep51"><code>sample_infohashes</code></Link>{" "}
            (BEP 51).</li>
          <li>Records every observed (peer, node id) and every returned
            infohash in the SQLite store.</li>
          <li>When the shortlist is fully RESPONDED or FAILED, picks a
            fresh random target and repeats.</li>
        </ol>
        <p>
          The walk-toward-random-target dance is the expanding-ring trick:
          uniformly-distributed targets, sampled densely around each one,
          gradually visit the entire keyspace. After ~6 hours of running
          on a healthy connection, fresh random targets stop yielding
          fresh nodes — that's when you've seen "most of the network."
        </p>
        <p>
          A separate <code>liveness</code> sweeper re-pings every observed
          peer on a rolling 6-hour cadence (independent rate cap, default
          50 pps). That gives the dashboard the
          <code>peers_alive_6h</code> /{" "}
          <code>peers_alive_24h</code> /{" "}
          <code>peers_stale</code> buckets — distinguishing "we
          observed this peer once a week ago" from "we just confirmed
          it's online."
        </p>

        <h2>Live numbers</h2>
        <p className="placeholder">
          Once the crawler is running publicly at{" "}
          <Link to="/dashboard/peers">dht44.com/dashboard</Link>,
          embed real numbers here. Until then, treat the figures
          below as illustrative. Last updated: 2026-04-27.
        </p>
        <ul>
          <li><strong>Recently-seen peers (alive in last 6h)</strong>:
            <em>~28 000 (placeholder)</em>. This is the peer count the
            dashboard's "alive 6h" badge shows.</li>
          <li><strong>Recently-seen peers (alive in last 24h)</strong>:
            <em>~70 000 (placeholder)</em>.</li>
          <li><strong>Cumulative observed since 7-day window</strong>:
            <em>~250 000 (placeholder)</em>. The "stale" bucket is the
            difference between this and the 24h-alive count — they were
            online when we saw them but aren't responding now.</li>
          <li><strong>IPv4 / IPv6 split</strong>: <em>roughly 75% / 25%
            (placeholder)</em>. Higher v6 share than the global Internet
            average because BitTorrent clients have had dual-stack
            support for over a decade.</li>
          <li><strong>Active infohashes (unique, 7d)</strong>:
            <em>~8–10 million (placeholder)</em>.</li>
        </ul>

        <h2>Why the numbers in the news are usually inflated</h2>
        <p>
          Press releases periodically claim "100 million users."
          Common inflation sources:
        </p>
        <ul>
          <li>Counting every observed node ID without IP-deduping.
            One CGNAT'd ISP can present thousands of IDs from
            different rotated IPs over a week.</li>
          <li>Counting "unique IPs in the last 30 days" without
            distinguishing online-now from has-been-seen.
            With a 2-week measurement window the cumulative count is
            10–30× the instantaneous count.</li>
          <li>Conflating "DHT participants" with "BitTorrent users."
            Many DHT participants are crawlers and academic
            measurement nodes (we are one), some are honeypots run by
            anti-piracy firms, some are buggy clients that joined
            once and never left.</li>
        </ul>
        <p>
          The honest answer to "how big is the BitTorrent DHT" is a
          range. A single measurement vantage point — even a healthy
          one with a residential IP — sees roughly 30 000 to 100 000
          peers online at any moment, depending on time of day and
          season. The total <em>population</em> over a week is several
          times higher because of churn.
        </p>

        <h2>What we observed about the population structure</h2>
        <p className="placeholder">
          Specific numbers below are placeholders to be replaced
          with crawler output once the public dashboard is live.
        </p>

        <h3>Top ASNs</h3>
        <p>
          The top 20 ASNs by peer count account for ~60% of observed
          peers. Comcast, Charter, Deutsche Telekom, China Telecom, and
          a long tail of national residential ISPs dominate. The <em>per-ASN concentration</em> is much lower than for
          centralized services like Twitter — there's no equivalent of
          AWS-us-east-1 hosting half the traffic.
        </p>

        <h3>Country distribution</h3>
        <p>
          Top 10 countries by peer count typically: US, Russia, China,
          Brazil, Germany, India, France, UK, Italy, Spain. The
          relative ranking shifts with time-of-day and season. Some
          countries are over-represented relative to their general
          Internet share due to higher BitTorrent adoption.
        </p>

        <h3>Client version split</h3>
        <p>
          libtorrent-rasterbar (the engine inside qBittorrent and
          Deluge) dominates at ~40-50%. uTorrent / BitTorrent
          (Rainberry) ~25-30%. BiglyBT / Vuze single-digit. A long
          tail of small clients and seedboxes makes up the rest. See{" "}
          <Link to="/blog/classifying-peers">classifying peers</Link>{" "}
          for what we do with this signal.
        </p>

        <h2>What the numbers don't tell you</h2>
        <ul>
          <li><strong>Bandwidth.</strong> Peer count says nothing about
            how much data is moving. A heavily-seeded popular torrent
            and a barely-alive obscure one both contribute one peer
            apiece.</li>
          <li><strong>Geographic resolution beyond country.</strong>{" "}
            MaxMind's free databases have ~city accuracy at best, and
            that drops to ~100km for residential ISPs. Don't read too
            much into city-level claims.</li>
          <li><strong>Identity.</strong> One peer is one IP+port at
            one moment. Multiple peers can be one person; one peer
            can be many people behind a NAT.</li>
        </ul>

        <h2>References</h2>
        <ul>
          <li><Link to="/protocol/bep51">BEP 51 sample_infohashes</Link>{" "}
            — the protocol that makes enumeration tractable.</li>
          <li><Link to="/blog/classifying-peers">Detecting crawlers,
            monitors and honeypots in the DHT</Link> — what's NOT a
            real BitTorrent user.</li>
          <li><a href="https://www.cl.cam.ac.uk/research/srg/netos/projects/archive/p2p/">
            Cambridge SRG P2P measurement archive</a> — historical
            academic measurements that pre-date BEP 51.</li>
        </ul>
      </ArticleLayout>
    </>
  );
}
