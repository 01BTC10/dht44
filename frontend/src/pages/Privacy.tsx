import SEO from "../components/SEO";
import ArticleLayout from "../components/ArticleLayout";

export default function Privacy() {
  return (
    <>
      <SEO
        title="Privacy Policy — dht44"
        description="What dht44.com collects about visitors, what the dht44 crawler observes about BitTorrent DHT peers, retention windows, and how to request data removal."
        path="/privacy"
        type="article"
      />
      <ArticleLayout
        crumbs={[{ label: "Home", to: "/intro" }, { label: "Privacy" }]}
        title="Privacy Policy"
        lede="Two distinct privacy stories live on this site: what we collect about you when you visit dht44.com, and what the crawler observes about peers on the public BitTorrent DHT. Both are documented below."
      >
        <p className="small">
          Last updated: 2026-04-27. We will revise the date when content
          materially changes; non-material edits (typos, formatting) won't
          bump the date.
        </p>

        <h2>1. About visitors to dht44.com</h2>

        <h3>What we collect</h3>
        <ul>
          <li>
            <strong>Cloudflare Web Analytics</strong>, auto-injected by
            the CF proxy. Cloudflare's analytics is cookieless, samples
            page URL, referrer, viewport, browser/OS, and country
            (derived from the request's edge IP, which Cloudflare does
            not store in the analytics dataset). No cross-site tracking,
            no advertising profile linkage. Cloudflare's privacy
            documentation describes the full retention and processing
            model.
          </li>
          <li>
            <strong>Cloudflare</strong> also sits in front of the site
            for DNS, edge TLS, and bot management. Cloudflare sets a
            single cookie, <code>__cf_bm</code>, classified by Cloudflare
            as "strictly necessary" — it expires after 30 minutes and is
            scoped to bot detection, not advertising. We do not use
            Cloudflare Turnstile or any other CF challenge feature on
            this site.
          </li>
          <li>
            <strong>Server logs.</strong> nginx access logs include the
            full IP, the requested URL, response status, and User-Agent.
            They rotate daily and the previous day's log is gzipped and
            kept for 7 days. After 7 days the logs are deleted irretrievably.
          </li>
        </ul>

        <h3>What we don't collect</h3>
        <ul>
          <li>No Google Analytics, no Facebook Pixel, no Hotjar, no Segment.</li>
          <li>No advertising network code.</li>
          <li>No cross-site tracking cookies.</li>
          <li>No social media embeds (no Twitter cards beyond meta tags,
            no embedded YouTube, no Disqus, etc.).</li>
          <li>No fingerprinting libraries.</li>
        </ul>

        <h3>Why no cookie consent banner</h3>
        <p>
          Under the EU GDPR / ePrivacy Directive, consent banners are
          required only for cookies and similar technologies that aren't
          strictly necessary for the service. Our analytics is cookieless
          by design and the only cookie we set (<code>__cf_bm</code>) is
          classified as strictly necessary. There's nothing to consent to.
          If we ever add something that would require a banner, we will
          either remove it or add the banner — we won't quietly start
          tracking you.
        </p>

        <h3>Your rights</h3>
        <p>
          Under GDPR, CCPA, and similar regimes you have the right to ask
          what we know about you, to correct it, to have it deleted, to
          export it, and to object to processing. Email{" "}
          <a href="mailto:tayaoutlk@gmail.com">tayaoutlk@gmail.com</a>{" "}
          and we will respond within 30 days. If you're a California
          resident, you also have the right to opt out of the "sale" of
          personal information — we don't sell data, but the right
          formally exists.
        </p>

        <h2>2. About the BitTorrent DHT crawler</h2>

        <p>
          The dashboard at <a href="/dashboard/peers">dht44.com/dashboard</a>{" "}
          is a passive observer of the public BitTorrent Mainline DHT — the
          same DHT that every modern BitTorrent client (uTorrent,
          qBittorrent, libtorrent, and so on) participates in by default.
          When a peer queries our node, or when we query theirs, we record
          the address, the query type, and the queried hash. This is exactly
          the information any other DHT participant sees.
        </p>

        <h3>What's in the public dashboard</h3>
        <ul>
          <li><strong>Truncated IP addresses</strong> — IPv4 to /24, IPv6 to /48.
            The last octet (or last 80 bits for IPv6) is replaced with zero
            before any data leaves the daemon. ASN, country, and city
            attribution remain intact, but identifying a specific household
            from the public dashboard is not possible.</li>
          <li><strong>Aggregated counts</strong> — total peers, queries per
            minute, infohashes observed, BEP 44 items observed, classifier
            distributions (crawler / monitor / honeypot / ok).</li>
          <li><strong>Public BitTorrent metadata</strong> that our node received —
            client version strings, protocol extensions advertised, node IDs
            (which are random and not personally identifying).</li>
          <li><strong>Infohashes</strong> the network is gossiping about. These
            identify content, not people. We make no claim about the
            legality, copyright status, or content of any specific
            infohash — they're 20 bytes of SHA-1 output that we record
            because the protocol broadcasts them.</li>
        </ul>

        <h3>What's NOT in the public dashboard</h3>
        <ul>
          <li>Full peer IP addresses (only redacted /24 or /48 blocks).</li>
          <li>Mappings from peer to actual content downloaded.</li>
          <li>Anything that links a DHT peer to a real-world identity beyond
            ASN-level attribution.</li>
        </ul>

        <h3>Data retention for the crawler</h3>
        <p>
          Per the daemon's <code>--prune-days</code> default, peers that
          have not been observed in 7 days are deleted from the operator's
          internal database. The public API serves the same window. There
          is no archival; deleted data is not recovered.
        </p>

        <h3>Lawful basis (GDPR Art. 6)</h3>
        <p>
          We process this data under <strong>legitimate interest</strong>{" "}
          (Art. 6(1)(f)) for academic and operational research into the
          health of the BitTorrent DHT. The dataset is comparable in scope
          and intent to published research from{" "}
          <a href="https://www.netsec.ethz.ch/">ETH Zurich</a>,{" "}
          <a href="https://www.cl.cam.ac.uk/">Cambridge</a>, and others on
          the same network. The crawler does not perform active probing
          beyond the BEP 5 / BEP 44 / BEP 51 standards and is rate-limited
          to avoid being abusive.
        </p>

        <h3>How to request removal</h3>
        <p>
          If your IP appears in our crawler dataset and you want it
          excluded permanently, email{" "}
          <a href="mailto:tayaoutlk@gmail.com">tayaoutlk@gmail.com</a>{" "}
          with the address (or /24 block — that's the resolution we keep).
          We will add it to a deny-list that runs at observation time, so
          subsequent traffic from that block is dropped before storage.
          Existing rows for that block will also be deleted within 7 days
          of the request.
        </p>

        <h2>3. Hosting and jurisdiction</h2>
        <ul>
          <li>The website is served from a VPS in (operator-disclosed
            location) behind Cloudflare. Cloudflare's edge cache may store
            a static copy of any non-personalized response.</li>
          <li>The crawler database lives on the same operator's residential
            ISP connection in (jurisdiction). It does not leave that machine.</li>
          <li>
            The operator is in (jurisdiction) and is the data controller for
            the purposes of GDPR.
          </li>
        </ul>
        <p className="small">
          (The locations above are placeholders pending the actual VPS
          provisioning. Replace with concrete jurisdictions before launch.)
        </p>

        <h2>4. Source code</h2>
        <p>
          Everything described here is implemented in open source.
          The redaction logic is in{" "}
          <a href="https://github.com/01BTC10/dht44/blob/crawler/src/redact.c">
            <code>src/redact.c</code>
          </a>; the daemon flag is{" "}
          <code>--web-show-full-ips</code> (default off — redaction on);
          retention is{" "}
          <code>--prune-days</code> (default 7).
        </p>

        <h2>5. Changes to this policy</h2>
        <p>
          Material changes will be announced on the home page with at least
          14 days' notice before they take effect. The full edit history is
          available in the project's git repository.
        </p>
      </ArticleLayout>
    </>
  );
}
