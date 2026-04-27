import { Link } from "react-router-dom";
import SEO from "../../components/SEO";
import ArticleLayout from "../../components/ArticleLayout";
import { techArticle } from "./_helpers";

const PATH = "/protocol/bep51";
const TITLE = "BEP 51 sample_infohashes — Enumerating the BitTorrent DHT";
const DESC = "How an active DHT crawler walks the keyspace using BEP 51's sample_infohashes query. Rate limits, dedup strategies, and what crawlers actually do with the output.";

export default function Bep51() {
  return (
    <>
      <SEO
        title={TITLE} description={DESC} path={PATH} type="article"
        jsonLd={techArticle(PATH, TITLE, DESC,
          "bep 51, sample_infohashes, dht crawler, bittorrent, kademlia enumeration")}
      />
      <ArticleLayout
        crumbs={[
          { label: "Home", to: "/intro" },
          { label: "Protocol", to: "/protocol" },
          { label: "BEP 51" },
        ]}
        title={TITLE}
        lede="BEP 51 adds one query to the Mainline DHT — sample_infohashes — that lets a node ask another node for a sample of the infohashes it knows about. It's the foundation of every modern BitTorrent DHT crawler."
      >
        <h2>Why it exists</h2>
        <p>
          Before BEP 51, enumerating the DHT meant guessing. To find live
          infohashes you'd issue <code>get_peers</code> for every random
          target you could think of, hoping to be near an active swarm.
          Hit rate was abysmal — the keyspace is 2^160 large and active
          infohashes are sparse.
        </p>
        <p>
          BEP 51 (proposed 2017, widely deployed by 2019) lets a node
          publish "here's the set of infohashes I'm currently storing" on
          demand. The sample is small (typically 20 entries), but querying
          enough of the network's nodes lets you reconstruct most of the
          live keyspace within hours.
        </p>

        <h2>The query</h2>
        <pre><code>{`Q: d 1:a d 2:id 20:<our>
              6:target 20:<random target>
              4:want l 2:n4 2:n6 e
            e
          1:q 17:sample_infohashes
          1:t 2:aa
          1:y 1:q
        e

R: d 1:r d 2:id 20:<their>
              8:interval i<seconds>e        (refresh hint)
              5:nodes <closer nodes>
              3:num i<total infohashes stored>e
              7:samples <N × 20-byte infohash>
            e
          1:t 2:aa 1:y 1:r e`}</code></pre>
        <p>
          Important fields:
        </p>
        <ul>
          <li><code>num</code> — total count of infohashes the responder
            currently holds. Useful for estimating the network's total
            stored set.</li>
          <li><code>samples</code> — concatenated 20-byte infohashes,
            randomly drawn from the responder's storage. Length is
            implementation choice; libtorrent caps at 20 entries.</li>
          <li><code>interval</code> — minimum seconds before the
            responder will return a fresh sample. Polite crawlers
            respect this.</li>
        </ul>
        <p>
          The <code>target</code> in the query is a hint for which part of
          the keyspace the requester is interested in, but most
          implementations ignore it and return a global random sample.
        </p>

        <h2>Crawl strategy</h2>
        <p>
          dht44's crawler (<code>src/crawl.c</code>) runs N parallel
          workers. Each worker:
        </p>
        <ol>
          <li>Picks a random target.</li>
          <li>Walks Kademlia toward that target via <code>find_node</code>{" "}
            until it has the closest 24 nodes.</li>
          <li>Sends each one <code>sample_infohashes</code>.</li>
          <li>Inserts every returned infohash and node-pointer into the
            observation database.</li>
          <li>When the worker's shortlist is fully RESPONDED or FAILED,
            picks a new random target and repeats.</li>
        </ol>
        <p>
          With 8 workers and a global rate cap of 100 packets/sec
          (defaults), a single crawler observes ~25k unique infohashes per
          hour. Running for a week gets you most of what's actually live
          on the network.
        </p>

        <h2>What you get</h2>
        <p>
          The output isn't "every torrent ever" — only what's currently
          being announced via <code>announce_peer</code> on at least one
          DHT node. Estimates from{" "}
          <Link to="/blog/dht-size">our own crawler</Link> in 2026 put
          the active set around 8–12 million infohashes globally, with
          significant churn.
        </p>
        <p>
          What you don't get from sample_infohashes alone:
        </p>
        <ul>
          <li>The torrent name or file list. That's in the torrent's
            <code>info</code> dict, which isn't on the DHT — you need
            metadata exchange (BEP 9, "ut_metadata") with an actual swarm
            peer to fetch it.</li>
          <li>Size, comment, creation date, etc. Same — these are torrent
            metadata, not DHT data.</li>
          <li>How many peers are in the swarm. <code>get_peers</code>
            against the infohash gives you a peer list, but the count is
            implementation-dependent.</li>
        </ul>

        <h2>Rate limiting and politeness</h2>
        <p>
          The DHT is a shared community resource. A crawler that hammers
          one bucket gets blacklisted by libtorrent (which actively
          tracks burst rates per source IP). Politeness rules dht44 follows:
        </p>
        <ul>
          <li><strong>Global rate cap.</strong> Default 100 outbound
            queries/sec across all workers. Tunable via
            <code>--crawl-pps</code>.</li>
          <li><strong>Per-node interval.</strong> Respect the responder's
            advertised <code>interval</code> field. Don't re-query before
            it expires.</li>
          <li><strong>Don't store-spam.</strong> The crawler is read-only;
            it never sends <code>announce_peer</code> or
            <code>put</code> for content it doesn't actually have.</li>
          <li><strong>Realistic node ID.</strong> Use a stable, BEP 42 -
            secured node ID. Random per-query IDs look like Sybil attacks
            and get filtered.</li>
        </ul>

        <h2>What clients support it</h2>
        <p>
          libtorrent: yes (since 2.0). qBittorrent inherits this. uTorrent:
          yes (modern versions). Transmission: yes (fairly recent).
          BitComet: partial. Older clients: no — they reply with
          <code>e: [204, "Method unknown"]</code>.
        </p>
        <p>
          That last point matters: a crawler will hit a fair number of nodes
          that don't speak BEP 51. dht44's classifier records this as a
          weak negative signal — peers that don't support BEP 51 are
          either old or not real BitTorrent clients.
        </p>

        <h2>What the dashboard does with the data</h2>
        <p>
          The crawler feeds infohashes into the <code>infohashes</code>{" "}
          table. The dashboard's{" "}
          <Link to="/dashboard/infohashes">Infohashes tab</Link> shows
          recent entries with first/last seen timestamps. The{" "}
          <code>infohash_sources</code> table tracks which nodes
          announced or sampled which hash, which is what makes the 3D
          peer-graph view possible.
        </p>

        <h2>References</h2>
        <ul>
          <li><a href="https://www.bittorrent.org/beps/bep_0051.html">BEP 51</a> — official spec.</li>
          <li><a href="https://github.com/arvidn/libtorrent/pull/943">libtorrent PR #943</a> — the canonical implementation reference.</li>
          <li><Link to="/blog/dht-size">How big is the DHT, really?</Link> — what BEP 51 enumeration tells us about the network's size.</li>
        </ul>
      </ArticleLayout>
    </>
  );
}
