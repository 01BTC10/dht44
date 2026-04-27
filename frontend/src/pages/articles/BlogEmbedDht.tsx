import { Link } from "react-router-dom";
import SEO from "../../components/SEO";
import ArticleLayout from "../../components/ArticleLayout";
import { techArticle } from "./_helpers";

const PATH = "/blog/embed-dht-c-app";
const TITLE = "Embedding a BitTorrent DHT in Your C App";
const DESC = "When a daemon isn't what you want. Using libbep44 to publish and retrieve BEP 44 items from inside a larger C program — event-loop integration, persistence, threading.";

export default function BlogEmbedDht() {
  return (
    <>
      <SEO
        title={TITLE} description={DESC} path={PATH} type="article"
        jsonLd={techArticle(PATH, TITLE, DESC,
          "libbep44, embedded dht, c, bep 44, bittorrent, kademlia, p2p")}
      />
      <ArticleLayout
        crumbs={[
          { label: "Home", to: "/intro" },
          { label: "Blog", to: "/blog" },
          { label: "Embed DHT" },
        ]}
        title={TITLE}
        lede="Most BitTorrent DHT references assume you'll run a daemon and talk to it from your app over a socket. That's the wrong shape for a lot of programs. This piece is about the other shape: a single process that participates in the DHT directly via libbep44."
      >
        <h2>The case against a daemon</h2>
        <p>
          A separate DHT daemon makes sense when:
        </p>
        <ul>
          <li>Multiple unrelated apps on the box need DHT access (so the
            cost of the routing table amortizes).</li>
          <li>The daemon process needs root for some reason (it doesn't,
            for vanilla BEP 5 + 44).</li>
          <li>Your app is OK with the operational complexity of process
            supervision, IPC framing, schema versioning across the wire,
            and multi-second startup latency for fresh daemons.</li>
        </ul>
        <p>
          For most embedded P2P uses — a CLI tool that occasionally
          publishes a value, a daemon that wants to register an
          endpoint, a research notebook driving a live experiment — the
          daemon model is friction without payoff.
        </p>

        <h2>What "embedded" gets you</h2>
        <p>The libbep44 approach: link a static archive, call four functions, run the event loop yourself.</p>
        <ul>
          <li><strong>No IPC layer.</strong> No bencode-framed UNIX socket, no
            schema, no concurrency between client and server within your
            box.</li>
          <li><strong>Single process.</strong> systemd unit, container, ps,
            and your own crash dumps all see one thing.</li>
          <li><strong>Synchronous semantics.</strong> Your event loop owns
            time. You decide when DHT work runs and how it interleaves
            with the rest of your program.</li>
          <li><strong>Smaller deps.</strong> libsodium + OpenSSL + jansson +
            miniupnpc. Total runtime &lt; 5 MB.</li>
        </ul>

        <h2>The integration shape</h2>
        <p>
          libbep44 is single-threaded and non-blocking. You drive it by
          calling <Link to="/lib/api#bep44_step"><code>bep44_step(ctx, timeout_ms)</code></Link>{" "}
          repeatedly. That call:
        </p>
        <ol>
          <li>Runs DHT housekeeping (jech bucket maintenance, pending
            transaction timeouts, lookup deadlines).</li>
          <li>Sleeps up to <code>timeout_ms</code> waiting for a UDP
            packet (clamped down to whatever the next deadline needs,
            so it never oversleeps a callback).</li>
          <li>Drains every packet that arrived and dispatches.</li>
          <li>Fires any put/get callbacks that are now ready.</li>
        </ol>

        <h3>Pattern 1: dedicated DHT thread</h3>
        <p>
          Simplest if you already have multi-threading in your app.
          Spawn a thread that does <code>while (running) bep44_step(ctx, 250);</code>{" "}
          and marshal calls in/out via your usual concurrency primitive.
          libbep44 is single-threaded, so all{" "}
          <code>bep44_*</code> calls must come from this thread.
        </p>

        <h3>Pattern 2: integrate into an existing select/poll/epoll loop</h3>
        <p>
          Use{" "}
          <Link to="/lib/api#bep44_fd"><code>bep44_fd(ctx)</code></Link>{" "}
          to get the underlying UDP socket and add it to your existing
          fd set. Call <code>bep44_step(ctx, 0)</code> whenever it's
          readable AND on every loop tick (to drive the periodic
          housekeeping):
        </p>
        <pre><code>{`int dht_fd = bep44_fd(ctx);

while (running) {
    fd_set rfds; FD_ZERO(&rfds);
    FD_SET(dht_fd, &rfds);
    FD_SET(my_other_fd, &rfds);
    int maxfd = max(dht_fd, my_other_fd);
    struct timeval tv = { 0, 250 * 1000 };

    int sr = select(maxfd + 1, &rfds, NULL, NULL, &tv);

    /* Always step — even on timeout — so housekeeping runs. */
    bep44_step(ctx, 0);

    if (sr > 0 && FD_ISSET(my_other_fd, &rfds))
        my_handler();
}`}</code></pre>

        <h3>Pattern 3: libuv / libevent / etc.</h3>
        <p>
          Wrap the libbep44 fd as a poll handle in your event library.
          Tick <code>bep44_step</code> on read events AND on a timer
          (250–500 ms is fine). The timer is what drives lookup
          deadlines and the auto-republish loop; without it, callbacks
          for outstanding ops only fire when packets happen to arrive.
        </p>

        <h2>Persistence — what the library handles</h2>
        <p>
          libbep44 persists three things to the <code>state_dir</code>{" "}
          you pass to{" "}
          <Link to="/lib/api#bep44_open"><code>bep44_open</code></Link>:
        </p>
        <ul>
          <li><strong>Node ID</strong> — generated on first open, never
            rotated. Surviving across restarts is what gives your node
            "presence" in the network's routing tables.</li>
          <li><strong>Warm-start nodes</strong> — saved on close,
            re-injected on next open. Cuts re-bootstrap time from ~60s
            to maybe 10s.</li>
          <li><strong>Stored items</strong> — your puts AND any
            peer-origin puts your inbound server accepted. The library
            re-publishes them all every 60 min by default. See{" "}
            <Link to="/lib/persistence">persistence and republish</Link>.</li>
        </ul>
        <p>
          Your app doesn't need to track any of this. Open the ctx, do
          your puts/gets, drive <code>bep44_step</code>, close on exit.
        </p>

        <h2>Auth — it's local</h2>
        <p>
          Your secret key never leaves the calling process. The library
          signs put requests in-memory using libsodium's Ed25519
          implementation; the signed bytes go on the wire. The DHT
          daemon you'd otherwise run never sees the key — but in the
          embedded model the DHT daemon doesn't exist.
        </p>
        <p>
          Practically: load the key from disk via{" "}
          <Link to="/lib/api#bep44_load_key"><code>bep44_load_key</code></Link>,
          keep it in a <code>bep44_keypair_t</code> on the stack or in
          your app's globals, zero it on shutdown (libsodium's{" "}
          <code>sodium_memzero</code> is idiomatic — libbep44 uses it
          for the keypair on close).
        </p>

        <h2>NAT — what to do</h2>
        <p>
          If your app runs behind a NAT (typical for desktop apps), set{" "}
          <code>opts.use_upnp = 1</code> on a fixed port. libbep44 will
          map the port via UPnP IGD, log success or failure, and refresh
          the lease. If UPnP doesn't work (no IGD, ISP-grade CGNAT, etc.)
          you'll work as an outbound-only client — your puts still
          propagate to 8 storers, you just can't be in others' routing
          tables.
        </p>
        <p>
          For desktop apps, consider also: prompt the user once to set
          a stable port, retry UPnP on failure, fall back to a manual
          port-forward instructions page. This is what most embedded
          BT clients do.
        </p>

        <h2>Performance ceiling</h2>
        <p>
          A few rough numbers from a 2026 mid-range desktop running
          libbep44 idle (just routing-table maintenance, no app
          traffic):
        </p>
        <ul>
          <li>~20 KB/sec sustained UDP, mostly tiny packets.</li>
          <li>~10 MB resident, including jech routing-table buckets.</li>
          <li>&lt; 1% of one core.</li>
        </ul>
        <p>
          During an iterative lookup (one put or get): ~100 packets in,
          ~100 packets out, completes in 2–5 seconds. The library can
          handle 16 concurrent ops by default; you're more likely to be
          rate-limited by the network than by the library.
        </p>

        <h2>When NOT to embed</h2>
        <ul>
          <li>If your app is a short-lived CLI that runs for &lt; 30
            seconds, the cold-bootstrap cost outweighs the savings —
            you'll bootstrap, do one query, and exit before the
            routing table is useful. Either keep the daemon model or
            pre-warm via persisted <code>nodes.bin</code>.</li>
          <li>If you need multiple processes on the same box to share
            DHT presence, you really do want a daemon. Running two
            independent embedded contexts is fine but each has its
            own node id and routing table — wasted resources.</li>
          <li>If you can't run a long-lived process at all (cron jobs,
            serverless), the BEP 44 republish window means your value
            evaporates 2 hours after the run ends. Either accept the
            short lifetime or move to a hosted daemon.</li>
        </ul>

        <h2>Where this came from</h2>
        <p>
          libbep44 was extracted from the dht44 daemon as a clean
          embeddable subset. Same protocol code, different shape. The{" "}
          <Link to="/lib">library landing page</Link> has the full API
          summary; the <Link to="/lib/quickstart">quickstart</Link> is
          a compile-and-run starting point.
        </p>
      </ArticleLayout>
    </>
  );
}
