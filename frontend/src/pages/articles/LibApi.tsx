import { Link } from "react-router-dom";
import SEO from "../../components/SEO";
import ArticleLayout from "../../components/ArticleLayout";
import { techArticle } from "./_helpers";

const PATH = "/lib/api";
const TITLE = "libbep44 API Reference";
const DESC = "Every public function in libbep44.h: signature, description, copy-pastable example, and explicit error cases. Built from the canonical README.";

export default function LibApi() {
  return (
    <>
      <SEO
        title={TITLE} description={DESC} path={PATH} type="article"
        jsonLd={techArticle(PATH, TITLE, DESC,
          "libbep44, api reference, bep 44, bittorrent dht, c library, ed25519")}
      />
      <ArticleLayout
        crumbs={[
          { label: "Home", to: "/" },
          { label: "Library", to: "/lib" },
          { label: "API" },
        ]}
        title={TITLE}
        lede="Per-function reference. Each entry has signature, description, a copy-pastable example, and an explicit error list. Anchor IDs match function names so AI agents and search results can deep-link."
      >
        <h2>Constants</h2>
        <table>
          <thead>
            <tr><th>Name</th><th>Value</th><th>Meaning</th></tr>
          </thead>
          <tbody>
            <tr><td><code>BEP44_PK_LEN</code></td><td>32</td><td>Ed25519 public key bytes</td></tr>
            <tr><td><code>BEP44_SK_LEN</code></td><td>64</td><td>Ed25519 secret key (libsodium combined form)</td></tr>
            <tr><td><code>BEP44_SIG_LEN</code></td><td>64</td><td>Ed25519 signature bytes</td></tr>
            <tr><td><code>BEP44_TARGET_LEN</code></td><td>20</td><td>SHA-1 target bytes</td></tr>
            <tr><td><code>BEP44_VALUE_MAX</code></td><td>1000</td><td>Max bencoded value length (BEP 44 spec cap)</td></tr>
            <tr><td><code>BEP44_SALT_MAX</code></td><td>64</td><td>Max salt length (BEP 44 spec cap)</td></tr>
          </tbody>
        </table>

        <h2>Types</h2>
        <p>
          <code>bep44_ctx_t</code> — opaque DHT context. Created by{" "}
          <a href="#bep44_open"><code>bep44_open</code></a>, freed by{" "}
          <a href="#bep44_close"><code>bep44_close</code></a>. One per
          process.
        </p>
        <p>
          <code>bep44_keypair_t</code>: <code>{`{ uint8_t pk[32]; uint8_t sk[64]; }`}</code>.
          The secret key is the libsodium 64-byte combined form (seed + pk).
        </p>
        <p><code>bep44_opts_t</code>:</p>
        <table>
          <thead><tr><th>Field</th><th>Type</th><th>Meaning</th></tr></thead>
          <tbody>
            <tr><td><code>port</code></td><td>int</td><td>UDP port (0 = OS pick)</td></tr>
            <tr><td><code>state_dir</code></td><td>const char *</td><td><strong>Required.</strong> Where node id, warm-start nodes, stored items live</td></tr>
            <tr><td><code>bootstrap_routers</code></td><td>int</td><td>Non-zero = ping public routers on open</td></tr>
            <tr><td><code>use_upnp</code></td><td>int</td><td>Non-zero = ask the gateway to forward <code>port</code> via UPnP IGD</td></tr>
            <tr><td><code>upnp_lifetime_sec</code></td><td>int</td><td>UPnP lease; 0 defaults 3600</td></tr>
            <tr><td><code>republish_minutes</code></td><td>int</td><td>Auto-republish cadence; 0 defaults 60; negative disables</td></tr>
          </tbody>
        </table>
        <p><code>bep44_put_result_t</code>: <code>success</code> (1 if any peer ack'd), <code>stored_count</code>, <code>err_code</code>.</p>
        <p><code>bep44_get_result_t</code>: <code>found</code>, <code>is_mutable</code>, <code>pk</code>, <code>seq</code>, <code>sig</code>, <code>value</code>, <code>value_len</code>. The <code>value</code> pointer is valid only inside the callback.</p>
        <p>Callbacks: <code>bep44_put_cb(const bep44_put_result_t*, void *user)</code>, <code>bep44_get_cb(const bep44_get_result_t*, void *user)</code>. Fire from inside <a href="#bep44_step"><code>bep44_step</code></a>, never from inside the queueing call.</p>

        {/* ============================== Lifecycle ============================== */}

        <h2>Lifecycle</h2>

        <h3 id="bep44_open"><code>bep44_open</code></h3>
        <pre><code>bep44_ctx_t *bep44_open(const bep44_opts_t *opts);</code></pre>
        <p>
          Bind the UDP socket, load (or create) the persistent node id,
          install the inbound BEP 44 server, and optionally ping the
          public bootstrap routers. <strong>One context per process</strong>{" "}
          — a second open in the same process returns <code>NULL</code>.
        </p>
        <pre><code>{`bep44_opts_t opts = {
    .port = 6881,
    .state_dir = "./libbep44_state",
    .bootstrap_routers = 1,
    .republish_minutes = 60,
};
bep44_ctx_t *ctx = bep44_open(&opts);
if (!ctx) {
    fprintf(stderr, "bep44_open failed\\n");
    return 1;
}`}</code></pre>
        <p><strong>Errors</strong>: <code>NULL</code> if <code>opts</code> or <code>opts-&gt;state_dir</code> is NULL, the dir can't be created, a context is already open in this process, the UDP port is bound, or libsodium fails to init.</p>

        <h3 id="bep44_close"><code>bep44_close</code></h3>
        <pre><code>void bep44_close(bep44_ctx_t *ctx);</code></pre>
        <p>
          Persist warm-start nodes, fire any pending callbacks with{" "}
          <code>success=0</code> / <code>found=0</code> so user closures
          can be freed, release the UDP socket. Safe on <code>NULL</code>{" "}
          or already-closed.
        </p>
        <p><strong>Errors</strong>: cannot fail.</p>

        <h3 id="bep44_fd"><code>bep44_fd</code></h3>
        <pre><code>int bep44_fd(const bep44_ctx_t *ctx);</code></pre>
        <p>The UDP file descriptor, for integrating with your own select / poll / epoll loop. Returns <code>-1</code> if not open.</p>
        <pre><code>{`int fd = bep44_fd(ctx);
fd_set rfds; FD_ZERO(&rfds); FD_SET(fd, &rfds);
struct timeval tv = { 0, 250 * 1000 };
if (select(fd + 1, &rfds, NULL, NULL, &tv) > 0)
    bep44_step(ctx, 0);  /* fd is readable, drain it */
else
    bep44_step(ctx, 0);  /* timeout, just tick */`}</code></pre>

        <h3 id="bep44_step"><code>bep44_step</code></h3>
        <pre><code>int bep44_step(bep44_ctx_t *ctx, int timeout_ms);</code></pre>
        <p>
          Drive one iteration of the event loop. Pumps DHT housekeeping,
          sleeps up to <code>timeout_ms</code> waiting for an inbound
          packet, drains all packets that arrived, dispatches lookup /
          put / get callbacks. Returns 0 on success, -1 on fatal error.
        </p>
        <pre><code>{`while (running) {
    if (bep44_step(ctx, 250) < 0) break;
}`}</code></pre>

        <h3 id="bep44_good_nodes"><code>bep44_good_nodes</code></h3>
        <pre><code>int bep44_good_nodes(const bep44_ctx_t *ctx);</code></pre>
        <p>Approximate count of "good" routing-table peers (responded within last 15 min). Useful as a readiness probe before put/get.</p>

        <h3 id="bep44_add_peer"><code>bep44_add_peer</code></h3>
        <pre><code>int bep44_add_peer(bep44_ctx_t *ctx, const char *ipv4, uint16_t port);</code></pre>
        <p>
          Inject a known IPv4 peer. Library sends a ping; the peer is
          promoted to "good" once its pong arrives via{" "}
          <a href="#bep44_step"><code>bep44_step</code></a>.
        </p>
        <pre><code>{`bep44_add_peer(ctx, "203.0.113.10", 6881);
for (int i = 0; i < 20; i++) bep44_step(ctx, 100);`}</code></pre>

        {/* ============================== Keys ============================== */}

        <h2>Keys</h2>

        <h3 id="bep44_keygen"><code>bep44_keygen</code></h3>
        <pre><code>int bep44_keygen(bep44_keypair_t *out);</code></pre>
        <p>Fresh Ed25519 keypair from the OS CSPRNG (libsodium). Returns 0 on success.</p>
        <pre><code>{`bep44_keypair_t kp;
if (bep44_keygen(&kp) != 0) return 1;
/* kp.pk = 32 bytes, kp.sk = 64 bytes */`}</code></pre>

        <h3 id="bep44_keypair_from_sk"><code>bep44_keypair_from_sk</code></h3>
        <pre><code>int bep44_keypair_from_sk(bep44_keypair_t *out, const uint8_t sk[BEP44_SK_LEN]);</code></pre>
        <p>Recover a full keypair from a 64-byte libsodium secret key (which embeds the seed + pk). Use this when your app stores secret keys in its own format.</p>

        <h3 id="bep44_save_key"><code>bep44_save_key</code></h3>
        <pre><code>int bep44_save_key(const char *path, const bep44_keypair_t *kp);</code></pre>
        <p>
          Atomic write of the keypair as JSON, mode 0600. The format is
          identical to <code>dht44 keygen</code>:
        </p>
        <pre><code>{`{
  "keys": [
    { "sk": "<128-hex>", "pk": "<64-hex>" }
  ]
}`}</code></pre>

        <h3 id="bep44_load_key"><code>bep44_load_key</code></h3>
        <pre><code>int bep44_load_key(const char *path, bep44_keypair_t *out);</code></pre>
        <p>Read the JSON keyfile, decode <code>keys[0].sk</code>, recover <code>pk</code>. The file may contain multiple keys; only the first is loaded.</p>
        <pre><code>{`bep44_keypair_t kp;
if (bep44_load_key("./state/identity.json", &kp) != 0) {
    bep44_keygen(&kp);
    bep44_save_key("./state/identity.json", &kp);
}`}</code></pre>

        {/* ============================== Targets ============================== */}

        <h2>Targets</h2>

        <h3 id="bep44_target_mutable"><code>bep44_target_mutable</code></h3>
        <pre><code>{`int bep44_target_mutable(const uint8_t pk[BEP44_PK_LEN],
                         const char *salt, size_t salt_len,
                         uint8_t target[BEP44_TARGET_LEN]);`}</code></pre>
        <p>BEP 44 target: <code>SHA1(pk ‖ salt)</code>. Pass <code>salt = NULL, salt_len = 0</code> for unsalted.</p>

        <h3 id="bep44_target_immutable"><code>bep44_target_immutable</code></h3>
        <pre><code>{`int bep44_target_immutable(const uint8_t *v_bencoded, size_t v_len,
                           uint8_t target[BEP44_TARGET_LEN]);`}</code></pre>
        <p>BEP 44 immutable target: <code>SHA1(v_bencoded)</code>. The input must already be bencoded (e.g. <code>"5:hello"</code>).</p>

        {/* ============================== Operations ============================== */}

        <h2>Operations</h2>

        <p>
          All four are <strong>non-blocking</strong>: they queue work and
          return immediately. Completion arrives via the user-supplied
          callback fired from inside{" "}
          <a href="#bep44_step"><code>bep44_step</code></a>.
        </p>

        <h3 id="bep44_put_mutable"><code>bep44_put_mutable</code></h3>
        <pre><code>{`int bep44_put_mutable(bep44_ctx_t *ctx,
                      const bep44_keypair_t *kp,
                      const char *salt, size_t salt_len,
                      int64_t seq, int64_t cas,
                      const uint8_t *v_bencoded, size_t v_len,
                      bep44_put_cb cb, void *user);`}</code></pre>
        <p>
          Sign locally, run an iterative lookup to find the 8 closest
          peers to <code>SHA1(pk ‖ salt)</code>, store on each one.
          <code>seq</code> must be strictly greater than any previously
          stored seq for this target. <code>cas = -1</code> skips
          compare-and-swap. <code>v_bencoded</code> must already be
          bencoded.
        </p>
        <pre><code>{`typedef struct { int done; int acks; } put_state;
static void on_put(const bep44_put_result_t *r, void *u) {
    put_state *ps = u; ps->done = 1; ps->acks = r->stored_count;
}

bep44_keypair_t kp; bep44_keygen(&kp);
const uint8_t v[] = "5:hello";
put_state ps = { 0 };
bep44_put_mutable(ctx, &kp, NULL, 0,
                  /*seq=*/ 1, /*cas=*/ -1,
                  v, sizeof(v) - 1,
                  on_put, &ps);
while (!ps.done) bep44_step(ctx, 250);`}</code></pre>

        <h3 id="bep44_put_immutable"><code>bep44_put_immutable</code></h3>
        <pre><code>{`int bep44_put_immutable(bep44_ctx_t *ctx,
                        const uint8_t *v_bencoded, size_t v_len,
                        bep44_put_cb cb, void *user);`}</code></pre>
        <p>Like put_mutable but for immutable items. Target is implicitly <code>SHA1(v_bencoded)</code>.</p>

        <h3 id="bep44_get_mutable"><code>bep44_get_mutable</code></h3>
        <pre><code>{`int bep44_get_mutable(bep44_ctx_t *ctx,
                      const uint8_t pk[BEP44_PK_LEN],
                      const char *salt, size_t salt_len,
                      bep44_get_cb cb, void *user);`}</code></pre>
        <p>
          Fetch the latest mutable item under <code>SHA1(pk ‖ salt)</code>.
          Library verifies signatures; <code>result.found = 0</code> if
          nothing retrievable or all candidates failed verification.
        </p>

        <h3 id="bep44_get_immutable"><code>bep44_get_immutable</code></h3>
        <pre><code>{`int bep44_get_immutable(bep44_ctx_t *ctx,
                        const uint8_t target[BEP44_TARGET_LEN],
                        bep44_get_cb cb, void *user);`}</code></pre>
        <p>
          Fetch an immutable item by precomputed target. No signature
          verification (immutable items aren't signed); recompute{" "}
          <a href="#bep44_target_immutable"><code>bep44_target_immutable</code></a>{" "}
          and compare if you want the integrity check.
        </p>

        <h2>Threading</h2>
        <p>
          Single-threaded. All public functions on <code>bep44_ctx_t</code>{" "}
          must be called from the same thread, and{" "}
          <a href="#bep44_step"><code>bep44_step</code></a> is the only
          place callbacks fire. Multi-threaded code marshals into the
          libbep44 thread (e.g. via a pipe whose read fd you select on
          alongside <a href="#bep44_fd"><code>bep44_fd</code></a>). One
          context per process.
        </p>

        <h2>See also</h2>
        <ul>
          <li><Link to="/lib/quickstart">Quickstart</Link> — end-to-end runnable example.</li>
          <li><Link to="/lib/persistence">Persistence and republish</Link> — what state_dir holds and how items stay alive.</li>
          <li><Link to="/protocol/bep44">BEP 44 in depth</Link> — the wire format these functions implement.</li>
          <li><a href="https://github.com/01BTC10/dht44/blob/libbep44/include/libbep44.h">include/libbep44.h on GitHub</a> — the canonical header.</li>
        </ul>
      </ArticleLayout>
    </>
  );
}
