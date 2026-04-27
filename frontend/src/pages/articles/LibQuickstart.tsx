import { Link } from "react-router-dom";
import SEO from "../../components/SEO";
import ArticleLayout from "../../components/ArticleLayout";
import { techArticle } from "./_helpers";

const PATH = "/lib/quickstart";
const TITLE = "libbep44 Quickstart — Embed BEP 44 in C";
const DESC = "Minimal end-to-end example using libbep44: open the DHT context, generate a key, publish a mutable item, retrieve it. Build, link, run.";

export default function LibQuickstart() {
  return (
    <>
      <SEO
        title={TITLE} description={DESC} path={PATH} type="article"
        jsonLd={techArticle(PATH, TITLE, DESC,
          "libbep44, bep 44, bittorrent dht, c library, quickstart, embedded dht")}
      />
      <ArticleLayout
        crumbs={[
          { label: "Home", to: "/" },
          { label: "Library", to: "/lib" },
          { label: "Quickstart" },
        ]}
        title={TITLE}
        lede="From zero to publish-and-retrieve in five minutes. This page is the verbatim quickstart from the libbep44 README, with deep-links into the API reference for each function used."
      >
        <h2>System packages</h2>
        <p>Arch Linux:</p>
        <pre><code>sudo pacman -S libsodium openssl jansson miniupnpc</code></pre>
        <p>Debian/Ubuntu:</p>
        <pre><code>sudo apt install libsodium-dev libssl-dev libjansson-dev libminiupnpc-dev</code></pre>

        <h2>Build the library</h2>
        <pre><code>{`git clone -b libbep44 https://github.com/01BTC10/dht44.git
cd dht44
make           # produces libbep44.a`}</code></pre>

        <h2>Linking</h2>
        <p>Static archive at <code>libbep44.a</code>, public header at <code>include/libbep44.h</code>:</p>
        <pre><code>{`gcc your_app.c \\
    -I/path/to/dht44/include \\
    /path/to/dht44/libbep44.a \\
    -lsodium -lcrypto -ljansson -lminiupnpc \\
    -o your_app`}</code></pre>
        <p>
          The library has no runtime files of its own; everything it needs
          lives in the <code>state_dir</code> you pass to{" "}
          <Link to="/lib/api#bep44_open"><code>bep44_open</code></Link>.
        </p>

        <h2>Quickstart program</h2>
        <p>Save as <code>quickstart.c</code>:</p>
        <pre><code>{`#include <stdio.h>
#include <string.h>
#include <time.h>
#include "libbep44.h"

typedef struct { int done; } put_state;
typedef struct { int done; int found; } get_state;

static void on_put(const bep44_put_result_t *r, void *u) {
    put_state *p = u; p->done = 1;
    printf("put: stored on %d node(s)\\n", r->stored_count);
}
static void on_get(const bep44_get_result_t *r, void *u) {
    get_state *g = u; g->done = 1; g->found = r->found;
    if (r->found) printf("got %zu bytes (seq=%lld)\\n",
                         r->value_len, (long long)r->seq);
    else          puts("not found");
}

int main(void) {
    bep44_opts_t opts = {
        .port = 6881,
        .state_dir = "./quickstart_state",
        .bootstrap_routers = 1,
    };
    bep44_ctx_t *ctx = bep44_open(&opts);
    if (!ctx) return 1;

    bep44_keypair_t kp;
    if (bep44_load_key("./quickstart_state/key.json", &kp) != 0) {
        bep44_keygen(&kp);
        bep44_save_key("./quickstart_state/key.json", &kp);
    }

    /* Block until we have enough peers to do real work. Cold-boot
     * against the public DHT takes 30s+ — don't add a time cap
     * unless you also handle the "no peers yet" path. */
    while (bep44_good_nodes(ctx) < 4) bep44_step(ctx, 250);

    put_state put_s = { 0 };
    bep44_put_mutable(ctx, &kp, NULL, 0, 1, -1,
                      (uint8_t *)"5:hello", 7, on_put, &put_s);
    while (!put_s.done) bep44_step(ctx, 250);

    /* Get-after-put on a freshly-bootstrapped node is sometimes flaky:
     * our lookup may converge on different peers than the put just
     * hit. The lookup itself grows the routing table, so retrying
     * a couple times reliably resolves it. */
    for (int attempt = 0; attempt < 5; attempt++) {
        get_state get_s = { 0 };
        bep44_get_mutable(ctx, kp.pk, NULL, 0, on_get, &get_s);
        while (!get_s.done) bep44_step(ctx, 250);
        if (get_s.found) break;
    }

    bep44_close(ctx);
    return 0;
}`}</code></pre>

        <h2>Build and run</h2>
        <pre><code>{`gcc quickstart.c libbep44.a -Iinclude \\
    -lsodium -lcrypto -ljansson -lminiupnpc -o quickstart
mkdir -p quickstart_state
./quickstart`}</code></pre>
        <p>Expected output (real, from the verified README walk-through):</p>
        <pre><code>{`[dht44:dht_wrap] bound :6881 v4 (v6 disabled)
[dht44:state] open ./quickstart_state/key.json: No such file or directory
put: stored on 19 node(s)
got 7 bytes (seq=1)`}</code></pre>

        <h2>What just happened</h2>
        <ol>
          <li><Link to="/lib/api#bep44_open"><code>bep44_open</code></Link>{" "}
            bound a UDP socket, loaded (or generated) a persistent node
            id, optionally pinged the public bootstrap routers, and
            installed an inbound BEP 44 server.</li>
          <li><Link to="/lib/api#bep44_keygen"><code>bep44_keygen</code></Link>{" "}
            produced a fresh Ed25519 keypair from the OS CSPRNG.</li>
          <li><Link to="/lib/api#bep44_save_key"><code>bep44_save_key</code></Link>{" "}
            wrote the key to disk in the same JSON format the dht44 CLI
            uses.</li>
          <li>The bootstrap loop pumped events until 4 good peers
            populated the routing table — typically 30–60 seconds on
            a cold start.</li>
          <li><Link to="/lib/api#bep44_put_mutable"><code>bep44_put_mutable</code></Link>{" "}
            ran an iterative Kademlia lookup, picked the 8 closest
            peers to <code>SHA1(pk)</code>, signed the value, and sent
            put queries to each. The library then waited for ack
            responses from the network.</li>
          <li><Link to="/lib/api#bep44_get_mutable"><code>bep44_get_mutable</code></Link>{" "}
            ran another iterative lookup, collected returned values,
            verified the signature, and called the user callback.</li>
        </ol>

        <h2>Where to go next</h2>
        <ul>
          <li><Link to="/lib/api">API reference</Link> — every public
            function, signature + description + standalone example +
            errors.</li>
          <li><Link to="/lib/persistence">Persistence and republish</Link>{" "}
            — why the BEP 44 ~2-hour expiry matters and how the
            library handles it for you.</li>
          <li><Link to="/blog/embed-dht-c-app">Embedding a BitTorrent DHT
            in your C app</Link> — when a daemon isn't what you want.</li>
          <li><Link to="/protocol/bep44">BEP 44 in depth</Link> — the
            wire format the library implements.</li>
        </ul>
      </ArticleLayout>
    </>
  );
}
