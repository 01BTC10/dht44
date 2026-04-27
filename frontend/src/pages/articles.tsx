/*
 * Stub article pages. One thin wrapper per route, all sharing
 * <ArticleStub>. As real content is written, replace the wrapper
 * with a full page (still using ArticleStub's metadata pattern is
 * fine; or render directly).
 */

import ArticleStub from "./ArticleStub";

const SITE = "https://dht44.com";

const techArticle = (path: string, title: string, desc: string,
                     keywords: string) => ({
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "@id": `${SITE}${path}#article`,
  headline: title,
  description: desc,
  url: `${SITE}${path}`,
  mainEntityOfPage: `${SITE}${path}`,
  inLanguage: "en",
  proficiencyLevel: "Expert",
  author: { "@type": "Person", name: "Tayaout Labelle-Kuberek" },
  publisher: { "@id": "https://dht44.com/#org" },
  keywords,
  license: "https://opensource.org/licenses/MIT",
  isAccessibleForFree: true,
});

/* ===== /protocol/* ===== */

export { default as Kademlia } from "./articles/Kademlia";

export { default as Bep5  } from "./articles/Bep5";
export { default as Bep44 } from "./articles/Bep44";
export { default as Bep51 } from "./articles/Bep51";

/* ===== /lib/* ===== */

export const LibQuickstart = () => (
  <ArticleStub
    title="libbep44 Quickstart — Embed BEP 44 in C"
    description="Minimal end-to-end example: open the DHT context, generate a key, publish a mutable item, retrieve it. Compiles in 5 lines."
    path="/lib/quickstart"
    crumbs={[
      { label: "Home", to: "/" },
      { label: "Library", to: "/lib" },
      { label: "Quickstart" },
    ]}
    jsonLd={techArticle(
      "/lib/quickstart",
      "libbep44 Quickstart — Embed BEP 44 in C",
      "Quickstart for the libbep44 BitTorrent DHT C library.",
      "libbep44, bep 44, bittorrent dht, c library, quickstart",
    )}
  />
);

export const LibApi = () => (
  <ArticleStub
    title="libbep44 API Reference"
    description="Every public function in libbep44.h: signature, description, copy-pastable example, and explicit error cases."
    path="/lib/api"
    crumbs={[
      { label: "Home", to: "/" },
      { label: "Library", to: "/lib" },
      { label: "API" },
    ]}
    jsonLd={techArticle(
      "/lib/api",
      "libbep44 API Reference",
      "API reference for the libbep44 BitTorrent DHT C library.",
      "libbep44, api reference, bep 44, bittorrent dht, c library",
    )}
  />
);

export const LibPersistence = () => (
  <ArticleStub
    title="Persistence and Republish in libbep44"
    description="Why BEP 44 items expire after ~2 hours, what state_dir holds, and how the library's republish loop keeps your value alive."
    path="/lib/persistence"
    crumbs={[
      { label: "Home", to: "/" },
      { label: "Library", to: "/lib" },
      { label: "Persistence" },
    ]}
    jsonLd={techArticle(
      "/lib/persistence",
      "Persistence and Republish in libbep44",
      "How the libbep44 library handles BEP 44 item expiry and republish.",
      "bep 44, republish, libbep44, bittorrent dht, expiry",
    )}
  />
);

/* ===== /blog/* ===== */

export const BlogDhtSize = () => (
  <ArticleStub
    title="How Big Is the BitTorrent DHT, Really?"
    description="Methodology and live measurements from the dht44 crawler — BEP 51 sampling, dedup window, ASN/country distribution, IPv4 vs IPv6 split."
    path="/blog/dht-size"
    crumbs={[
      { label: "Home", to: "/" },
      { label: "Blog", to: "/blog" },
      { label: "DHT size" },
    ]}
    jsonLd={techArticle(
      "/blog/dht-size",
      "How Big Is the BitTorrent DHT, Really?",
      "Live measurements of the BitTorrent Mainline DHT size.",
      "bittorrent dht, dht size, kademlia, network measurement",
    )}
  />
);

export const BlogClassifyingPeers = () => (
  <ArticleStub
    title="Detecting Crawlers, Monitors and Honeypots in the DHT"
    description="Classifier signals from running a passive observer on the public DHT: high-pps single sources, lying about node id, refusing announce_peer."
    path="/blog/classifying-peers"
    crumbs={[
      { label: "Home", to: "/" },
      { label: "Blog", to: "/blog" },
      { label: "Classifying peers" },
    ]}
    jsonLd={techArticle(
      "/blog/classifying-peers",
      "Detecting Crawlers, Monitors and Honeypots in the DHT",
      "How to classify peers on the BitTorrent DHT as crawlers, monitors, or honeypots.",
      "dht crawler, honeypot, monitor, sybil, bittorrent dht",
    )}
  />
);

export const BlogEmbedDht = () => (
  <ArticleStub
    title="Embedding a BitTorrent DHT in Your C App"
    description="When a daemon isn't what you want — using libbep44 to publish and retrieve BEP 44 items from inside a larger C program."
    path="/blog/embed-dht-c-app"
    crumbs={[
      { label: "Home", to: "/" },
      { label: "Blog", to: "/blog" },
      { label: "Embed DHT" },
    ]}
    jsonLd={techArticle(
      "/blog/embed-dht-c-app",
      "Embedding a BitTorrent DHT in Your C App",
      "How to embed a BitTorrent Mainline DHT into a C program with libbep44.",
      "libbep44, embedded dht, c, bep 44, bittorrent",
    )}
  />
);

export const BlogKademliaVsChord = () => (
  <ArticleStub
    title="Kademlia vs Chord vs Pastry: Which One and Why"
    description="Comparative tour of three influential DHT designs. Lookup hops, churn handling, lookup correctness under partial failure."
    path="/blog/kademlia-vs-chord"
    crumbs={[
      { label: "Home", to: "/" },
      { label: "Blog", to: "/blog" },
      { label: "Kademlia vs Chord" },
    ]}
    jsonLd={techArticle(
      "/blog/kademlia-vs-chord",
      "Kademlia vs Chord vs Pastry: Which One and Why",
      "Comparing three influential DHT protocols.",
      "kademlia, chord, pastry, dht, distributed hash table",
    )}
  />
);
