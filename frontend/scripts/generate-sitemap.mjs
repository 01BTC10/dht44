/*
 * Build-time sitemap.xml generator. Walks a static route table and
 * writes dist/sitemap.xml. /dashboard is intentionally excluded — it
 * is marked noindex via SEO and shouldn't be in search results.
 *
 * Run after `vite build` from the package.json build script.
 */

import fs from "node:fs";
import path from "node:path";

const SITE = "https://dht44.com";

const routes = [
  { path: "/",                          priority: 1.0,  changefreq: "weekly" },
  { path: "/about",                     priority: 0.6,  changefreq: "monthly" },

  { path: "/protocol",                  priority: 0.9,  changefreq: "monthly" },
  { path: "/protocol/kademlia",         priority: 0.9,  changefreq: "monthly" },
  { path: "/protocol/bep5",             priority: 0.8,  changefreq: "monthly" },
  { path: "/protocol/bep44",            priority: 0.9,  changefreq: "monthly" },
  { path: "/protocol/bep51",            priority: 0.7,  changefreq: "monthly" },

  { path: "/lib",                       priority: 0.9,  changefreq: "monthly" },
  { path: "/lib/quickstart",            priority: 0.8,  changefreq: "monthly" },
  { path: "/lib/api",                   priority: 0.8,  changefreq: "monthly" },
  { path: "/lib/persistence",           priority: 0.7,  changefreq: "monthly" },

  { path: "/blog",                      priority: 0.6,  changefreq: "weekly"  },
  { path: "/blog/dht-size",             priority: 0.8,  changefreq: "monthly" },
  { path: "/blog/classifying-peers",    priority: 0.8,  changefreq: "monthly" },
  { path: "/blog/embed-dht-c-app",      priority: 0.7,  changefreq: "monthly" },
  { path: "/blog/kademlia-vs-chord",    priority: 0.7,  changefreq: "monthly" },
];

const today = new Date().toISOString().slice(0, 10);

const urls = routes
  .map(
    (r) => `  <url>
    <loc>${SITE}${r.path}</loc>
    <lastmod>${today}</lastmod>
    <changefreq>${r.changefreq}</changefreq>
    <priority>${r.priority.toFixed(1)}</priority>
  </url>`,
  )
  .join("\n");

const out = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls}
</urlset>
`;

const distDir = path.resolve("dist");
if (!fs.existsSync(distDir)) {
  console.error(`generate-sitemap: ${distDir} does not exist; run 'vite build' first`);
  process.exit(1);
}
fs.writeFileSync(path.join(distDir, "sitemap.xml"), out);
console.log(`generate-sitemap: wrote dist/sitemap.xml (${routes.length} urls)`);
