/*
 * Per-route <head> management. Every page renders <SEO ... /> as its
 * first child; react-helmet-async hoists the tags into <head>.
 *
 * Also injects:
 *   - Canonical URL
 *   - Open Graph + Twitter cards
 *   - JSON-LD (single object or array — caller picks)
 *   - Umami analytics beacon, gated by VITE_UMAMI_WEBSITE_ID
 *
 * The site origin is fixed at SITE — change once at deploy time.
 */

import { Helmet } from "react-helmet-async";

const SITE = "https://dht44.com";

/* Read at build time. Empty string if not set → no Umami beacon. */
const UMAMI_ORIGIN  = (import.meta.env.VITE_UMAMI_ORIGIN  as string | undefined) ?? "";
const UMAMI_WEBSITE = (import.meta.env.VITE_UMAMI_WEBSITE_ID as string | undefined) ?? "";

type SEOProps = {
  title: string;
  description: string;
  /** Path including leading slash, e.g. "/protocol/kademlia". */
  path: string;
  type?: "website" | "article";
  /** Absolute URL to OG image. Defaults to /og.png. */
  image?: string;
  /** Single JSON-LD object or an array. */
  jsonLd?: Record<string, unknown> | Record<string, unknown>[];
  /** True for /dashboard and other non-content pages. */
  noindex?: boolean;
};

export default function SEO({
  title,
  description,
  path,
  type = "website",
  image = `${SITE}/og.png`,
  jsonLd,
  noindex = false,
}: SEOProps) {
  const url = `${SITE}${path}`;
  const ldArray = jsonLd
    ? (Array.isArray(jsonLd) ? jsonLd : [jsonLd])
    : [];

  return (
    <Helmet prioritizeSeoTags>
      <title>{title}</title>
      <meta name="description" content={description} />
      <link rel="canonical" href={url} />
      {noindex && <meta name="robots" content="noindex,nofollow" />}

      {/* Open Graph */}
      <meta property="og:type" content={type} />
      <meta property="og:title" content={title} />
      <meta property="og:description" content={description} />
      <meta property="og:url" content={url} />
      <meta property="og:image" content={image} />
      <meta property="og:site_name" content="dht44" />

      {/* Twitter / X */}
      <meta name="twitter:card" content="summary_large_image" />
      <meta name="twitter:title" content={title} />
      <meta name="twitter:description" content={description} />
      <meta name="twitter:image" content={image} />

      {/* JSON-LD */}
      {ldArray.map((ld, i) => (
        <script key={i} type="application/ld+json">
          {JSON.stringify(ld)}
        </script>
      ))}

      {/* Umami analytics — env-gated, no-op if not configured. */}
      {UMAMI_ORIGIN && UMAMI_WEBSITE && (
        <script
          defer
          src={`${UMAMI_ORIGIN}/script.js`}
          data-website-id={UMAMI_WEBSITE}
        />
      )}
    </Helmet>
  );
}
