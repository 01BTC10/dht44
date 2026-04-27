/*
 * Shared article shell. Centers the prose, renders breadcrumbs above
 * the title, and emits BreadcrumbList JSON-LD for SEO.
 */

import { Link } from "react-router-dom";

export type Crumb = { label: string; to?: string };

type Props = {
  crumbs: Crumb[];
  title: string;
  /** Optional subtitle / lede paragraph. */
  lede?: string;
  children: React.ReactNode;
};

const SITE = "https://dht44.com";

export default function ArticleLayout({ crumbs, title, lede, children }: Props) {
  const breadcrumbLd = {
    "@context": "https://schema.org",
    "@type": "BreadcrumbList",
    itemListElement: crumbs.map((c, i) => ({
      "@type": "ListItem",
      position: i + 1,
      name: c.label,
      ...(c.to ? { item: `${SITE}${c.to}` } : {}),
    })),
  };

  return (
    <article className="article">
      <nav className="breadcrumbs" aria-label="breadcrumb">
        {crumbs.map((c, i) => (
          <span key={i}>
            {c.to ? <Link to={c.to}>{c.label}</Link> : <span aria-current="page">{c.label}</span>}
            {i < crumbs.length - 1 && <span aria-hidden="true"> / </span>}
          </span>
        ))}
      </nav>
      <h1>{title}</h1>
      {lede && <p className="lede">{lede}</p>}
      {children}
      <script
        type="application/ld+json"
        // breadcrumb JSON-LD inline; SEO component already emits TechArticle.
        dangerouslySetInnerHTML={{ __html: JSON.stringify(breadcrumbLd) }}
      />
    </article>
  );
}
