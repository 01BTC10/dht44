/*
 * Reusable stub for articles that don't have content yet. Each route
 * gets its own thin wrapper that passes metadata in. Renders a
 * "coming soon" notice plus the breadcrumbs and SEO so the URL is
 * indexable + the route is in the sitemap from day 1.
 */

import SEO from "../components/SEO";
import ArticleLayout, { Crumb } from "../components/ArticleLayout";
import { Link } from "react-router-dom";

type Props = {
  title: string;
  description: string;
  path: string;
  crumbs: Crumb[];
  /** Optional JSON-LD (TechArticle, Article, etc.). */
  jsonLd?: Record<string, unknown>;
};

export default function ArticleStub({ title, description, path, crumbs, jsonLd }: Props) {
  return (
    <>
      <SEO
        title={title}
        description={description}
        path={path}
        type="article"
        jsonLd={jsonLd}
      />
      <ArticleLayout crumbs={crumbs} title={title} lede={description}>
        <p className="placeholder">
          Full content is being written. In the meantime, browse the{" "}
          <Link to="/protocol">protocol reference</Link>, the{" "}
          <Link to="/lib">libbep44 docs</Link>, or the{" "}
          <a href="https://github.com/01BTC10/dht44">source on GitHub</a>.
        </p>
      </ArticleLayout>
    </>
  );
}
