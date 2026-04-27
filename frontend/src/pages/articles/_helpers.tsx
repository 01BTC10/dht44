/* Shared helpers for content articles. */

const SITE = "https://dht44.com";

export const techArticle = (
  path: string,
  title: string,
  desc: string,
  keywords: string,
  date: string = "2026-04-27",
) => ({
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "@id": `${SITE}${path}#article`,
  headline: title,
  description: desc,
  url: `${SITE}${path}`,
  mainEntityOfPage: `${SITE}${path}`,
  inLanguage: "en",
  proficiencyLevel: "Expert",
  datePublished: date,
  dateModified: date,
  author: { "@type": "Person", name: "Tayaout Labelle-Kuberek" },
  publisher: { "@id": "https://dht44.com/#org" },
  keywords,
  license: "https://opensource.org/licenses/MIT",
  isAccessibleForFree: true,
});
