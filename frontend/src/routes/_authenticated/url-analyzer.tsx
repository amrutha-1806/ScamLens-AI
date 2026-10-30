import { createFileRoute } from "@tanstack/react-router";
import { UrlAnalyzerPage } from "@/components/scamlens/pages";

export const Route = createFileRoute("/_authenticated/url-analyzer")({
  head: () => ({ meta: [
    { title: "URL Analyzer — SCAMLENS AI" },
    { name: "description", content: "Perform safe static inspection of suspicious URL structure and indicators." },
    { property: "og:title", content: "URL Analyzer — SCAMLENS AI" },
    { property: "og:description", content: "Perform safe static inspection of suspicious URL structure and indicators." },
    { property: "og:type", content: "website" },
    { name: "twitter:card", content: "summary_large_image" },
  ] }),
  component: UrlAnalyzerPage,
});
