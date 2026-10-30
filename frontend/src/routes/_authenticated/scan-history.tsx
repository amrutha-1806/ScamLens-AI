import { createFileRoute } from "@tanstack/react-router";
import { HistoryPage } from "@/components/scamlens/pages";

export const Route = createFileRoute("/_authenticated/scan-history")({
  head: () => ({ meta: [
    { title: "Scan History — SCAMLENS AI" },
    { name: "description", content: "Search and filter past SCAMLENS AI security analyses." },
    { property: "og:title", content: "Scan History — SCAMLENS AI" },
    { property: "og:description", content: "Search and filter past SCAMLENS AI security analyses." },
    { property: "og:type", content: "website" },
    { name: "twitter:card", content: "summary_large_image" },
  ] }),
  component: HistoryPage,
});
