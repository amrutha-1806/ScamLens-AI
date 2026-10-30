import { createFileRoute } from "@tanstack/react-router";
import { AnalyticsPage } from "@/components/scamlens/pages";

export const Route = createFileRoute("/_authenticated/analytics")({
  head: () => ({ meta: [
    { title: "Security Analytics — SCAMLENS AI" },
    { name: "description", content: "Review SCAMLENS AI scan trends, risk distribution, and classification insights." },
    { property: "og:title", content: "Security Analytics — SCAMLENS AI" },
    { property: "og:description", content: "Review SCAMLENS AI scan trends, risk distribution, and classification insights." },
    { property: "og:type", content: "website" },
    { name: "twitter:card", content: "summary_large_image" },
  ] }),
  component: AnalyticsPage,
});
