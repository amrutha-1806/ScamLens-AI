import { createFileRoute } from "@tanstack/react-router";
import { ReportsPage } from "@/components/scamlens/pages";

export const Route = createFileRoute("/_authenticated/reports")({
  head: () => ({ meta: [
    { title: "Security Reports — SCAMLENS AI" },
    { name: "description", content: "Generate structured reports from completed SCAMLENS AI analyses." },
    { property: "og:title", content: "Security Reports — SCAMLENS AI" },
    { property: "og:description", content: "Generate structured reports from completed SCAMLENS AI analyses." },
    { property: "og:type", content: "website" },
    { name: "twitter:card", content: "summary_large_image" },
  ] }),
  component: ReportsPage,
});
