import { createFileRoute } from "@tanstack/react-router";
import { BatchScannerPage } from "@/components/scamlens/pages";

export const Route = createFileRoute("/_authenticated/batch-scanner")({
  head: () => ({ meta: [
    { title: "Batch CSV Scanner — SCAMLENS AI" },
    { name: "description", content: "Preview and prepare CSV message datasets for batch scam analysis." },
    { property: "og:title", content: "Batch CSV Scanner — SCAMLENS AI" },
    { property: "og:description", content: "Preview and prepare CSV message datasets for batch scam analysis." },
    { property: "og:type", content: "website" },
    { name: "twitter:card", content: "summary_large_image" },
  ] }),
  component: BatchScannerPage,
});
