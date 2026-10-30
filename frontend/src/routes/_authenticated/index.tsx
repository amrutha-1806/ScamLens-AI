import { createFileRoute } from "@tanstack/react-router";
import { DashboardPage } from "@/components/scamlens/pages";

export const Route = createFileRoute("/_authenticated/")({
  head: () => ({ meta: [
    { title: "Security Dashboard — SCAMLENS AI" },
    { name: "description", content: "Monitor scam and phishing analysis activity in SCAMLENS AI." },
    { property: "og:title", content: "Security Dashboard — SCAMLENS AI" },
    { property: "og:description", content: "Monitor scam and phishing analysis activity in SCAMLENS AI." },
    { property: "og:type", content: "website" }, { name: "twitter:card", content: "summary_large_image" },
  ]}),
  component: DashboardPage,
});
