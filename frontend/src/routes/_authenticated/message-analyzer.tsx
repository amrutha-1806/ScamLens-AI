import { createFileRoute } from "@tanstack/react-router";
import { MessageAnalyzerPage } from "@/components/scamlens/pages";

export const Route = createFileRoute("/_authenticated/message-analyzer")({
  head: () => ({ meta: [
    { title: "Message Analyzer — SCAMLENS AI" },
    { name: "description", content: "Analyze suspicious message and email text for scam and phishing risk." },
    { property: "og:title", content: "Message Analyzer — SCAMLENS AI" },
    { property: "og:description", content: "Analyze suspicious message and email text for scam and phishing risk." },
    { property: "og:type", content: "website" },
    { name: "twitter:card", content: "summary_large_image" },
  ] }),
  component: MessageAnalyzerPage,
});
