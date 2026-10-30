import { createFileRoute } from "@tanstack/react-router";
import { LearnPractisePage } from "@/components/scamlens/pages";

export const Route = createFileRoute("/_authenticated/learn-practise")({
  head: () => ({
    meta: [
      { title: "Learn & Practise — SCAMLENS AI" },
      {
        name: "description",
        content:
          "Interactive cybersecurity education and phishing detection practice scenarios inside SCAMLENS AI.",
      },
      { property: "og:title", content: "Learn & Practise — SCAMLENS AI" },
      {
        property: "og:description",
        content:
          "Interactive cybersecurity education and phishing detection practice scenarios inside SCAMLENS AI.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: LearnPractisePage,
});
