import { createFileRoute, redirect } from "@tanstack/react-router";
import { SettingsInformationPage } from "@/components/scamlens/pages";

export const Route = createFileRoute("/_authenticated/ai-models")({
  beforeLoad: () => {
    throw redirect({
      to: "/settings-information",
      search: { tab: "ai-models" },
      replace: true,
    });
  },
  head: () => ({
    meta: [
      { title: "AI & Models — SCAMLENS AI" },
      { name: "description", content: "Explore the dataset, feature engineering, evaluated models, and prediction process." },
    ],
  }),
  component: () => <SettingsInformationPage initialTab="ai-models" />,
});
