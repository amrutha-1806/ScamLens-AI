import { createFileRoute } from "@tanstack/react-router";
import { SettingsInformationPage, type SettingsInfoTab } from "@/components/scamlens/pages";

export const Route = createFileRoute("/_authenticated/settings-information")({
  validateSearch: (search: Record<string, unknown>): { tab?: SettingsInfoTab } => {
    const raw = search["tab"];
    if (raw === "ai-models" || raw === "about" || raw === "settings") {
      return { tab: raw };
    }
    return {};
  },
  head: () => ({
    meta: [
      { title: "Settings & Information — SCAMLENS AI" },
      {
        name: "description",
        content:
          "Explore the SCAMLENS AI Random Forest machine-learning pipeline, project architecture, and workspace settings.",
      },
      { property: "og:title", content: "Settings & Information — SCAMLENS AI" },
      {
        property: "og:description",
        content:
          "Explore the SCAMLENS AI Random Forest machine-learning pipeline, project architecture, and workspace settings.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: function SettingsInformationRouteComponent() {
    const { tab } = Route.useSearch();
    return <SettingsInformationPage initialTab={tab ?? "ai-models"} />;
  },
});
