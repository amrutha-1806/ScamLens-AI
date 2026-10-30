import { createFileRoute, redirect } from "@tanstack/react-router";
import { SettingsInformationPage } from "@/components/scamlens/pages";

export const Route = createFileRoute("/_authenticated/about")({
  beforeLoad: () => {
    throw redirect({
      to: "/settings-information",
      search: { tab: "about" },
      replace: true,
    });
  },
  head: () => ({
    meta: [
      { title: "About the Project — SCAMLENS AI" },
      { name: "description", content: "Learn about the SCAMLENS AI objective, approach, limitations, and roadmap." },
    ],
  }),
  component: () => <SettingsInformationPage initialTab="about" />,
});
