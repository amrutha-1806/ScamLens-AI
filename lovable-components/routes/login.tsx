import { createFileRoute } from "@tanstack/react-router";
import AuthPage from "../AuthPage";

export const Route = createFileRoute("/login")({
  component: AuthPage,
});
