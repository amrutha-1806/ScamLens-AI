import { createFileRoute } from "@tanstack/react-router";
import AuthPage from "../AuthPage";

export const Route = createFileRoute("/signup")({
  component: AuthPage,
});
