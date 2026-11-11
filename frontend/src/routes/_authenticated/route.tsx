import { createFileRoute, redirect, Outlet } from "@tanstack/react-router";
import { supabase } from "@/integrations/supabase/client";
import { AppShell } from "@/components/scamlens/app-shell";
import { resolveSupabaseAuthCallback } from "@/lib/auth-error-helper";

export const Route = createFileRoute("/_authenticated")({
  ssr: false,
  beforeLoad: async () => {
    if (typeof window !== "undefined") {
      const callback = await resolveSupabaseAuthCallback(supabase);
      if (callback.handled) {
        if (callback.authenticated) {
          if (callback.type === "recovery") {
            throw redirect({ to: "/reset-password" });
          }
          return;
        }
        if (callback.error) {
          throw redirect({ to: "/auth" });
        }
      }
    }

    const { data: sessionData } = await supabase.auth.getSession();
    if (sessionData.session?.user) {
      return;
    }

    const { data } = await supabase.auth.getUser();
    if (!data.user) {
      throw redirect({ to: "/auth" });
    }
  },
  component: () => (
    <AppShell>
      <Outlet />
    </AppShell>
  ),
});
