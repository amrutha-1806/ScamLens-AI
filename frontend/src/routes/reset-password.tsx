import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useState, type FormEvent } from "react";
import { Loader2 } from "lucide-react";
import { ScamLensIcon } from "@/components/scamlens/logo";
import { supabase } from "@/integrations/supabase/client";
import { resolveSupabaseAuthCallback } from "@/lib/auth-error-helper";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export const Route = createFileRoute("/reset-password")({
  ssr: false,
  head: () => ({
    meta: [
      { title: "Set new password — SCAMLENS AI" },
      { name: "description", content: "Choose a new password for your SCAMLENS AI account." },
      { property: "og:title", content: "Set new password — SCAMLENS AI" },
      { property: "og:description", content: "Choose a new password for your SCAMLENS AI account." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: ResetPasswordPage,
});

function ResetPasswordPage() {
  const navigate = useNavigate();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    resolveSupabaseAuthCallback(supabase).then((res) => {
      if (res.error) {
        setError(res.error);
      }
    });
  }, []);

  async function submit(e: FormEvent) {
    e.preventDefault(); setError(null);
    if (password.length < 8) return setError("Password must be at least 8 characters.");
    if (password !== confirm) return setError("Passwords do not match.");
    setBusy(true);
    const { error } = await supabase.auth.updateUser({ password });
    setBusy(false);
    if (error) return setError(error.message.includes("session") ? "This reset link is invalid or has expired. Request a new one." : error.message);
    navigate({ to: "/", replace: true });
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background bg-chart-grid px-4">
      <form onSubmit={submit} className="w-full max-w-md space-y-4 rounded-xl border border-border bg-card/80 p-7 shadow-xl backdrop-blur-md" noValidate>
        <div className="flex items-center gap-3"><ScamLensIcon size={36} /><h1 className="text-xl font-semibold text-foreground">Set a new password</h1></div>
        <div className="space-y-1.5"><Label htmlFor="pw">New password</Label><Input id="pw" type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} /></div>
        <div className="space-y-1.5"><Label htmlFor="pw2">Confirm password</Label><Input id="pw2" type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} /></div>
        {error && <p role="alert" className="rounded-md border border-danger/40 bg-danger/10 px-3 py-2 text-sm text-danger">{error}</p>}
        <Button type="submit" className="w-full" disabled={busy}>{busy && <Loader2 className="animate-spin" />}Update password</Button>
      </form>
    </div>
  );
}
