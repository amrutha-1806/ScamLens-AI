import { useState, useId, type FormEvent } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { motion, AnimatePresence } from "motion/react";
import {
  AlertTriangle,
  Bell,
  CheckCircle2,
  ChevronRight,
  Eye,
  EyeOff,
  KeyRound,
  Loader2,
  Lock,
  LogOut,
  Mail,
  Moon,
  Monitor,
  RotateCcw,
  Save,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Sun,
  User,
  Volume2,
  VolumeX,
} from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { useScamlensPreferences } from "@/lib/scamlens-preferences";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";

export type ProfileTab = "profile" | "password" | "security" | "notifications" | "preferences";

interface ProfileSettingsDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  defaultTab?: ProfileTab;
}

export function ProfileSettingsDialog({
  open,
  onOpenChange,
  defaultTab = "profile",
}: ProfileSettingsDialogProps) {
  const [activeTab, setActiveTab] = useState<ProfileTab>(defaultTab);
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const { prefs, updatePreferences, shouldReduceMotion, resetPreferences } = useScamlensPreferences();

  // Sync default tab whenever dialog is re-opened with a specific tab
  const handleOpenChange = (nextOpen: boolean) => {
    if (nextOpen && defaultTab) {
      setActiveTab(defaultTab);
    }
    onOpenChange(nextOpen);
  };

  const userQuery = useQuery({
    queryKey: ["auth-user"],
    queryFn: async () => (await supabase.auth.getUser()).data.user,
    staleTime: 60_000,
  });

  const user = userQuery.data;

  // Display Name state
  const rawDisplayName =
    (user?.user_metadata?.["display_name"] as string) ||
    (user?.user_metadata?.["full_name"] as string) ||
    "";
  const [displayName, setDisplayName] = useState(rawDisplayName);
  const [nameSaving, setNameSaving] = useState(false);
  const [nameSuccess, setNameSuccess] = useState<string | null>(null);
  const [nameError, setNameError] = useState<string | null>(null);

  // Change Password state
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showCurrent, setShowCurrent] = useState(false);
  const [showNew, setShowNew] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [pwdSaving, setPwdSaving] = useState(false);
  const [pwdSuccess, setPwdSuccess] = useState<string | null>(null);
  const [pwdError, setPwdError] = useState<string | null>(null);

  // Compute initials
  const initials = (() => {
    if (displayName.trim()) {
      const parts = displayName.trim().split(/\s+/);
      return (parts[0][0] + (parts[1]?.[0] || "")).toUpperCase();
    }
    if (user?.email) {
      return user.email.slice(0, 2).toUpperCase();
    }
    return "SL";
  })();

  // Format dates
  const formatDate = (isoString?: string) => {
    if (!isoString) return "Not available";
    try {
      const d = new Date(isoString);
      return d.toLocaleDateString("en-US", {
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
    } catch {
      return isoString;
    }
  };

  // Sign out
  async function handleSignOut() {
    onOpenChange(false);
    await queryClient.cancelQueries();
    queryClient.clear();
    await supabase.auth.signOut();
    navigate({ to: "/auth", replace: true });
  }

  // Update Display Name
  async function handleSaveDisplayName(e: FormEvent) {
    e.preventDefault();
    setNameError(null);
    setNameSuccess(null);
    const trimmed = displayName.trim();

    setNameSaving(true);
    try {
      const { error } = await supabase.auth.updateUser({
        data: { display_name: trimmed },
      });
      if (error) throw error;
      setNameSuccess("Display name updated successfully.");
      await queryClient.invalidateQueries({ queryKey: ["auth-user"] });
    } catch (err) {
      setNameError(err instanceof Error ? err.message : "Failed to update display name.");
    } finally {
      setNameSaving(false);
    }
  }

  // Handle Change Password
  async function handleChangePassword(e: FormEvent) {
    e.preventDefault();
    setPwdError(null);
    setPwdSuccess(null);

    // Basic validation
    if (!currentPassword) {
      setPwdError("Please enter your current password.");
      return;
    }
    if (newPassword.length < 8) {
      setPwdError("New password must be at least 8 characters long.");
      return;
    }
    if (!/[A-Za-z]/.test(newPassword) || !/[0-9]/.test(newPassword)) {
      setPwdError("New password must contain both letters and numbers.");
      return;
    }
    if (newPassword !== confirmPassword) {
      setPwdError("New passwords do not match.");
      return;
    }
    if (currentPassword === newPassword) {
      setPwdError("New password must be different from your current password.");
      return;
    }

    setPwdSaving(true);
    try {
      // 1. Verify current password via re-authentication
      if (user?.email) {
        const { error: verifyErr } = await supabase.auth.signInWithPassword({
          email: user.email,
          password: currentPassword,
        });
        if (verifyErr) {
          throw new Error("Current password is incorrect. Please check and try again.");
        }
      }

      // 2. Update to new password via Supabase
      const { error: updateErr } = await supabase.auth.updateUser({
        password: newPassword,
      });

      if (updateErr) throw updateErr;

      setPwdSuccess("Your password has been changed successfully.");
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
    } catch (err) {
      setPwdError(err instanceof Error ? err.message : "Failed to update password.");
    } finally {
      setPwdSaving(false);
    }
  }

  const tabs = [
    { id: "profile" as const, label: "My Profile", icon: User },
    { id: "password" as const, label: "Change Password", icon: KeyRound },
    { id: "security" as const, label: "Security Settings", icon: Shield },
    { id: "notifications" as const, label: "Notifications", icon: Bell },
    { id: "preferences" as const, label: "Preferences", icon: Settings },
  ];

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="max-w-2xl border-border bg-card p-0 shadow-2xl overflow-hidden sm:rounded-xl">
        <DialogHeader className="border-b border-border bg-secondary/30 p-5 sm:p-6">
          <div className="flex items-center gap-3.5">
            <Avatar className="size-11 border-2 border-primary/40 bg-gradient-to-br from-primary/20 to-secondary text-primary font-bold shadow-sm">
              <AvatarFallback className="bg-transparent text-foreground font-mono">
                {initials}
              </AvatarFallback>
            </Avatar>
            <div className="min-w-0 flex-1">
              <DialogTitle className="text-base font-bold text-foreground sm:text-lg">
                Account &amp; Profile Settings
              </DialogTitle>
              <DialogDescription className="truncate text-xs text-muted-foreground mt-0.5">
                {user?.email ?? "Signed in analyst"} • SCAMLENS AI Workspace
              </DialogDescription>
            </div>
          </div>

          {/* Navigation Tabs (Responsive) */}
          <div className="mt-4 flex gap-1 overflow-x-auto pb-1 scrollbar-none">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => {
                    setActiveTab(tab.id);
                    setNameSuccess(null);
                    setNameError(null);
                    setPwdSuccess(null);
                    setPwdError(null);
                  }}
                  className={cn(
                    "flex shrink-0 items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold transition-colors duration-150 min-h-9 sm:min-h-8",
                    isActive
                      ? "bg-primary text-primary-foreground shadow-sm"
                      : "text-muted-foreground hover:bg-secondary hover:text-foreground"
                  )}
                >
                  <Icon className="size-3.5" />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </div>
        </DialogHeader>

        <div className="max-h-[70vh] overflow-y-auto p-5 sm:p-6">
          <AnimatePresence mode="wait">
            {/* TAB 1: MY PROFILE */}
            {activeTab === "profile" && (
              <motion.div
                key="tab-profile"
                initial={shouldReduceMotion ? false : { opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={shouldReduceMotion ? { opacity: 1 } : { opacity: 0 }}
                transition={{ duration: 0.18 }}
                className="space-y-5"
              >
                <div className="flex flex-col items-center gap-3 rounded-xl border border-border bg-secondary/20 p-5 text-center sm:flex-row sm:text-left">
                  <Avatar className="size-16 border-2 border-primary/50 bg-primary/10 text-primary text-xl font-bold font-mono">
                    <AvatarFallback className="bg-transparent text-primary">
                      {initials}
                    </AvatarFallback>
                  </Avatar>
                  <div className="min-w-0 flex-1">
                    <h4 className="text-base font-bold text-foreground">
                      {displayName || "Security Analyst"}
                    </h4>
                    <p className="font-mono text-xs text-muted-foreground mt-0.5">
                      {user?.email}
                    </p>
                    <div className="mt-2 flex flex-wrap items-center justify-center gap-2 sm:justify-start">
                      <span className="inline-flex items-center gap-1 rounded-full border border-safe/30 bg-safe/10 px-2.5 py-0.5 text-[10px] font-semibold text-safe">
                        <ShieldCheck className="size-3" /> Authenticated
                      </span>
                      <span className="rounded-full border border-border bg-secondary px-2.5 py-0.5 text-[10px] font-mono text-muted-foreground">
                        UID: {user?.id?.slice(0, 8)}...
                      </span>
                    </div>
                  </div>
                </div>

                <form onSubmit={handleSaveDisplayName} className="space-y-4">
                  <div className="space-y-1.5">
                    <Label htmlFor="display-name" className="text-xs font-semibold text-foreground">
                      Display Name
                    </Label>
                    <Input
                      id="display-name"
                      type="text"
                      value={displayName}
                      onChange={(e) => setDisplayName(e.target.value)}
                      placeholder="e.g. Alex Morgan"
                      className="h-10 text-sm font-medium"
                      maxLength={60}
                    />
                    <p className="text-[11px] text-muted-foreground">
                      Visible in workspace reports and header profile greeting.
                    </p>
                  </div>

                  {nameSuccess && (
                    <div className="flex items-center gap-2 rounded-lg border border-safe/30 bg-safe/10 p-3 text-xs text-safe">
                      <CheckCircle2 className="size-4 shrink-0" />
                      <span>{nameSuccess}</span>
                    </div>
                  )}

                  {nameError && (
                    <div className="flex items-center gap-2 rounded-lg border border-danger/30 bg-danger/10 p-3 text-xs text-danger">
                      <AlertTriangle className="size-4 shrink-0" />
                      <span>{nameError}</span>
                    </div>
                  )}

                  <Button
                    type="submit"
                    disabled={nameSaving}
                    className="min-h-10 w-full sm:w-auto"
                  >
                    {nameSaving ? <Loader2 className="size-4 animate-spin" /> : <Save className="size-4" />}
                    <span>{nameSaving ? "Saving..." : "Save Profile Details"}</span>
                  </Button>
                </form>

                <div className="rounded-lg border border-border bg-secondary/15 p-4 space-y-2 text-xs">
                  <p className="font-semibold text-foreground">Account Information</p>
                  <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 text-muted-foreground">
                    <div>
                      <span className="text-[11px] block">Primary Email:</span>
                      <strong className="text-foreground font-mono">{user?.email ?? "—"}</strong>
                    </div>
                    <div>
                      <span className="text-[11px] block">Account Created:</span>
                      <strong className="text-foreground">{formatDate(user?.created_at)}</strong>
                    </div>
                    <div>
                      <span className="text-[11px] block">Last Sign-In:</span>
                      <strong className="text-foreground">{formatDate(user?.last_sign_in_at)}</strong>
                    </div>
                    <div>
                      <span className="text-[11px] block">Auth Provider:</span>
                      <strong className="text-foreground capitalize">
                        {user?.app_metadata?.provider ?? "Email"}
                      </strong>
                    </div>
                  </div>
                </div>
              </motion.div>
            )}

            {/* TAB 2: CHANGE PASSWORD */}
            {activeTab === "password" && (
              <motion.div
                key="tab-password"
                initial={shouldReduceMotion ? false : { opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={shouldReduceMotion ? { opacity: 1 } : { opacity: 0 }}
                transition={{ duration: 0.18 }}
                className="space-y-5"
              >
                <div className="rounded-lg border border-primary/25 bg-primary/5 p-3.5 text-xs text-muted-foreground flex items-start gap-2.5">
                  <KeyRound className="size-4 text-primary shrink-0 mt-0.5" />
                  <div>
                    <strong className="text-foreground">Secure Password Update: </strong>
                    Enter your current password to verify your identity, then specify your new secure password. Passwords are never stored in plain text.
                  </div>
                </div>

                <form onSubmit={handleChangePassword} className="space-y-4">
                  {/* Current Password */}
                  <div className="space-y-1.5">
                    <Label htmlFor="current-pwd" className="text-xs font-semibold text-foreground">
                      Current Password
                    </Label>
                    <div className="relative">
                      <Input
                        id="current-pwd"
                        type={showCurrent ? "text" : "password"}
                        value={currentPassword}
                        onChange={(e) => setCurrentPassword(e.target.value)}
                        placeholder="••••••••••••"
                        className="h-10 pr-10 text-sm font-mono"
                        autoComplete="current-password"
                      />
                      <button
                        type="button"
                        onClick={() => setShowCurrent(!showCurrent)}
                        className="absolute right-2.5 top-2.5 text-muted-foreground hover:text-foreground p-1"
                        aria-label={showCurrent ? "Hide password" : "Show password"}
                      >
                        {showCurrent ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
                      </button>
                    </div>
                  </div>

                  {/* New Password */}
                  <div className="space-y-1.5">
                    <Label htmlFor="new-pwd" className="text-xs font-semibold text-foreground">
                      New Password
                    </Label>
                    <div className="relative">
                      <Input
                        id="new-pwd"
                        type={showNew ? "text" : "password"}
                        value={newPassword}
                        onChange={(e) => setNewPassword(e.target.value)}
                        placeholder="At least 8 characters (letters & numbers)"
                        className="h-10 pr-10 text-sm font-mono"
                        autoComplete="new-password"
                      />
                      <button
                        type="button"
                        onClick={() => setShowNew(!showNew)}
                        className="absolute right-2.5 top-2.5 text-muted-foreground hover:text-foreground p-1"
                        aria-label={showNew ? "Hide password" : "Show password"}
                      >
                        {showNew ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
                      </button>
                    </div>
                    <p className="text-[11px] text-muted-foreground">
                      Must be at least 8 characters long and include letters and numbers.
                    </p>
                  </div>

                  {/* Confirm New Password */}
                  <div className="space-y-1.5">
                    <Label htmlFor="confirm-pwd" className="text-xs font-semibold text-foreground">
                      Confirm New Password
                    </Label>
                    <div className="relative">
                      <Input
                        id="confirm-pwd"
                        type={showConfirm ? "text" : "password"}
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        placeholder="Re-type your new password"
                        className="h-10 pr-10 text-sm font-mono"
                        autoComplete="new-password"
                      />
                      <button
                        type="button"
                        onClick={() => setShowConfirm(!showConfirm)}
                        className="absolute right-2.5 top-2.5 text-muted-foreground hover:text-foreground p-1"
                        aria-label={showConfirm ? "Hide password" : "Show password"}
                      >
                        {showConfirm ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
                      </button>
                    </div>
                  </div>

                  {pwdSuccess && (
                    <div className="flex items-center gap-2 rounded-lg border border-safe/30 bg-safe/10 p-3 text-xs text-safe">
                      <CheckCircle2 className="size-4 shrink-0" />
                      <span>{pwdSuccess}</span>
                    </div>
                  )}

                  {pwdError && (
                    <div className="flex items-center gap-2 rounded-lg border border-danger/30 bg-danger/10 p-3 text-xs text-danger">
                      <AlertTriangle className="size-4 shrink-0" />
                      <span>{pwdError}</span>
                    </div>
                  )}

                  <Button
                    type="submit"
                    disabled={pwdSaving || !currentPassword || !newPassword || !confirmPassword}
                    className="min-h-10 w-full sm:w-auto"
                  >
                    {pwdSaving ? <Loader2 className="size-4 animate-spin" /> : <KeyRound className="size-4" />}
                    <span>{pwdSaving ? "Updating Password..." : "Update Password"}</span>
                  </Button>
                </form>
              </motion.div>
            )}

            {/* TAB 3: SECURITY SETTINGS */}
            {activeTab === "security" && (
              <motion.div
                key="tab-security"
                initial={shouldReduceMotion ? false : { opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={shouldReduceMotion ? { opacity: 1 } : { opacity: 0 }}
                transition={{ duration: 0.18 }}
                className="space-y-4"
              >
                <div className="rounded-xl border border-border bg-secondary/20 p-4 space-y-3">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <ShieldCheck className="size-4 text-safe" />
                      <span className="text-xs font-bold text-foreground">Authentication &amp; Session</span>
                    </div>
                    <span className="rounded-full border border-safe/30 bg-safe/10 px-2.5 py-0.5 text-[10px] font-semibold text-safe">
                      Active
                    </span>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs text-muted-foreground">
                    <div>
                      <span className="text-[11px] block">Account Email:</span>
                      <strong className="text-foreground font-mono">{user?.email}</strong>
                    </div>
                    <div>
                      <span className="text-[11px] block">Auth Method:</span>
                      <strong className="text-foreground">Supabase Email &amp; Password</strong>
                    </div>
                    <div>
                      <span className="text-[11px] block">Registered On:</span>
                      <strong className="text-foreground">{formatDate(user?.created_at)}</strong>
                    </div>
                    <div>
                      <span className="text-[11px] block">Last Sign-In Timestamp:</span>
                      <strong className="text-foreground">{formatDate(user?.last_sign_in_at)}</strong>
                    </div>
                  </div>
                </div>

                {/* Password Management Shortcut */}
                <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-border bg-secondary/20 p-4">
                  <div>
                    <p className="text-xs font-semibold text-foreground">Password Management</p>
                    <p className="text-[11px] text-muted-foreground mt-0.5">
                      Change your password or update security credentials.
                    </p>
                  </div>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => setActiveTab("password")}
                    className="min-h-9"
                  >
                    <KeyRound className="size-3.5" /> Change Password
                  </Button>
                </div>

                {/* Active Session Sign Out */}
                <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-danger/30 bg-danger/5 p-4">
                  <div>
                    <p className="text-xs font-semibold text-foreground">Sign Out of Session</p>
                    <p className="text-[11px] text-muted-foreground mt-0.5">
                      Terminate the current authenticated session on this browser.
                    </p>
                  </div>
                  <Button
                    type="button"
                    variant="destructive"
                    size="sm"
                    onClick={handleSignOut}
                    className="min-h-9"
                  >
                    <LogOut className="size-3.5" /> Sign Out
                  </Button>
                </div>
              </motion.div>
            )}

            {/* TAB 4: NOTIFICATIONS */}
            {activeTab === "notifications" && (
              <motion.div
                key="tab-notifications"
                initial={shouldReduceMotion ? false : { opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={shouldReduceMotion ? { opacity: 1 } : { opacity: 0 }}
                transition={{ duration: 0.18 }}
                className="space-y-4"
              >
                {/* In-App Risk Alert Banners */}
                <div className="flex items-center justify-between gap-4 rounded-xl border border-border bg-secondary/20 p-4">
                  <div className="min-w-0 flex-1">
                    <p className="text-xs font-semibold text-foreground">In-App Threat Alert Banners</p>
                    <p className="text-[11px] text-muted-foreground mt-0.5">
                      Display high-visibility warning notifications whenever a scan predicts High or Very High phishing probability.
                    </p>
                  </div>
                  <Button
                    type="button"
                    variant={prefs.inAppRiskAlerts ? "default" : "outline"}
                    size="sm"
                    onClick={() => updatePreferences({ inAppRiskAlerts: !prefs.inAppRiskAlerts })}
                    className="min-h-9 min-w-20"
                  >
                    {prefs.inAppRiskAlerts ? "Enabled" : "Disabled"}
                  </Button>
                </div>

                {/* Sound Alerts on Threat Detection */}
                <div className="flex items-center justify-between gap-4 rounded-xl border border-border bg-secondary/20 p-4">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1.5">
                      {prefs.soundAlerts ? <Volume2 className="size-4 text-primary" /> : <VolumeX className="size-4 text-muted-foreground" />}
                      <p className="text-xs font-semibold text-foreground">Audible Threat Chime</p>
                    </div>
                    <p className="text-[11px] text-muted-foreground mt-0.5">
                      Play an audible alert chime when a malicious URL or message is classified by the machine-learning pipeline.
                    </p>
                  </div>
                  <Button
                    type="button"
                    variant={prefs.soundAlerts ? "default" : "outline"}
                    size="sm"
                    onClick={() => updatePreferences({ soundAlerts: !prefs.soundAlerts })}
                    className="min-h-9 min-w-20"
                  >
                    {prefs.soundAlerts ? "Enabled" : "Disabled"}
                  </Button>
                </div>
              </motion.div>
            )}

            {/* TAB 5: PREFERENCES */}
            {activeTab === "preferences" && (
              <motion.div
                key="tab-preferences"
                initial={shouldReduceMotion ? false : { opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={shouldReduceMotion ? { opacity: 1 } : { opacity: 0 }}
                transition={{ duration: 0.18 }}
                className="space-y-4"
              >
                {/* Theme Mode */}
                <div className="rounded-xl border border-border bg-secondary/20 p-4 space-y-3">
                  <div className="flex items-center justify-between gap-2">
                    <div>
                      <p className="text-xs font-semibold text-foreground">Theme &amp; Visual Appearance</p>
                      <p className="text-[11px] text-muted-foreground">Select your preferred color scheme.</p>
                    </div>
                    <span className="rounded-full border border-primary/30 bg-primary/10 px-2 py-0.5 text-[10px] font-semibold text-primary capitalize">
                      {prefs.themeMode}
                    </span>
                  </div>

                  <div className="grid grid-cols-3 gap-2">
                    <Button
                      type="button"
                      variant={prefs.themeMode === "light" ? "default" : "outline"}
                      size="sm"
                      onClick={() => updatePreferences({ themeMode: "light" })}
                      className="text-xs min-h-9"
                    >
                      <Sun className="size-3.5" /> Light
                    </Button>
                    <Button
                      type="button"
                      variant={prefs.themeMode === "dark" ? "default" : "outline"}
                      size="sm"
                      onClick={() => updatePreferences({ themeMode: "dark" })}
                      className="text-xs min-h-9"
                    >
                      <Moon className="size-3.5" /> Dark
                    </Button>
                    <Button
                      type="button"
                      variant={prefs.themeMode === "system" ? "default" : "outline"}
                      size="sm"
                      onClick={() => updatePreferences({ themeMode: "system" })}
                      className="text-xs min-h-9"
                    >
                      <Monitor className="size-3.5" /> System
                    </Button>
                  </div>
                </div>

                {/* Animation Mode */}
                <div className="flex items-center justify-between gap-4 rounded-xl border border-border bg-secondary/20 p-4">
                  <div className="min-w-0 flex-1">
                    <p className="text-xs font-semibold text-foreground">Reduced Motion</p>
                    <p className="text-[11px] text-muted-foreground mt-0.5">
                      Minimize non-essential animations and transitions for improved focus or accessibility.
                    </p>
                  </div>
                  <Button
                    type="button"
                    variant={shouldReduceMotion ? "default" : "outline"}
                    size="sm"
                    onClick={() => updatePreferences({ motionMode: shouldReduceMotion ? "full" : "reduced" })}
                    className="min-h-9 min-w-20"
                  >
                    {shouldReduceMotion ? "Reduced" : "Full Motion"}
                  </Button>
                </div>

                {/* Compact Density Mode */}
                <div className="flex items-center justify-between gap-4 rounded-xl border border-border bg-secondary/20 p-4">
                  <div className="min-w-0 flex-1">
                    <p className="text-xs font-semibold text-foreground">High-Density Card Layout</p>
                    <p className="text-[11px] text-muted-foreground mt-0.5">
                      Display more items on screen with condensed card padding.
                    </p>
                  </div>
                  <Button
                    type="button"
                    variant={prefs.compactCards ? "default" : "outline"}
                    size="sm"
                    onClick={() => updatePreferences({ compactCards: !prefs.compactCards })}
                    className="min-h-9 min-w-20"
                  >
                    {prefs.compactCards ? "Enabled" : "Disabled"}
                  </Button>
                </div>

                {/* Restore Defaults */}
                <div className="pt-2 flex justify-end">
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    onClick={resetPreferences}
                    className="text-xs text-muted-foreground hover:text-foreground"
                  >
                    <RotateCcw className="size-3.5" /> Restore Default Preferences
                  </Button>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </DialogContent>
    </Dialog>
  );
}
