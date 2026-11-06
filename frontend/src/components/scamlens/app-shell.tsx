import { useEffect, useState, type ReactNode } from "react";
import { Link, useNavigate, useRouterState } from "@tanstack/react-router";
import { supabase } from "@/integrations/supabase/client";
import {
  Activity,
  BarChart3,
  ChevronLeft,
  ChevronRight,
  FileBarChart,
  FileSearch,
  GraduationCap,
  History,
  Link2,
  LogOut,
  Menu,
  ScanText,
  Settings,
  ShieldCheck,
  Sparkles,
  Upload,
  User,
  X,
} from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { healthQueryOptions } from "@/lib/scamlens-queries";
import { useScamlensPreferences } from "@/lib/scamlens-preferences";
import { ThemeSwitcher } from "./primitives";
import { ScamLensIcon, ScamLensLogo } from "./logo";
import { ProfileMenu } from "./profile-menu";
import { ProfileSettingsDialog } from "./profile-settings-dialog";

const items = [
  { to: "/", label: "Dashboard", icon: Activity },
  { to: "/message-analyzer", label: "Message Analyzer", icon: ScanText },
  { to: "/url-analyzer", label: "URL Analyzer", icon: Link2 },
  { to: "/batch-scanner", label: "Batch CSV Scanner", icon: Upload },
  { to: "/learn-practise", label: "Learn & Practise", icon: GraduationCap },
  { to: "/analytics", label: "Analytics", icon: BarChart3 },
  { to: "/scan-history", label: "Scan History", icon: History },
  { to: "/reports", label: "Reports", icon: FileBarChart },
  { to: "/settings-information", label: "Settings & Information", icon: Settings },
] as const;

export function AppShell({ children }: { children: ReactNode }) {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [mobileProfileOpen, setMobileProfileOpen] = useState(false);
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const { shouldReduceMotion, updatePreferences } = useScamlensPreferences();

  const user = useQuery({
    queryKey: ["auth-user"],
    queryFn: async () => (await supabase.auth.getUser()).data.user,
    staleTime: 60_000,
  });

  async function signOut() {
    setMobileOpen(false);
    await queryClient.cancelQueries();
    queryClient.clear();
    await supabase.auth.signOut();
    navigate({ to: "/auth", replace: true });
  }

  const path = useRouterState({ select: (state) => state.location.pathname });
  const health = useQuery(healthQueryOptions());
  const connected = health.isSuccess && health.data.healthy;

  // Close mobile drawer on route change or Escape key
  useEffect(() => {
    setMobileOpen(false);
  }, [path]);

  useEffect(() => {
    if (!mobileOpen) return;
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setMobileOpen(false);
    };
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [mobileOpen]);

  const renderNav = (scope: "desktop" | "mobile") => (
    <>
      <div className="flex h-16 shrink-0 items-center border-b border-sidebar-border px-3 sm:h-18">
        {collapsed && scope === "desktop" ? (
          <div className="flex w-full justify-center">
            <ScamLensIcon size={32} glow />
          </div>
        ) : (
          <ScamLensLogo size="sm" showTagline={true} />
        )}
      </div>

      <nav className="flex-1 space-y-1 overflow-y-auto p-3" aria-label="Main navigation">
        {items.map((item) => {
          const active =
            item.to === "/"
              ? path === "/"
              : item.to === "/settings-information"
                ? path.startsWith("/settings-information") || path.startsWith("/ai-models") || path.startsWith("/about")
                : path.startsWith(item.to);
          return (
            <Link
              key={item.to}
              to={item.to}
              onClick={() => setMobileOpen(false)}
              className={cn(
                "group relative flex min-h-11 items-center gap-3 overflow-hidden rounded-lg px-3 text-sm transition-colors duration-150 lg:min-h-10",
                active
                  ? "font-semibold text-sidebar-accent-foreground"
                  : "text-muted-foreground hover:bg-sidebar-accent/60 hover:text-sidebar-foreground",
                collapsed && scope === "desktop" && "justify-center px-0"
              )}
              aria-label={item.label}
            >
              {active && (
                <motion.span
                  layoutId={`sidebar-active-pill-${scope}`}
                  transition={
                    shouldReduceMotion
                      ? { duration: 0 }
                      : { type: "spring", stiffness: 380, damping: 32 }
                  }
                  className="pointer-events-none absolute inset-0 rounded-lg bg-sidebar-accent shadow-[inset_3px_0_0_0_var(--color-primary)]"
                />
              )}
              <item.icon
                className={cn(
                  "relative z-10 size-4 shrink-0 transition-transform duration-150",
                  !shouldReduceMotion && "group-hover:scale-110 group-hover:-rotate-3",
                  active && "text-primary"
                )}
              />
              {(!collapsed || scope === "mobile") && (
                <span className="relative z-10 truncate transition-transform duration-150 group-hover:translate-x-0.5">
                  {item.label}
                </span>
              )}
            </Link>
          );
        })}
      </nav>

      {scope === "mobile" && (
        <div className="space-y-2.5 border-t border-sidebar-border px-3 py-3">
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              setMobileOpen(false);
              setMobileProfileOpen(true);
            }}
            className="w-full min-h-10 justify-start gap-2 border-primary/30 bg-primary/5 text-xs font-semibold text-foreground hover:bg-primary/10"
          >
            <User className="size-4 text-primary" />
            <span>My Profile &amp; Settings</span>
          </Button>

          <div>
            <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
              Theme Appearance
            </p>
            <ThemeSwitcher scopeId="mobile-drawer" />
          </div>
          <div className="flex items-center justify-between gap-2">
            <button
              type="button"
              onClick={() => updatePreferences({ motionMode: shouldReduceMotion ? "full" : "reduced" })}
              className="flex min-h-10 flex-1 items-center justify-center gap-1.5 rounded-lg border border-border bg-card px-3 py-2 text-xs font-medium text-foreground transition-colors hover:border-primary/40"
            >
              <Sparkles className={cn("size-3.5", !shouldReduceMotion ? "text-primary" : "text-muted-foreground")} />
              <span>Motion: {shouldReduceMotion ? "Reduced" : "Full"}</span>
            </button>
            <Button variant="outline" size="sm" onClick={signOut} className="min-h-10 px-3">
              <LogOut className="size-3.5" />
              <span>Sign out</span>
            </Button>
          </div>
          {user.data?.email && (
            <p className="truncate text-center text-[11px] text-muted-foreground">
              Signed in as <strong className="text-foreground">{user.data.email}</strong>
            </p>
          )}
        </div>
      )}

      <div className="border-t border-sidebar-border p-3">
        <div className={cn("flex items-center gap-3 rounded-lg bg-secondary p-3", collapsed && scope === "desktop" && "justify-center p-2")}>
          <span className={cn("relative size-2 shrink-0 rounded-full", connected ? "bg-safe" : "bg-warning")}>
            {(health.isFetching || connected) && !shouldReduceMotion && (
              <span className={cn("absolute inset-0 animate-ping rounded-full opacity-40", connected ? "bg-safe" : "bg-warning")} />
            )}
          </span>
          {(!collapsed || scope === "mobile") && (
            <div className="min-w-0">
              <p className="truncate text-xs font-medium text-sidebar-foreground">
                {connected ? "Connected" : "Backend unavailable"}
              </p>
              <p className="mt-0.5 truncate text-[10px] text-muted-foreground">
                {connected ? "Python service is healthy" : "Static analysis only"}
              </p>
            </div>
          )}
        </div>
      </div>
    </>
  );

  return (
    <div className="min-h-screen w-full overflow-x-hidden bg-background text-foreground">
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-40 hidden border-r border-sidebar-border bg-sidebar transition-[width,background-color,border-color] duration-200 lg:flex lg:flex-col",
          collapsed ? "w-18" : "w-64"
        )}
      >
        {renderNav("desktop")}
        <Button
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          variant="outline"
          size="icon"
          onClick={() => setCollapsed(!collapsed)}
          className="absolute -right-4 top-22 size-8 rounded-full bg-card shadow-md transition-transform hover:scale-105"
        >
          {collapsed ? <ChevronRight /> : <ChevronLeft />}
        </Button>
      </aside>

      <AnimatePresence>
        {mobileOpen && (
          <motion.div
            key="mobile-nav-backdrop"
            initial={shouldReduceMotion ? false : { opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={shouldReduceMotion ? { opacity: 1 } : { opacity: 0 }}
            transition={{ duration: 0.18 }}
            className="fixed inset-0 z-50 bg-overlay backdrop-blur-xs lg:hidden"
            onClick={() => setMobileOpen(false)}
          >
            <motion.aside
              initial={shouldReduceMotion ? false : { x: -300 }}
              animate={{ x: 0 }}
              exit={shouldReduceMotion ? { x: 0 } : { x: -300 }}
              transition={{ duration: 0.22, ease: "easeOut" }}
              className="relative flex h-full w-[min(86vw,300px)] flex-col border-r border-sidebar-border bg-sidebar shadow-2xl"
              onClick={(event) => event.stopPropagation()}
            >
              <Button
                variant="ghost"
                size="icon"
                className="absolute right-2.5 top-3 z-10 min-h-10 min-w-10"
                onClick={() => setMobileOpen(false)}
                aria-label="Close menu"
              >
                <X className="size-5" />
              </Button>
              {renderNav("mobile")}
            </motion.aside>
          </motion.div>
        )}
      </AnimatePresence>

      <div className={cn("min-w-0 transition-[padding] duration-200", collapsed ? "lg:pl-18" : "lg:pl-64")}>
        <header className="sticky top-0 z-30 flex h-16 items-center justify-between gap-2 border-b border-border bg-background/90 px-3 backdrop-blur-md sm:px-5 md:px-7">
          <div className="flex min-w-0 items-center gap-2 sm:gap-3">
            <Button
              variant="ghost"
              size="icon"
              className="min-h-10 min-w-10 shrink-0 lg:hidden"
              onClick={() => setMobileOpen(true)}
              aria-label="Open menu"
            >
              <Menu className="size-5" />
            </Button>
            <div className="flex items-center gap-2 lg:hidden">
              <ScamLensIcon size={26} glow={false} />
            </div>
            <div className="min-w-0">
              <p className="truncate text-xs font-semibold text-foreground sm:text-sm">
                Security Analysis Workspace
              </p>
              <p className="hidden truncate text-xs text-muted-foreground sm:block">
                See the risk before you click.
              </p>
            </div>
          </div>

          <div className="flex shrink-0 items-center gap-1.5 sm:gap-2">
            {/* Theme Switcher: Compact Icon on Mobile (<640px), Full 3-Mode Pill on sm+ */}
            <ThemeSwitcher scopeId="header" compactMobile />

            {/* Motion Preference Quick Toggle */}
            <motion.button
              type="button"
              whileHover={shouldReduceMotion ? { scale: 1 } : { y: -1 }}
              whileTap={shouldReduceMotion ? { scale: 1 } : { scale: 0.97 }}
              onClick={() => updatePreferences({ motionMode: shouldReduceMotion ? "full" : "reduced" })}
              title={shouldReduceMotion ? "Enable full UI animations" : "Switch to reduced motion"}
              className="hidden min-h-9 items-center gap-1.5 rounded-lg border border-border bg-card px-2.5 py-1.5 text-xs font-medium text-muted-foreground transition-colors hover:border-primary/35 hover:text-foreground xl:flex"
            >
              <Sparkles className={cn("size-3.5 transition-transform duration-200", !shouldReduceMotion ? "text-primary" : "text-muted-foreground")} />
              <span>{shouldReduceMotion ? "Motion: Reduced" : "Motion: Full"}</span>
            </motion.button>

            <div className="hidden shrink-0 items-center gap-2 rounded-lg border border-border bg-card px-3 py-1.5 text-xs text-muted-foreground md:flex">
              <FileSearch className={cn("size-3.5", connected ? "text-safe" : "text-primary")} />
              <span>{connected ? "ML analysis connected" : "Static analysis only"}</span>
            </div>

            {/* Complete Profile Menu & Settings Dropdown */}
            <ProfileMenu />
          </div>
        </header>

        <motion.main
          key={path}
          initial={shouldReduceMotion ? false : { opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: shouldReduceMotion ? 0 : 0.24, ease: "easeOut" }}
          className="mx-auto min-w-0 max-w-[1600px] p-3.5 sm:p-5 md:p-7 lg:p-8"
        >
          {children}
        </motion.main>
      </div>

      <ProfileSettingsDialog
        open={mobileProfileOpen}
        onOpenChange={setMobileProfileOpen}
      />
    </div>
  );
}
