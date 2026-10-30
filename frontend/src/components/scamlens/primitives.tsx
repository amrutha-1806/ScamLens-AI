import { useEffect, useState, type ReactNode } from "react";
import { AlertTriangle, BarChart3, Clock3, Database, LoaderCircle, Monitor, Moon, ShieldCheck, Sun } from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import { cn } from "@/lib/utils";
import { useScamlensPreferences, type ThemePreference } from "@/lib/scamlens-preferences";

/**
 * Smoothly animates a numeric value from 0 (or previous value) to its real target value
 * unless reduced-motion is active.
 */
function AnimatedMetricValue({ value, reduceMotion }: { value: string | number | undefined; reduceMotion: boolean }) {
  const numericTarget = typeof value === "number" ? value : null;
  const [displayNum, setDisplayNum] = useState<number>(numericTarget ?? 0);

  useEffect(() => {
    if (numericTarget === null) return;
    if (reduceMotion) {
      setDisplayNum(numericTarget);
      return;
    }
    let frameId = 0;
    const duration = 520;
    const startTime = performance.now();
    const startValue = 0;

    const tick = (now: number) => {
      const elapsed = now - startTime;
      const progress = Math.min(1, elapsed / duration);
      // Ease-out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      setDisplayNum(Math.round(startValue + (numericTarget - startValue) * eased));
      if (progress < 1) {
        frameId = requestAnimationFrame(tick);
      }
    };

    frameId = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frameId);
  }, [numericTarget, reduceMotion]);

  if (value === undefined) return <>—</>;
  if (numericTarget !== null) return <>{displayNum.toLocaleString()}</>;
  return <>{value}</>;
}

/**
 * Reusable Theme Switcher supporting Light, Dark, and System modes.
 */
export function ThemeSwitcher({
  scopeId = "header",
  compactMobile = false,
}: {
  scopeId?: string | undefined;
  compactMobile?: boolean | undefined;
}) {
  const { prefs, resolvedTheme, shouldReduceMotion, updatePreferences } = useScamlensPreferences();

  const modes: { id: ThemePreference; label: string; icon: typeof Sun }[] = [
    { id: "light", label: "Light", icon: Sun },
    { id: "dark", label: "Dark", icon: Moon },
    { id: "system", label: "System", icon: Monitor },
  ];

  function cycleTheme() {
    const next: ThemePreference =
      prefs.themeMode === "dark" ? "light" : prefs.themeMode === "light" ? "system" : "dark";
    updatePreferences({ themeMode: next });
  }

  const CurrentIcon =
    prefs.themeMode === "system" ? Monitor : resolvedTheme === "light" ? Sun : Moon;

  return (
    <div className="flex items-center">
      {compactMobile && (
        <motion.button
          type="button"
          whileTap={shouldReduceMotion ? { scale: 1 } : { scale: 0.94 }}
          onClick={cycleTheme}
          aria-label={`Switch theme (current: ${prefs.themeMode})`}
          title={`Theme: ${prefs.themeMode} (${resolvedTheme}). Tap to switch.`}
          className="inline-flex min-h-10 min-w-10 items-center justify-center gap-1.5 rounded-lg border border-border bg-card px-2.5 text-xs font-medium text-foreground shadow-2xs transition-colors hover:border-primary/40 sm:hidden"
        >
          <AnimatePresence mode="wait" initial={false}>
            <motion.span
              key={prefs.themeMode}
              initial={shouldReduceMotion ? false : { opacity: 0, rotate: -30, scale: 0.75 }}
              animate={{ opacity: 1, rotate: 0, scale: 1 }}
              exit={shouldReduceMotion ? { opacity: 1 } : { opacity: 0, rotate: 30, scale: 0.75 }}
              transition={{ duration: shouldReduceMotion ? 0 : 0.18 }}
              className="inline-flex text-primary"
            >
              <CurrentIcon className="size-4" />
            </motion.span>
          </AnimatePresence>
        </motion.button>
      )}

      <div
        role="group"
        aria-label="Color theme switcher"
        className={cn(
          "items-center gap-0.5 rounded-lg border border-border bg-card p-1 shadow-2xs",
          compactMobile ? "hidden sm:inline-flex" : "inline-flex w-full sm:w-auto"
        )}
      >
        {modes.map((m) => {
          const Icon = m.icon;
          const active = prefs.themeMode === m.id;
          return (
            <button
              key={m.id}
              type="button"
              onClick={() => updatePreferences({ themeMode: m.id })}
              aria-pressed={active}
              title={`Switch to ${m.label} theme`}
              className={cn(
                "relative flex min-h-8 flex-1 items-center justify-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-semibold transition-colors sm:flex-initial",
                active
                  ? "text-primary-foreground"
                  : "text-muted-foreground hover:text-foreground"
              )}
            >
              {active && (
                <motion.span
                  layoutId={`theme-switcher-pill-${scopeId}`}
                  transition={
                    shouldReduceMotion
                      ? { duration: 0 }
                      : { type: "spring", stiffness: 400, damping: 30 }
                  }
                  className="pointer-events-none absolute inset-0 rounded-md bg-primary shadow-xs"
                />
              )}
              <motion.span
                animate={
                  active && !shouldReduceMotion
                    ? { rotate: m.id === "light" ? 15 : m.id === "dark" ? -10 : 0, scale: 1.05 }
                    : { rotate: 0, scale: 1 }
                }
                transition={{ duration: 0.2 }}
                className="relative z-10 inline-flex"
              >
                <Icon className="size-3.5" />
              </motion.span>
              <span className="relative z-10">{m.label}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

export function PageHeader({ eyebrow, title, description, actions }: { eyebrow: string; title: string; description: string; actions?: ReactNode }) {
  const { shouldReduceMotion } = useScamlensPreferences();
  return (
    <motion.header
      initial={shouldReduceMotion ? false : { opacity: 0, y: -6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25, ease: "easeOut" }}
      className="grid grid-cols-1 gap-4 border-b border-border pb-5 sm:pb-6 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-end"
    >
      <div className="min-w-0">
        <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-widest text-primary sm:mb-2 sm:text-xs">{eyebrow}</p>
        <h1 className="text-xl font-bold tracking-tight text-foreground sm:text-2xl md:text-3xl">{title}</h1>
        <p className="mt-1.5 max-w-2xl text-xs leading-5 text-muted-foreground sm:mt-2 sm:text-sm sm:leading-6">{description}</p>
      </div>
      {actions && <div className="w-full shrink-0 lg:w-auto">{actions}</div>}
    </motion.header>
  );
}

export function Panel({
  title,
  description,
  action,
  children,
  className,
  delay = 0,
}: {
  title: string;
  description?: string | undefined;
  action?: ReactNode;
  children: ReactNode;
  className?: string | undefined;
  delay?: number | undefined;
}) {
  const { shouldReduceMotion } = useScamlensPreferences();
  return (
    <motion.section
      initial={shouldReduceMotion ? false : { opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: shouldReduceMotion ? 0 : 0.28, delay: shouldReduceMotion ? 0 : delay, ease: "easeOut" }}
      className={cn(
        "min-w-0 rounded-xl border border-border bg-card shadow-panel transition-[border-color,box-shadow,background-color] duration-200 hover:border-primary/30",
        className
      )}
    >
      <div className="flex flex-col gap-3 border-b border-border px-4 py-3.5 sm:grid sm:grid-cols-[minmax(0,1fr)_auto] sm:items-start sm:px-5 sm:py-4">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold text-card-foreground sm:text-base">{title}</h2>
          {description && <p className="mt-1 text-xs leading-5 text-muted-foreground">{description}</p>}
        </div>
        {action && <div className="w-full shrink-0 sm:w-auto">{action}</div>}
      </div>
      <div className="min-w-0 p-4 sm:p-5">{children}</div>
    </motion.section>
  );
}

export function KpiCard({
  label,
  icon: Icon,
  tone = "primary",
  value,
  note,
  delay = 0,
}: {
  label: string;
  icon: typeof ShieldCheck;
  tone?: "primary" | "safe" | "warning" | "danger" | undefined;
  value?: string | number | undefined;
  note?: string | undefined;
  delay?: number | undefined;
}) {
  const { shouldReduceMotion } = useScamlensPreferences();
  const toneClass = {
    primary: "bg-primary/10 text-primary border-primary/25",
    safe: "bg-safe/10 text-safe border-safe/25",
    warning: "bg-warning/10 text-warning border-warning/25",
    danger: "bg-danger/10 text-danger border-danger/25",
  }[tone];
  const glowHover = {
    primary: "hover:border-primary/40 hover:shadow-[0_10px_30px_-12px_rgba(56,189,248,0.22)]",
    safe: "hover:border-safe/40 hover:shadow-[0_10px_30px_-12px_rgba(34,197,94,0.22)]",
    warning: "hover:border-warning/40 hover:shadow-[0_10px_30px_-12px_rgba(245,158,11,0.22)]",
    danger: "hover:border-danger/40 hover:shadow-[0_10px_30px_-12px_rgba(239,68,68,0.22)]",
  }[tone];

  return (
    <motion.div
      initial={shouldReduceMotion ? false : { opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      whileHover={shouldReduceMotion ? { y: 0 } : { y: -3 }}
      transition={{ duration: shouldReduceMotion ? 0 : 0.24, delay: shouldReduceMotion ? 0 : delay, ease: "easeOut" }}
      className={cn(
        "group min-w-0 rounded-xl border border-border bg-card p-4 shadow-panel transition-all duration-200 sm:p-5",
        glowHover
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="truncate text-xs font-medium text-muted-foreground sm:text-sm">{label}</p>
          <p className={cn("mt-2.5 font-mono text-xl font-bold text-foreground sm:mt-3 sm:text-2xl", value === undefined && !shouldReduceMotion && "animate-pulse text-muted-foreground")}>
            <AnimatedMetricValue value={value} reduceMotion={shouldReduceMotion} />
          </p>
        </div>
        <span
          className={cn(
            "grid size-9 shrink-0 place-items-center rounded-lg border transition-transform duration-200",
            !shouldReduceMotion && "group-hover:scale-105",
            toneClass
          )}
        >
          <Icon className="size-4" />
        </span>
      </div>
      <p className="mt-2.5 flex items-center gap-1.5 truncate text-[11px] text-muted-foreground sm:mt-3 sm:text-xs">
        <Clock3 className="size-3.5 shrink-0" /> <span className="truncate">{note ?? "Awaiting backend data"}</span>
      </p>
    </motion.div>
  );
}

export function EmptyState({ title, description, compact = false }: { title: string; description: string; compact?: boolean }) {
  const { shouldReduceMotion } = useScamlensPreferences();
  return (
    <motion.div
      initial={shouldReduceMotion ? false : { opacity: 0, scale: 0.985 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: shouldReduceMotion ? 0 : 0.22, ease: "easeOut" }}
      className={cn(
        "flex flex-col items-center justify-center rounded-lg border border-dashed border-border bg-muted/30 px-4 py-6 text-center transition-colors hover:border-primary/25 sm:px-5",
        compact ? "min-h-36 sm:min-h-40" : "min-h-56 sm:min-h-64"
      )}
    >
      <motion.span
        whileHover={shouldReduceMotion ? { scale: 1 } : { scale: 1.06, y: -2 }}
        className="mb-3 grid size-11 place-items-center rounded-lg border border-border bg-secondary sm:mb-4"
      >
        <Database className="size-5 text-muted-foreground" />
      </motion.span>
      <h3 className="text-sm font-semibold text-foreground">{title}</h3>
      <p className="mt-1 max-w-sm text-xs leading-5 text-muted-foreground">{description}</p>
    </motion.div>
  );
}

export function ChartEmpty({ label }: { label: string }) {
  const { shouldReduceMotion } = useScamlensPreferences();
  return (
    <div className="relative flex min-h-48 items-end gap-2.5 overflow-hidden rounded-lg border border-border bg-chart-grid p-4 sm:min-h-52 sm:gap-3 sm:p-5">
      <div className="absolute inset-x-4 top-4 flex items-center justify-between text-xs text-muted-foreground sm:inset-x-5 sm:top-5">
        <span>{label}</span>
        <BarChart3 className="size-4" />
      </div>
      {[35, 55, 42, 72, 48, 65, 38].map((height, index) => (
        <motion.div
          key={index}
          initial={shouldReduceMotion ? false : { height: 0 }}
          animate={{ height: `${height}%` }}
          transition={{
            duration: shouldReduceMotion ? 0 : 0.45,
            delay: shouldReduceMotion ? 0 : index * 0.04,
            ease: "easeOut",
          }}
          className="flex-1 rounded-t-sm bg-muted/60"
        />
      ))}
      <span className="absolute inset-0 grid place-items-center px-3">
        <span className="rounded-md border border-border bg-card px-3 py-2 text-xs text-muted-foreground shadow-panel">
          No scan data available
        </span>
      </span>
    </div>
  );
}

export function ApiNotice({ kind = "idle", message }: { kind?: "idle" | "loading" | "error" | "success"; message?: string | undefined }) {
  const { shouldReduceMotion } = useScamlensPreferences();
  const Icon = kind === "loading" ? LoaderCircle : kind === "error" ? AlertTriangle : ShieldCheck;
  const errorTitle =
    message === "Backend unavailable"
      ? "Backend unavailable"
      : message?.includes("expected") || message?.includes("invalid response") || message?.includes("did not match")
        ? "Malformed backend response"
        : "Backend error";
  return (
    <motion.div
      key={`${kind}-${message ?? "default"}`}
      initial={shouldReduceMotion ? false : { opacity: 0, y: 5 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: shouldReduceMotion ? 0 : 0.2, ease: "easeOut" }}
      className={cn(
        "flex items-start gap-3 rounded-lg border p-3.5 text-sm sm:p-4",
        kind === "error"
          ? "border-danger/30 bg-danger/10 text-danger"
          : kind === "success"
            ? "border-safe/30 bg-safe/10 text-safe"
            : "border-primary/20 bg-primary/5 text-muted-foreground"
      )}
    >
      <Icon
        className={cn(
          "mt-0.5 size-4 shrink-0",
          kind === "loading" && "animate-spin",
          kind === "success" ? "text-safe" : kind !== "error" && "text-primary"
        )}
      />
      <div className="min-w-0">
        <p className="font-medium text-foreground">
          {kind === "loading"
            ? "Analysis in progress"
            : kind === "error"
              ? errorTitle
              : kind === "success"
                ? "Analysis complete"
                : "Ready for analysis"}
        </p>
        <p className="mt-1 break-words text-xs leading-5">
          {message ?? "Submit content to receive results from the connected Python service."}
        </p>
      </div>
    </motion.div>
  );
}
