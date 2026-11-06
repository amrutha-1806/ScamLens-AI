import { useCallback, useEffect, useState } from "react";
import { useReducedMotion } from "motion/react";

export type MotionPreference = "full" | "reduced";
export type ThemePreference = "light" | "dark" | "system";
export type ResolvedTheme = "light" | "dark";

export interface ScamlensPreferences {
  /**
   * 'full' enables smooth UI transitions, KPI counter animations, and scanning effects
   * (unless the OS/browser forces prefers-reduced-motion and honorSystemReducedMotion is true).
   * 'reduced' disables non-essential motion across the workspace.
   */
  motionMode: MotionPreference;
  /**
   * Whether to automatically respect the OS/browser `prefers-reduced-motion: reduce` setting.
   */
  honorSystemReducedMotion: boolean;
  /**
   * Visual color theme preference: 'light', 'dark', or 'system'.
   * Kept independent of motionMode.
   */
  themeMode: ThemePreference;
  /**
   * Whether to display high-priority in-app alert banners when a High/Very High risk scam is detected.
   */
  inAppRiskAlerts: boolean;
  /**
   * Whether to play an audible security alert ping upon detecting a confirmed scam or high-risk URL.
   */
  soundAlerts: boolean;
  /**
   * Whether to render compact UI cards for information-dense monitoring.
   */
  compactCards: boolean;
}

export const PREFS_STORAGE_KEY = "scamlens_ui_preferences_v1";
const PREFS_EVENT_NAME = "scamlens:preferences-updated";

const DEFAULT_PREFERENCES: ScamlensPreferences = {
  motionMode: "full",
  honorSystemReducedMotion: true,
  themeMode: "dark",
  inAppRiskAlerts: true,
  soundAlerts: false,
  compactCards: false,
};

export function readStoredPreferences(): ScamlensPreferences {
  if (typeof window === "undefined") return DEFAULT_PREFERENCES;
  try {
    const raw = window.localStorage.getItem(PREFS_STORAGE_KEY);
    if (!raw) return DEFAULT_PREFERENCES;
    const parsed = JSON.parse(raw) as Partial<ScamlensPreferences>;
    const themeMode: ThemePreference =
      parsed.themeMode === "light" || parsed.themeMode === "dark" || parsed.themeMode === "system"
        ? parsed.themeMode
        : "dark";
    return {
      motionMode: parsed.motionMode === "reduced" ? "reduced" : "full",
      honorSystemReducedMotion:
        typeof parsed.honorSystemReducedMotion === "boolean"
          ? parsed.honorSystemReducedMotion
          : true,
      themeMode,
      inAppRiskAlerts: typeof parsed.inAppRiskAlerts === "boolean" ? parsed.inAppRiskAlerts : true,
      soundAlerts: typeof parsed.soundAlerts === "boolean" ? parsed.soundAlerts : false,
      compactCards: typeof parsed.compactCards === "boolean" ? parsed.compactCards : false,
    };
  } catch {
    return DEFAULT_PREFERENCES;
  }
}

export function getSystemColorScheme(): ResolvedTheme {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
    return "dark";
  }
  return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

export function resolveThemeMode(themeMode: ThemePreference, systemScheme: ResolvedTheme): ResolvedTheme {
  return themeMode === "system" ? systemScheme : themeMode;
}

export function applyThemeToDocument(resolved: ResolvedTheme): void {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  root.classList.toggle("dark", resolved === "dark");
  root.classList.toggle("light", resolved === "light");
  root.setAttribute("data-theme", resolved);
  root.style.colorScheme = resolved;
}

let hasHydratedGlobal = false;
let clientPrefsCache: ScamlensPreferences = DEFAULT_PREFERENCES;
let clientOsSchemeCache: ResolvedTheme = "dark";

export function writeStoredPreferences(next: ScamlensPreferences): void {
  clientPrefsCache = next;
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(PREFS_STORAGE_KEY, JSON.stringify(next));
    applyThemeToDocument(resolveThemeMode(next.themeMode, getSystemColorScheme()));
    window.dispatchEvent(new CustomEvent(PREFS_EVENT_NAME, { detail: next }));
  } catch {
    // Ignore storage write errors
  }
}

export function useScamlensPreferences() {
  const osReducedMotion = useReducedMotion() ?? false;
  const [isHydrated, setIsHydrated] = useState(hasHydratedGlobal);
  const [prefs, setPrefs] = useState<ScamlensPreferences>(() =>
    hasHydratedGlobal ? clientPrefsCache : DEFAULT_PREFERENCES
  );
  const [osColorScheme, setOsColorScheme] = useState<ResolvedTheme>(() =>
    hasHydratedGlobal ? clientOsSchemeCache : "dark"
  );

  useEffect(() => {
    hasHydratedGlobal = true;
    setIsHydrated(true);

    const current = readStoredPreferences();
    const sys = getSystemColorScheme();
    clientPrefsCache = current;
    clientOsSchemeCache = sys;

    setPrefs(current);
    setOsColorScheme(sys);
    applyThemeToDocument(resolveThemeMode(current.themeMode, sys));

    const handleStorage = (event: StorageEvent) => {
      if (event.key === PREFS_STORAGE_KEY) {
        const updated = readStoredPreferences();
        clientPrefsCache = updated;
        setPrefs(updated);
        applyThemeToDocument(resolveThemeMode(updated.themeMode, getSystemColorScheme()));
      }
    };
    const handleCustom = () => {
      const updated = readStoredPreferences();
      clientPrefsCache = updated;
      setPrefs(updated);
      applyThemeToDocument(resolveThemeMode(updated.themeMode, getSystemColorScheme()));
    };

    const mediaQuery =
      typeof window.matchMedia === "function"
        ? window.matchMedia("(prefers-color-scheme: light)")
        : null;

    const handleMediaChange = () => {
      const nextSys = getSystemColorScheme();
      clientOsSchemeCache = nextSys;
      setOsColorScheme(nextSys);
      const latest = readStoredPreferences();
      applyThemeToDocument(resolveThemeMode(latest.themeMode, nextSys));
    };

    window.addEventListener("storage", handleStorage);
    window.addEventListener(PREFS_EVENT_NAME, handleCustom);
    mediaQuery?.addEventListener("change", handleMediaChange);

    return () => {
      window.removeEventListener("storage", handleStorage);
      window.removeEventListener(PREFS_EVENT_NAME, handleCustom);
      mediaQuery?.removeEventListener("change", handleMediaChange);
    };
  }, []);

  const updatePreferences = useCallback((patch: Partial<ScamlensPreferences>) => {
    setPrefs((prev) => {
      const updated: ScamlensPreferences = { ...prev, ...patch };
      writeStoredPreferences(updated);
      return updated;
    });
  }, []);

  const resetPreferences = useCallback(() => {
    writeStoredPreferences(DEFAULT_PREFERENCES);
    setPrefs(DEFAULT_PREFERENCES);
  }, []);

  const setThemeMode = useCallback((mode: ThemePreference) => {
    updatePreferences({ themeMode: mode });
  }, [updatePreferences]);

  const shouldReduceMotion =
    prefs.motionMode === "reduced" ||
    (prefs.honorSystemReducedMotion && (isHydrated ? osReducedMotion : false));

  const resolvedTheme: ResolvedTheme = resolveThemeMode(prefs.themeMode, osColorScheme);

  return {
    prefs,
    osReducedMotion,
    osColorScheme,
    resolvedTheme,
    shouldReduceMotion,
    isHydrated,
    setThemeMode,
    updatePreferences,
    resetPreferences,
  };
}
