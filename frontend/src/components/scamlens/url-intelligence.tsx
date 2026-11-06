import { motion } from "motion/react";
import {
  AlertTriangle,
  CheckCircle2,
  Cpu,
  Globe2,
  Info,
  Link2,
  Lock,
  LockKeyhole,
  Network,
  Radar,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Zap,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useScamlensPreferences } from "@/lib/scamlens-preferences";
import type { UrlIntelligenceData } from "@/lib/scamlens-types";

export function UrlIntelligenceCard({ intelligence }: { intelligence: UrlIntelligenceData }) {
  const { shouldReduceMotion } = useScamlensPreferences();
  const { components, metrics, findings, brand_match, heuristic_level, heuristic_score } = intelligence;

  // Entropy evaluation
  const entropy = metrics.domain_entropy_bits;
  const entropyLevel = entropy > 3.8 ? "High" : entropy > 2.8 ? "Moderate" : "Low";
  const entropyColor =
    entropyLevel === "High" ? "text-danger" : entropyLevel === "Moderate" ? "text-warning" : "text-safe";
  const entropyBarPct = Math.min(100, Math.max(0, (entropy / 5.0) * 100));

  return (
    <motion.div
      initial={shouldReduceMotion ? false : { opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: shouldReduceMotion ? 0 : 0.25 }}
      className="space-y-4 rounded-xl border border-primary/25 bg-card p-4 shadow-panel sm:p-5 dark:border-cyan-500/25 dark:bg-slate-950/70"
    >
      {/* Header & Security Guarantee */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border pb-3.5 dark:border-slate-800">
        <div className="flex items-center gap-2.5">
          <div className="grid size-9 place-items-center rounded-lg bg-primary/10 text-primary dark:bg-cyan-500/10 dark:text-cyan-400">
            <Link2 className="size-5" />
          </div>
          <div>
            <h4 className="text-sm font-bold text-foreground">URL Safety Analysis</h4>
            <p className="text-[11px] text-muted-foreground">
              Zero network execution • Structural pattern recognition, domain checks &amp; heuristics.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span
            className={cn(
              "rounded-full border px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider",
              heuristic_level === "High"
                ? "border-danger/40 bg-danger/10 text-danger"
                : heuristic_level === "Elevated"
                  ? "border-warning/40 bg-warning/10 text-warning"
                  : "border-safe/40 bg-safe/10 text-safe"
            )}
          >
            {heuristic_level} Heuristic Risk
          </span>
          <span className="inline-flex items-center gap-1 rounded-full border border-primary/30 bg-primary/10 px-2 py-0.5 text-[10px] font-semibold text-primary dark:border-cyan-500/30 dark:text-cyan-300">
            <Lock className="size-3" />
            100% Offline Static
          </span>
        </div>
      </div>

      {/* Safety Guarantee Callout */}
      <div className="flex items-start gap-2.5 rounded-lg border border-safe/30 bg-safe/5 p-3 text-xs leading-relaxed text-muted-foreground dark:border-emerald-900/40 dark:bg-emerald-950/20">
        <ShieldCheck className="mt-0.5 size-4 shrink-0 text-safe dark:text-emerald-400" />
        <div>
          <strong className="text-foreground dark:text-emerald-300">Safety Guarantee: </strong>
          The analyzer checks the URL as text without opening or contacting the website.
        </div>
      </div>

      {/* Brand Impersonation / Typosquatting Alert */}
      {brand_match && (
        <div
          className={cn(
            "rounded-lg border p-3.5 text-xs leading-relaxed",
            brand_match.type === "official_domain"
              ? "border-safe/40 bg-safe/10 text-safe dark:border-emerald-500/30 dark:bg-emerald-950/25"
              : "border-danger/40 bg-danger/10 text-danger dark:border-rose-500/30 dark:bg-rose-950/25"
          )}
        >
          <div className="flex items-center gap-2 font-semibold">
            {brand_match.type === "official_domain" ? (
              <CheckCircle2 className="size-4 shrink-0 text-safe" />
            ) : (
              <ShieldAlert className="size-4 shrink-0 text-danger" />
            )}
            <span>
              {brand_match.type === "official_domain"
                ? `Official Domain Verified: ${brand_match.brand.toUpperCase()}`
                : brand_match.type === "typosquat"
                  ? `Typosquatting Detected targeting ${brand_match.brand.toUpperCase()}`
                  : `Brand Impersonation Detected: ${brand_match.brand.toUpperCase()}`}
            </span>
          </div>
          <p className="mt-1 text-[11px] opacity-90">
            {brand_match.type === "official_domain"
              ? `This domain matches the verified legitimate web properties for ${brand_match.brand}.`
              : `The hostname mimics ${brand_match.brand}, but official legitimate domains are: ${brand_match.official_domains.join(
                  ", "
                )}. This is a high-risk phishing indicator.`}
          </p>
        </div>
      )}

      {/* Critical Indicator Badges */}
      <div className="grid gap-2.5 sm:grid-cols-3">
        {/* Shortener */}
        <div
          className={cn(
            "rounded-lg border p-3 text-xs",
            metrics.is_shortener
              ? "border-warning/40 bg-warning/10 text-warning"
              : "border-border bg-secondary/25 text-muted-foreground"
          )}
        >
          <span className="text-[10px] font-semibold uppercase tracking-wider">URL Shortener</span>
          <p className="mt-1 font-semibold text-foreground">
            {metrics.is_shortener ? "Yes (Masks Final Target)" : "No (Direct Host)"}
          </p>
        </div>

        {/* IP Address Host */}
        <div
          className={cn(
            "rounded-lg border p-3 text-xs",
            components.is_ip_address
              ? "border-danger/40 bg-danger/10 text-danger"
              : "border-border bg-secondary/25 text-muted-foreground"
          )}
        >
          <span className="text-[10px] font-semibold uppercase tracking-wider">Host Format</span>
          <p className="mt-1 font-semibold text-foreground">
            {components.is_ip_address ? `Raw IP (${components.ip_address})` : "Domain Name (FQDN)"}
          </p>
        </div>

        {/* Suspicious TLD */}
        <div
          className={cn(
            "rounded-lg border p-3 text-xs",
            metrics.suspicious_tld
              ? "border-warning/40 bg-warning/10 text-warning"
              : "border-border bg-secondary/25 text-muted-foreground"
          )}
        >
          <span className="text-[10px] font-semibold uppercase tracking-wider">Domain Extension Check</span>
          <p className="mt-1 font-semibold text-foreground">
            {components.tld ? `.${components.tld}` : "None"} {metrics.suspicious_tld ? "(Frequently Abused)" : "(Standard)"}
          </p>
        </div>
      </div>

      {/* Unusual URL Pattern Gauge */}
      <div className="rounded-lg border border-border bg-secondary/20 p-3.5">
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
          <div className="flex items-center gap-2">
            <Radar className="size-4 text-primary" />
            <span className="font-semibold text-foreground">Unusual URL Pattern</span>
          </div>
          <div className="flex items-center gap-2">
            <span className={cn("font-mono font-bold", entropyColor)}>{entropy.toFixed(3)} bits/char</span>
            <span className="text-[10px] text-muted-foreground">({entropyLevel} randomness)</span>
          </div>
        </div>

        <div className="mt-2.5 h-2 w-full overflow-hidden rounded-full bg-secondary">
          <motion.div
            initial={shouldReduceMotion ? false : { width: 0 }}
            animate={{ width: `${entropyBarPct}%` }}
            transition={{ duration: shouldReduceMotion ? 0 : 0.5, ease: "easeOut" }}
            className={cn(
              "h-full rounded-full",
              entropyLevel === "High" ? "bg-danger" : entropyLevel === "Moderate" ? "bg-warning" : "bg-safe"
            )}
          />
        </div>
        <p className="mt-1.5 text-[10px] text-muted-foreground">
          Measures character randomness in the website name. High randomness often indicates machine-generated links or evasion attempts.
        </p>
      </div>

      {/* Structural Components Grid */}
      <div>
        <p className="mb-2 text-xs font-semibold text-foreground">Decomposed URL Elements</p>
        <div className="grid grid-cols-2 gap-2 text-xs sm:grid-cols-4">
          <div className="rounded border border-border bg-secondary/25 p-2.5">
            <span className="text-[10px] text-muted-foreground">Scheme</span>
            <p className="font-mono font-semibold text-foreground">{components.scheme}://</p>
          </div>
          <div className="rounded border border-border bg-secondary/25 p-2.5">
            <span className="text-[10px] text-muted-foreground">Website Address</span>
            <p className="truncate font-mono font-semibold text-foreground">{components.registrable_domain || "—"}</p>
          </div>
          <div className="rounded border border-border bg-secondary/25 p-2.5">
            <span className="text-[10px] text-muted-foreground">Subdomains Detected</span>
            <p className="font-mono font-semibold text-foreground">{components.subdomain_count} level(s)</p>
          </div>
          <div className="rounded border border-border bg-secondary/25 p-2.5">
            <span className="text-[10px] text-muted-foreground">Query Parameters</span>
            <p className="font-mono font-semibold text-foreground">{components.query_parameter_count} param(s)</p>
          </div>
        </div>
      </div>

      {/* Static Findings List */}
      {findings.length > 0 && (
        <div className="space-y-2">
          <p className="text-xs font-semibold text-foreground">Why This Link Looks Suspicious ({findings.length})</p>
          <div className="space-y-1.5">
            {findings.map((f, i) => (
              <div
                key={i}
                className="flex items-start gap-2.5 rounded-lg border border-border bg-secondary/20 p-2.5 text-xs text-foreground"
              >
                <span
                  className={cn(
                    "mt-0.5 shrink-0 rounded px-1.5 py-0.5 font-mono text-[9px] font-bold uppercase",
                    f.severity === "high"
                      ? "bg-danger/20 text-danger dark:text-rose-300"
                      : f.severity === "medium"
                        ? "bg-warning/20 text-warning dark:text-amber-300"
                        : "bg-muted text-muted-foreground"
                  )}
                >
                  {f.severity}
                </span>
                <div className="min-w-0 flex-1">
                  <p className="font-semibold text-foreground">{f.title}</p>
                  <p className="mt-0.5 text-[11px] text-muted-foreground">{f.detail}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </motion.div>
  );
}
