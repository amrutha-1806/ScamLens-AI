import { useState } from "react";
import { motion, AnimatePresence } from "motion/react";
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
  ChevronRight,
  Layers,
  Search,
  Copy,
  Check,
  FolderTree,
  SlidersHorizontal,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useScamlensPreferences } from "@/lib/scamlens-preferences";
import type { UrlIntelligenceData, UrlFinding } from "@/lib/scamlens-types";

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

// ============================================================================
// Phase 2A: URL Anatomy Inspector
// ============================================================================

export type UrlComponentId =
  | "scheme"
  | "subdomain"
  | "registrable_domain"
  | "tld"
  | "port"
  | "path"
  | "query";

interface UrlSegment {
  id: UrlComponentId;
  name: string;
  shortLabel: string;
  tokenText: string;
  rawText: string;
  displayValue: string;
  present: boolean;
  severity: "safe" | "info" | "warning" | "danger";
  findings: UrlFinding[];
  offsets?: [number, number] | null;
  /** Query parameter names reported by the backend (query segment only). */
  paramNames?: string[];
  roleDescription: string;
  cleanExplanation: string;
}

const COMPONENT_BY_CODE: Record<string, UrlComponentId> = {
  no_https: "scheme",
  no_scheme: "scheme",
  non_web_scheme: "scheme",
  ip_host: "registrable_domain",
  typosquatting: "registrable_domain",
  idn_homograph: "registrable_domain",
  url_shortener: "registrable_domain",
  high_entropy: "registrable_domain",
  free_hosting: "registrable_domain",
  encoded_host: "registrable_domain",
  userinfo_at: "registrable_domain",
  deep_subdomains: "subdomain",
  suspicious_tld: "tld",
  non_standard_port: "port",
  risky_download: "path",
  credential_keywords: "path",
  path_double_slash: "path",
  embedded_redirect: "query",
  many_params: "query",
};

function resolveFindingComponent(finding: UrlFinding): UrlComponentId {
  // The backend tags every finding that targets a specific part of the URL.
  if (finding.component && isUrlComponentId(finding.component)) {
    return finding.component;
  }
  return COMPONENT_BY_CODE[finding.code] ?? "registrable_domain";
}

function isUrlComponentId(val: string): val is UrlComponentId {
  return [
    "scheme",
    "subdomain",
    "registrable_domain",
    "tld",
    "port",
    "path",
    "query",
  ].includes(val);
}

const COMPONENT_ICONS: Record<UrlComponentId, React.ComponentType<{ className?: string }>> = {
  scheme: LockKeyhole,
  subdomain: Layers,
  registrable_domain: Globe2,
  tld: Network,
  port: SlidersHorizontal,
  path: FolderTree,
  query: Search,
};

const COMPONENT_ROLES: Record<UrlComponentId, string> = {
  scheme: "The transfer protocol. Encrypted HTTPS protects data from interception, while plaintext HTTP exposes traffic.",
  subdomain: "Prefix before the primary domain. Phishers frequently create deceptive subdomains like 'paypal.com.evil.com'.",
  registrable_domain: "The authoritative domain registered with a registrar. The primary anchor of trust for web communications.",
  tld: "Top-Level Domain extension. Certain generic extensions have higher historical abuse and fraud rates.",
  port: "Network communication port. Standard web ports are 80 (HTTP) and 443 (HTTPS); unusual ports suggest hidden servers.",
  path: "Resource location on the web server. Attackers use familiar login path keywords or link to executable malware files.",
  query: "URL query parameters. Can contain hidden open redirect destinations or obfuscated tracking payloads.",
};

const COMPONENT_CLEAN_EXPLANATIONS: Record<UrlComponentId, string> = {
  scheme: "Secure HTTPS protocol in use. All data in transit is encrypted using modern TLS standards.",
  subdomain: "No deceptive subdomains or excessive nesting detected. Clean hierarchical structure.",
  registrable_domain: "No known brand impersonation, typosquatting, IDN homoglyphs, or abnormal entropy patterns detected.",
  tld: "Standard top-level domain extension with normal security reputation.",
  port: "Standard default web port in use (port 443 for HTTPS or 80 for HTTP). No abnormal ports.",
  path: "Clean resource path. No malicious download extensions or credential harvesting patterns identified.",
  query: "Standard query string. No suspicious embedded redirect targets or excessive parameter counts detected.",
};

const COMPONENT_VIVA_TIPS: Record<UrlComponentId, string> = {
  scheme: "Why analysts check the scheme: Phishing campaigns on unencrypted HTTP or unconventional protocols expose traffic or indicate unverified infrastructure.",
  subdomain: "Why analysts check subdomains: Scammers often construct deceptive subdomains like 'paypal.com.verify-login.xyz' hoping victims only glance at the start of the URL.",
  registrable_domain: "Why analysts check the registrable domain: The domain name is the cryptographic anchor of the site. Watch for lookalike domains (e.g. 'rnicrosoft.com' or 'paypa1.com').",
  tld: "Why analysts check the TLD: Low-cost or non-regulated TLDs (.top, .xyz, .cc) have high statistical prevalence in automated phishing kits.",
  port: "Why analysts check ports: Standard web traffic uses 80 (HTTP) or 443 (HTTPS). Non-standard ports (e.g., 8080, 8443, 2082) may bypass proxy firewalls or expose ad-hoc attacker servers.",
  path: "Why analysts check paths: Attackers frequently disguise credential harvesting forms under deep subpaths like '/account/security/login.php' or link to executable payloads.",
  query: "Why analysts check query parameters: Query strings can harbor open redirects (?redirect=https://evil.com) or base64-encoded payloads used to bypass URL filters.",
};

export function UrlAnatomyInspector({ intelligence }: { intelligence: UrlIntelligenceData }) {
  const { shouldReduceMotion } = useScamlensPreferences();
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const { components, findings } = intelligence;

  // Build component-level segments
  const segments: UrlSegment[] = (() => {
    if (!components) return [];

    const offsets = components.offsets || {};
    const findingsFor = (id: UrlComponentId) =>
      findings.filter((f) => resolveFindingComponent(f) === id);

    // 1. Scheme
    const schemeVal = components.scheme ? `${components.scheme}://` : "";
    const schemeFindings = findingsFor("scheme");
    const isHttps = components.scheme?.toLowerCase() === "https";
    const schemeSeverity: "safe" | "info" | "warning" | "danger" =
      schemeFindings.some((f) => f.severity === "high")
        ? "danger"
        : schemeFindings.some((f) => f.severity === "medium")
          ? "warning"
          : isHttps
            ? "safe"
            : "warning";

    // 2. Subdomain
    const subVal = components.subdomain || "";
    const subFindings = findingsFor("subdomain");
    const subSeverity: "safe" | "info" | "warning" | "danger" =
      subFindings.some((f) => f.severity === "high")
        ? "danger"
        : subFindings.some((f) => f.severity === "medium")
          ? "warning"
          : subFindings.some((f) => f.severity === "low")
            ? "info"
            : "safe";

    // 3. Registrable Domain (Main Domain stem)
    const rawReg = components.registrable_domain || components.host || "";
    const tldVal = components.tld ? components.tld.replace(/^\./, "") : "";
    // If reg_domain ends with .tld, strip tld for visual token strip
    let domainStem = rawReg;
    if (tldVal && rawReg.toLowerCase().endsWith("." + tldVal.toLowerCase())) {
      domainStem = rawReg.slice(0, -(tldVal.length + 1));
    }
    const domainFindings = findingsFor("registrable_domain");
    const domainSeverity: "safe" | "info" | "warning" | "danger" =
      domainFindings.some((f) => f.severity === "high")
        ? "danger"
        : domainFindings.some((f) => f.severity === "medium")
          ? "warning"
          : domainFindings.some((f) => f.severity === "low")
            ? "info"
            : "safe";

    // 4. TLD
    const formattedTld = tldVal ? `.${tldVal}` : "";
    const tldFindings = findingsFor("tld");
    const tldSeverity: "safe" | "info" | "warning" | "danger" =
      tldFindings.some((f) => f.severity === "high")
        ? "danger"
        : tldFindings.some((f) => f.severity === "medium")
          ? "warning"
          : tldFindings.some((f) => f.severity === "low")
            ? "info"
            : "safe";

    // 5. Port
    const portVal = components.port !== null && components.port !== undefined ? `:${components.port}` : "";
    const portFindings = findingsFor("port");
    const portSeverity: "safe" | "info" | "warning" | "danger" =
      portFindings.some((f) => f.severity === "high")
        ? "danger"
        : portFindings.some((f) => f.severity === "medium")
          ? "warning"
          : "safe";

    // 6. Path
    const rawPath = components.path || "";
    const pathVal = rawPath && rawPath !== "/" ? rawPath : rawPath === "/" ? "/" : "";
    const pathFindings = findingsFor("path");
    const pathSeverity: "safe" | "info" | "warning" | "danger" =
      pathFindings.some((f) => f.severity === "high")
        ? "danger"
        : pathFindings.some((f) => f.severity === "medium")
          ? "warning"
          : pathFindings.some((f) => f.severity === "low")
            ? "info"
            : "safe";

    // 7. Query
    // The backend does not send the raw query string. It sends the parameter names/count and
    // `offsets.query` (start/end indexes of the text after "?" within the submitted URL), so the
    // raw text is read from the submitted URL using those exact offsets.
    const queryOffsets = offsets["query"] ?? null;
    const queryParamNames = components.query_parameter_names ?? [];
    const queryParamCount = components.query_parameter_count ?? queryParamNames.length;
    const submittedUrl = intelligence.input ?? "";
    const queryRaw = queryOffsets ? submittedUrl.slice(queryOffsets[0], queryOffsets[1]) : "";
    const queryPresent = queryRaw.length > 0 || queryParamCount > 0;
    // Without offsets (should not happen for a valid URL) fall back to the reported names only.
    const queryVal = queryRaw
      ? `?${queryRaw}`
      : queryParamNames.length > 0
        ? `?${queryParamNames.join("&")}`
        : "";
    const queryFindings = findingsFor("query");
    const querySeverity: "safe" | "info" | "warning" | "danger" =
      queryFindings.some((f) => f.severity === "high")
        ? "danger"
        : queryFindings.some((f) => f.severity === "medium")
          ? "warning"
          : queryFindings.some((f) => f.severity === "low")
            ? "info"
            : "safe";

    return [
      {
        id: "scheme",
        name: "Scheme (Protocol)",
        shortLabel: "Scheme",
        tokenText: schemeVal,
        rawText: components.scheme || "",
        displayValue: schemeVal || "None (Defaulted to HTTP)",
        present: Boolean(components.scheme),
        severity: schemeSeverity,
        findings: schemeFindings,
        offsets: offsets["scheme"] || null,
        roleDescription: COMPONENT_ROLES.scheme,
        cleanExplanation: COMPONENT_CLEAN_EXPLANATIONS.scheme,
      },
      {
        id: "subdomain",
        name: "Subdomain",
        shortLabel: "Subdomain",
        tokenText: subVal ? `${subVal}.` : "",
        rawText: subVal,
        displayValue: subVal || "None (Apex Domain)",
        present: Boolean(subVal),
        severity: subSeverity,
        findings: subFindings,
        offsets: offsets["subdomain"] || null,
        roleDescription: COMPONENT_ROLES.subdomain,
        cleanExplanation: COMPONENT_CLEAN_EXPLANATIONS.subdomain,
      },
      {
        id: "registrable_domain",
        name: components.is_ip_address ? "IP Host Address" : "Website Address (Domain)",
        shortLabel: "Domain",
        tokenText: domainStem,
        rawText: rawReg,
        displayValue: rawReg || "None",
        present: Boolean(rawReg),
        severity: domainSeverity,
        findings: domainFindings,
        offsets: offsets["registrable_domain"] || null,
        roleDescription: COMPONENT_ROLES.registrable_domain,
        cleanExplanation: COMPONENT_CLEAN_EXPLANATIONS.registrable_domain,
      },
      {
        id: "tld",
        name: "Domain Extension (TLD)",
        shortLabel: "TLD",
        tokenText: formattedTld,
        rawText: tldVal,
        displayValue: formattedTld || (components.is_ip_address ? "N/A (Raw IP)" : "None"),
        present: Boolean(tldVal),
        severity: tldSeverity,
        findings: tldFindings,
        offsets: offsets["tld"] || null,
        roleDescription: COMPONENT_ROLES.tld,
        cleanExplanation: COMPONENT_CLEAN_EXPLANATIONS.tld,
      },
      {
        id: "port",
        name: "Network Port",
        shortLabel: "Port",
        tokenText: portVal,
        rawText: components.port !== null && components.port !== undefined ? String(components.port) : "",
        displayValue: portVal || "Default (80 / 443)",
        present: components.port !== null && components.port !== undefined,
        severity: portSeverity,
        findings: portFindings,
        offsets: offsets["port"] || null,
        roleDescription: COMPONENT_ROLES.port,
        cleanExplanation: COMPONENT_CLEAN_EXPLANATIONS.port,
      },
      {
        id: "path",
        name: "Resource Path",
        shortLabel: "Path",
        tokenText: pathVal,
        rawText: rawPath,
        displayValue: pathVal || "/",
        present: Boolean(rawPath && rawPath !== "/"),
        severity: pathSeverity,
        findings: pathFindings,
        offsets: offsets["path"] || null,
        roleDescription: COMPONENT_ROLES.path,
        cleanExplanation: COMPONENT_CLEAN_EXPLANATIONS.path,
      },
      {
        id: "query",
        name: "Query Parameters",
        shortLabel: "Query",
        tokenText: queryVal,
        rawText: queryRaw,
        displayValue: queryVal || "None",
        present: queryPresent,
        severity: querySeverity,
        findings: queryFindings,
        offsets: queryOffsets,
        paramNames: queryParamNames,
        roleDescription: COMPONENT_ROLES.query,
        cleanExplanation: COMPONENT_CLEAN_EXPLANATIONS.query,
      },
    ];
  })();

  // Prioritize default selection: highest risk segment first, otherwise domain
  const defaultSelectedId = (() => {
    const dangerSeg = segments.find((s) => s.severity === "danger" && s.present);
    if (dangerSeg) return dangerSeg.id;
    const warningSeg = segments.find((s) => s.severity === "warning" && s.present);
    if (warningSeg) return warningSeg.id;
    const domainSeg = segments.find((s) => s.id === "registrable_domain" && s.present);
    if (domainSeg) return domainSeg.id;
    return segments[0]?.id || "registrable_domain";
  })();

  const [selectedId, setSelectedId] = useState<UrlComponentId>(defaultSelectedId);

  const selectedSegment = segments.find((s) => s.id === selectedId) ?? segments[0];

  if (!components || !selectedSegment) {
    return (
      <div className="rounded-xl border border-border bg-card p-4 text-xs text-muted-foreground">
        URL components unavailable for this input.
      </div>
    );
  }

  const flaggedCount = segments.filter((s) => s.findings.length > 0).length;
  const tokensToRender = segments.filter((s) => s.present && s.tokenText.length > 0);

  const handleCopy = (text: string, id: string) => {
    if (!navigator?.clipboard) return;
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const SelectedIcon = COMPONENT_ICONS[selectedSegment.id] || Globe2;

  return (
    <motion.div
      initial={shouldReduceMotion ? false : { opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: shouldReduceMotion ? 0 : 0.25 }}
      className="space-y-4 rounded-xl border border-primary/25 bg-card p-4 shadow-panel sm:p-5 dark:border-cyan-500/25 dark:bg-slate-950/70"
    >
      {/* 1. Header with Status Badge */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border pb-3.5 dark:border-slate-800">
        <div className="flex items-center gap-2.5">
          <div className="grid size-9 place-items-center rounded-lg bg-primary/10 text-primary dark:bg-cyan-500/10 dark:text-cyan-400">
            <Layers className="size-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h4 className="text-sm font-bold text-foreground">URL Anatomy Inspector</h4>
              <span className="rounded bg-primary/10 px-1.5 py-0.5 text-[10px] font-semibold text-primary dark:bg-cyan-500/15 dark:text-cyan-300">
                Phase 2A Interactive
              </span>
            </div>
            <p className="text-[11px] text-muted-foreground">
              Select any segment below to inspect exact offsets, component roles, and heuristic evidence.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {flaggedCount > 0 ? (
            <span className="inline-flex items-center gap-1.5 rounded-full border border-danger/40 bg-danger/10 px-2.5 py-1 text-xs font-semibold text-danger">
              <ShieldAlert className="size-3.5" />
              {flaggedCount} Segment{flaggedCount > 1 ? "s" : ""} Flagged
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 rounded-full border border-safe/40 bg-safe/10 px-2.5 py-1 text-xs font-semibold text-safe">
              <ShieldCheck className="size-3.5" />
              All Segments Clean
            </span>
          )}
        </div>
      </div>

      {/* 2. Interactive Segmented URL Bar */}
      <div className="space-y-2">
        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span className="flex items-center gap-1.5 font-medium text-foreground">
            <Search className="size-3.5 text-primary dark:text-cyan-400" />
            Interactive Segmented URL
          </span>
          <span className="text-[11px]">Click a token to inspect</span>
        </div>

        <div className="overflow-x-auto rounded-lg border border-border bg-slate-950/80 p-3 shadow-inner dark:bg-slate-950">
          <div className="flex flex-wrap items-center gap-1.5 font-mono text-xs sm:text-sm">
            {tokensToRender.map((seg) => {
              const isSelected = selectedSegment.id === seg.id;
              const hasFindings = seg.findings.length > 0;

              return (
                <button
                  key={seg.id}
                  type="button"
                  onClick={() => setSelectedId(seg.id)}
                  title={`Inspect ${seg.name}: ${seg.tokenText}`}
                  className={cn(
                    "group relative flex items-center rounded-md border px-2.5 py-1.5 font-mono text-xs transition-all duration-150 focus:outline-none",
                    isSelected
                      ? "ring-2 ring-primary ring-offset-2 ring-offset-background dark:ring-cyan-400"
                      : "hover:scale-[1.02]",
                    seg.severity === "danger"
                      ? "border-rose-500/50 bg-rose-500/15 text-rose-300 dark:border-rose-500/60 dark:bg-rose-950/50 hover:bg-rose-500/25"
                      : seg.severity === "warning"
                        ? "border-amber-500/50 bg-amber-500/15 text-amber-300 dark:border-amber-500/60 dark:bg-amber-950/50 hover:bg-amber-500/25"
                        : seg.severity === "info"
                          ? "border-sky-500/40 bg-sky-500/10 text-sky-300 dark:border-sky-500/50 dark:bg-sky-950/40 hover:bg-sky-500/20"
                          : seg.id === "scheme" && components.scheme === "https"
                            ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300 dark:border-emerald-500/50 dark:bg-emerald-950/40 hover:bg-emerald-500/20"
                            : "border-border bg-secondary/40 text-foreground hover:bg-secondary/70"
                  )}
                >
                  <span className="truncate max-w-[260px] sm:max-w-none font-semibold">{seg.tokenText}</span>
                  {hasFindings && (
                    <span
                      className={cn(
                        "ml-1.5 size-1.5 rounded-full shrink-0",
                        seg.severity === "danger"
                          ? "bg-rose-400 animate-pulse"
                          : "bg-amber-400"
                      )}
                    />
                  )}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* 3. Selected Component Inspector Card */}
      <AnimatePresence mode="wait">
        <motion.div
          key={selectedSegment.id}
          initial={shouldReduceMotion ? false : { opacity: 0, y: 4 }}
          animate={{ opacity: 1, y: 0 }}
          {...(shouldReduceMotion ? {} : { exit: { opacity: 0, y: -4 } })}
          transition={{ duration: 0.15 }}
          className={cn(
            "rounded-xl border p-4 sm:p-5 space-y-3.5 transition-colors",
            selectedSegment.severity === "danger"
              ? "border-rose-500/40 bg-rose-500/5 shadow-[0_0_20px_-8px_rgba(244,63,94,0.2)]"
              : selectedSegment.severity === "warning"
                ? "border-amber-500/40 bg-amber-500/5 shadow-[0_0_20px_-8px_rgba(245,158,11,0.2)]"
                : "border-safe/30 bg-safe/5"
          )}
        >
          {/* Header row */}
          <div className="flex flex-wrap items-center justify-between gap-2.5">
            <div className="flex items-center gap-2">
              <div
                className={cn(
                  "grid size-8 place-items-center rounded-lg border",
                  selectedSegment.severity === "danger"
                    ? "border-rose-500/40 bg-rose-500/15 text-rose-400"
                    : selectedSegment.severity === "warning"
                      ? "border-amber-500/40 bg-amber-500/15 text-amber-400"
                      : "border-safe/40 bg-safe/15 text-safe"
                )}
              >
                <SelectedIcon className="size-4" />
              </div>
              <div>
                <h5 className="text-xs font-bold uppercase tracking-wider text-foreground">
                  {selectedSegment.name}
                </h5>
                <span className="text-[11px] text-muted-foreground">
                  {selectedSegment.present ? "Present in submitted URL" : "Not specified (Defaulted)"}
                </span>
              </div>
            </div>

            <div className="flex items-center gap-2">
              {selectedSegment.offsets && (
                <span className="rounded border border-border bg-secondary/40 px-2 py-0.5 font-mono text-[10px] text-muted-foreground">
                  Chars {selectedSegment.offsets[0]} – {selectedSegment.offsets[1]}
                </span>
              )}
              <span
                className={cn(
                  "inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider",
                  selectedSegment.severity === "danger"
                    ? "border border-danger/40 bg-danger/15 text-danger"
                    : selectedSegment.severity === "warning"
                      ? "border border-warning/40 bg-warning/15 text-warning"
                      : selectedSegment.severity === "info"
                        ? "border border-sky-500/40 bg-sky-500/15 text-sky-400"
                        : "border border-safe/40 bg-safe/15 text-safe"
                )}
              >
                {selectedSegment.severity === "danger" ? (
                  <ShieldAlert className="size-3" />
                ) : selectedSegment.severity === "warning" ? (
                  <AlertTriangle className="size-3" />
                ) : (
                  <ShieldCheck className="size-3" />
                )}
                {selectedSegment.severity === "danger"
                  ? "High Risk"
                  : selectedSegment.severity === "warning"
                    ? "Warning / Suspicious"
                    : selectedSegment.severity === "info"
                      ? "Informational"
                      : "Clean & Verified"}
              </span>
            </div>
          </div>

          {/* Value Display Box with Copy Button */}
          <div className="flex items-center justify-between gap-3 rounded-lg border border-border bg-slate-950 p-2.5 font-mono text-xs sm:text-sm">
            <span className="truncate text-foreground font-semibold">
              {selectedSegment.displayValue}
            </span>
            {selectedSegment.present && (
              <button
                type="button"
                onClick={() => handleCopy(selectedSegment.rawText, selectedSegment.id)}
                className="inline-flex shrink-0 items-center gap-1 rounded border border-border bg-secondary/30 px-2 py-1 text-[11px] text-muted-foreground hover:bg-secondary/60 hover:text-foreground transition-colors"
                title="Copy segment value"
              >
                {copiedId === selectedSegment.id ? (
                  <>
                    <Check className="size-3 text-safe" />
                    <span className="text-safe font-sans">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="size-3" />
                    <span className="font-sans">Copy</span>
                  </>
                )}
              </button>
            )}
          </div>

          {/* Query parameter names (query segment only; names come from the backend response) */}
          {selectedSegment.paramNames && selectedSegment.paramNames.length > 0 && (
            <p className="text-xs text-muted-foreground leading-relaxed">
              <strong className="text-foreground">
                Parameters ({selectedSegment.paramNames.length}):{" "}
              </strong>
              <span className="font-mono">{selectedSegment.paramNames.join(", ")}</span>
            </p>
          )}

          {/* Educational Role Description */}
          <p className="text-xs text-muted-foreground leading-relaxed">
            <strong className="text-foreground">Architectural Role: </strong>
            {selectedSegment.roleDescription}
          </p>

          {/* Associated Findings or Clean Explanation */}
          {selectedSegment.findings.length > 0 ? (
            <div className="space-y-2 pt-1">
              <p className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                <AlertTriangle className="size-3.5 text-warning" />
                Identified Security Warnings on this Component ({selectedSegment.findings.length}):
              </p>
              <div className="space-y-2">
                {selectedSegment.findings.map((f, idx) => (
                  <div
                    key={idx}
                    className="rounded-lg border border-border bg-secondary/30 p-3 text-xs space-y-1"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-semibold text-foreground">{f.title}</span>
                      <span
                        className={cn(
                          "rounded px-1.5 py-0.5 font-mono text-[9px] font-bold uppercase",
                          f.severity === "high"
                            ? "bg-danger/20 text-danger"
                            : f.severity === "medium"
                              ? "bg-warning/20 text-warning"
                              : "bg-muted text-muted-foreground"
                        )}
                      >
                        {f.severity}
                      </span>
                    </div>
                    <p className="text-[11px] text-muted-foreground">{f.detail}</p>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="flex items-start gap-2.5 rounded-lg border border-safe/30 bg-safe/10 p-3 text-xs leading-relaxed text-muted-foreground">
              <ShieldCheck className="mt-0.5 size-4 shrink-0 text-safe" />
              <div>
                <strong className="text-foreground">Component Evaluation: </strong>
                {selectedSegment.cleanExplanation}
              </div>
            </div>
          )}

          {/* Viva Explainer Tip */}
          <div className="rounded-lg border border-primary/20 bg-primary/5 p-3 text-[11px] text-muted-foreground dark:border-cyan-500/20 dark:bg-cyan-500/5">
            <div className="flex items-center gap-1.5 font-semibold text-foreground dark:text-cyan-300">
              <Sparkles className="size-3.5 text-primary dark:text-cyan-400" />
              Examiner &amp; Analyst Viva Context
            </div>
            <p className="mt-1 leading-relaxed">
              {COMPONENT_VIVA_TIPS[selectedSegment.id]}
            </p>
          </div>
        </motion.div>
      </AnimatePresence>

      {/* 4. Full Component Breakdown Grid */}
      <div className="space-y-2 pt-1">
        <div className="flex items-center justify-between text-xs font-semibold text-foreground">
          <span>Component Breakdown (All 7 Architectural Elements)</span>
          <span className="text-[10px] font-normal text-muted-foreground">
            Tap any row to inspect above
          </span>
        </div>

        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {segments.map((seg) => {
            const Icon = COMPONENT_ICONS[seg.id] || Globe2;
            const isSelected = selectedSegment.id === seg.id;
            const isFlagged = seg.findings.length > 0;

            return (
              <button
                key={seg.id}
                type="button"
                onClick={() => setSelectedId(seg.id)}
                className={cn(
                  "flex flex-col justify-between rounded-lg border p-3 text-left transition-all duration-150 focus:outline-none",
                  isSelected
                    ? "border-primary bg-secondary/40 ring-1 ring-primary dark:border-cyan-400 dark:ring-cyan-400"
                    : "border-border bg-secondary/20 hover:bg-secondary/35",
                  isFlagged
                    ? seg.severity === "danger"
                      ? "border-danger/40 hover:border-danger/60"
                      : "border-warning/40 hover:border-warning/60"
                    : ""
                )}
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5 text-xs font-semibold text-foreground">
                    <Icon className="size-3.5 text-primary dark:text-cyan-400" />
                    <span>{seg.shortLabel}</span>
                  </div>
                  <span
                    className={cn(
                      "rounded px-1.5 py-0.5 font-mono text-[9px] font-bold uppercase",
                      seg.severity === "danger"
                        ? "bg-danger/15 text-danger border border-danger/30"
                        : seg.severity === "warning"
                          ? "bg-warning/15 text-warning border border-warning/30"
                          : seg.severity === "info"
                            ? "bg-sky-500/15 text-sky-400 border border-sky-500/30"
                            : "bg-safe/15 text-safe border border-safe/30"
                    )}
                  >
                    {seg.severity === "danger"
                      ? "Danger"
                      : seg.severity === "warning"
                        ? "Warning"
                        : "Clean"}
                  </span>
                </div>

                <div className="mt-2 font-mono text-xs truncate text-foreground">
                  {seg.displayValue}
                </div>

                <div className="mt-2 flex items-center justify-between text-[10px] text-muted-foreground border-t border-border/50 pt-1.5">
                  <span>
                    {isFlagged ? `${seg.findings.length} warning(s)` : "No anomalies"}
                  </span>
                  <span className="flex items-center gap-0.5 text-primary dark:text-cyan-400 font-semibold">
                    Inspect <ChevronRight className="size-2.5" />
                  </span>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* 5. Zero-network offline guarantee footer */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border pt-3 text-[11px] text-muted-foreground dark:border-slate-800">
        <span className="flex items-center gap-1.5">
          <Lock className="size-3 text-safe" />
          Zero network calls • 100% client &amp; static algorithmic evaluation
        </span>
        <span className="font-mono text-[10px]">
          {components.offsets ? "Offset Bounds Verified [0..N]" : "Lexical Decomposition"}
        </span>
      </div>
    </motion.div>
  );
}
