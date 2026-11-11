import * as React from "react";
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Eye,
  Globe,
  Info,
  Link2,
  Loader2,
  Network,
  ShieldAlert,
} from "lucide-react";
import { scamlensApi } from "@/lib/scamlens-api";
import type { AdvancedUrlResolutionResult, AdvancedUrlWarning, AnalysisResult } from "@/lib/scamlens-types";
import { Badge, Button, Card, cn } from "./ui";

const KNOWN_SHORTENERS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "is.gd",
  "buff.ly",
  "rebrand.ly",
  "cutt.ly",
  "shorturl.at",
  "rb.gy",
  "tiny.cc",
  "lnkd.in",
  "s.id",
  "v.gd",
]);

const PROTECTED_BRANDS: Record<string, string[]> = {
  paypal: ["paypal.com"],
  google: ["google.com", "google.co.in"],
  microsoft: ["microsoft.com", "live.com", "office.com"],
  apple: ["apple.com", "icloud.com"],
  amazon: ["amazon.com", "amazon.in"],
  netflix: ["netflix.com"],
  sbi: ["onlinesbi.sbi", "sbi.co.in"],
  hdfcbank: ["hdfcbank.com"],
  icicibank: ["icicibank.com"],
  axisbank: ["axisbank.com"],
  paytm: ["paytm.com"],
  phonepe: ["phonepe.com"],
};

/**
 * Immediate client-side lookalike, character-substitution, punycode, and shortener check
 * so plain-language warnings are visible immediately even before or during redirect tracing.
 */
export function computeClientSideAdvancedUrlWarnings(rawUrl: string): {
  isShortened: boolean;
  warnings: AdvancedUrlWarning[];
} {
  const warnings: AdvancedUrlWarning[] = [];
  let isShortened = false;

  const trimmed = rawUrl.trim();
  const normalized = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed) ? trimmed : `http://${trimmed}`;

  try {
    const parsed = new URL(normalized);
    const host = parsed.hostname.toLowerCase();

    if (KNOWN_SHORTENERS.has(host)) {
      isShortened = true;
      warnings.push({
        code: "URL_SHORTENER_DETECTED",
        severity: "medium",
        title: "Shortened Link Hides True Destination",
        plain_explanation: `This link uses the URL shortener '${host}', which conceals the actual website you will land on until you click or trace it.`,
      });
    }

    if (host.includes("xn--")) {
      warnings.push({
        code: "PUNYCODE_IDN_HOMOGRAPH",
        severity: "high",
        title: "Punycode / Internationalized Lookalike Domain (xn--)",
        plain_explanation: `The domain '${host}' uses Punycode ('xn--') to render non-Latin characters that visually mimic familiar letters—a classic homograph phishing technique.`,
      });
    }

    const parts = host.split(".");
    const mainLabel = parts.length >= 2 ? (parts[parts.length - 2] ?? host) : host;
    const deLeeted = mainLabel
      .replace(/0/g, "o")
      .replace(/1/g, "l")
      .replace(/3/g, "e")
      .replace(/4/g, "a")
      .replace(/5/g, "s")
      .replace(/rn/g, "m")
      .replace(/vv/g, "w");
    const deLeetedAltI = mainLabel
      .replace(/0/g, "o")
      .replace(/1/g, "i")
      .replace(/rn/g, "m")
      .replace(/vv/g, "w");

    for (const [brand, officialList] of Object.entries(PROTECTED_BRANDS)) {
      const isOfficial = officialList.some((off) => host === off || host.endsWith(`.${off}`));
      if (isOfficial) continue;

      if (
        mainLabel !== brand &&
        (deLeeted.includes(brand) || deLeetedAltI.includes(brand)) &&
        !mainLabel.includes(brand)
      ) {
        const subs: string[] = [];
        if (mainLabel.includes("0")) subs.push("'0' instead of 'o'");
        if (mainLabel.includes("1")) subs.push("'1' instead of 'l' or 'i'");
        if (mainLabel.includes("rn")) subs.push("'rn' instead of 'm'");
        if (mainLabel.includes("vv")) subs.push("'vv' instead of 'w'");

        warnings.push({
          code: "CHARACTER_SUBSTITUTION_SPOOF",
          severity: "high",
          title: `Lookalike Character Substitution Impersonating ${brand.toUpperCase()}`,
          plain_explanation: `The domain '${host}' uses visual character substitution (${subs.join(", ") || "lookalike characters"}) to impersonate ${brand.toUpperCase()} (official domain: ${officialList[0] ?? brand}).`,
          matched_brand: brand,
          official_domains: officialList,
        });
      }
    }
  } catch {
    // Ignore malformed URLs here; handled by primary validator
  }

  return { isShortened, warnings };
}

export function AdvancedLinkCheckerCard({
  analyzedUrl,
  result,
}: {
  analyzedUrl: string;
  result: AnalysisResult;
}) {
  const [resolutionData, setResolutionData] = React.useState<AdvancedUrlResolutionResult | null>(null);
  const [resolving, setResolving] = React.useState<boolean>(false);
  const [resolveError, setResolveError] = React.useState<string | null>(null);

  const clientCheck = React.useMemo(
    () => computeClientSideAdvancedUrlWarnings(analyzedUrl),
    [analyzedUrl]
  );

  const runSafeResolution = React.useCallback(
    async (urlToInspect: string) => {
      if (!urlToInspect.trim()) return;
      setResolving(true);
      setResolveError(null);
      try {
        const res = await scamlensApi.resolveUrlAdvanced(urlToInspect.trim(), true);
        setResolutionData(res);
      } catch (err) {
        setResolveError(
          err instanceof Error
            ? err.message
            : "Could not complete backend redirect resolution. Static link warnings are shown below."
        );
      } finally {
        setResolving(false);
      }
    },
    []
  );

  // Automatically run safe resolution when a new URL is analyzed
  React.useEffect(() => {
    if (analyzedUrl.trim()) {
      void runSafeResolution(analyzedUrl);
    }
  }, [analyzedUrl, runSafeResolution]);

  // Merge backend and client-side warnings without duplicates
  const combinedWarnings = React.useMemo(() => {
    const map = new Map<string, AdvancedUrlWarning>();
    for (const w of clientCheck.warnings) {
      map.set(`${w.code}:${w.title}`, w);
    }
    if (resolutionData?.advanced_warnings) {
      for (const w of resolutionData.advanced_warnings) {
        map.set(`${w.code}:${w.title}`, w);
      }
    }
    return Array.from(map.values());
  }, [clientCheck.warnings, resolutionData]);

  const isShortened =
    Boolean(resolutionData?.is_shortened) ||
    clientCheck.isShortened ||
    Boolean(result.urlIntelligence?.metrics?.is_shortener);

  return (
    <Card
      className="p-5 space-y-4 border-cyan-500/25 bg-slate-900/80"
      data-testid="advanced-link-checker-card"
    >
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3.5">
        <div className="flex items-start gap-2.5">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-cyan-500/35 bg-cyan-500/10 text-cyan-300">
            <Network className="h-4 w-4" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="text-sm font-bold text-white">
                Advanced Link Checker — Homograph, Substitution & Redirect Inspector
              </h3>
              {isShortened && <Badge tone="warning">Shortened URL Detected</Badge>}
              <Badge tone="info">SSRF-Protected Resolution</Badge>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Detects lookalike character substitutions (0→o, 1→l, rn→m), Punycode homographs, and safely inspects redirect chains without executing page scripts.
            </p>
          </div>
        </div>

        <Button
          type="button"
          variant="secondary"
          size="sm"
          data-testid="retrace-url-btn"
          disabled={resolving}
          onClick={() => void runSafeResolution(analyzedUrl)}
        >
          {resolving ? (
            <>
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              <span>Tracing Redirects...</span>
            </>
          ) : (
            <>
              <Eye className="h-3.5 w-3.5" />
              <span>Re-Verify Destination</span>
            </>
          )}
        </Button>
      </div>

      {/* Original URL vs Final Resolved URL Comparison */}
      <div className="grid gap-3 md:grid-cols-2" data-testid="url-origin-destination-grid">
        <div className="rounded-xl border border-slate-800 bg-slate-950/75 p-3.5 space-y-1">
          <div className="flex items-center justify-between text-[11px] font-mono uppercase tracking-wider text-slate-400">
            <span>1. Original Submitted URL</span>
            {isShortened && <span className="text-amber-300">Shortener</span>}
          </div>
          <p
            className="text-xs font-mono text-slate-200 break-all"
            data-testid="advanced-original-url"
          >
            {resolutionData?.original_url || analyzedUrl}
          </p>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-950/75 p-3.5 space-y-1">
          <div className="flex items-center justify-between text-[11px] font-mono uppercase tracking-wider text-slate-400">
            <span>2. Final Resolved Destination</span>
            {resolving ? (
              <span className="text-cyan-300">Resolving...</span>
            ) : resolutionData?.destination_verified ? (
              <span className="text-emerald-400">Destination Verified</span>
            ) : (
              <span className="text-amber-300">Unverified / Static Only</span>
            )}
          </div>
          {resolving ? (
            <div className="flex items-center gap-2 text-xs text-slate-400 py-1">
              <Loader2 className="h-3.5 w-3.5 animate-spin text-cyan-400" />
              <span>Tracing HTTP/HTTPS redirect headers with SSRF protection...</span>
            </div>
          ) : resolutionData?.final_resolved_url ? (
            <p
              className="text-xs font-mono text-cyan-300 break-all"
              data-testid="advanced-final-resolved-url"
            >
              {resolutionData.final_resolved_url}
            </p>
          ) : (
            <p
              className="text-xs text-amber-200/90 leading-relaxed"
              data-testid="advanced-unverified-destination-note"
            >
              {resolutionData?.resolution_note ||
                resolveError ||
                "Final destination could not be verified online (domain is unreachable, offline, or blocked by SSRF safety policy). Static URL analysis is shown."}
            </p>
          )}
        </div>
      </div>

      {/* Redirect Hops Chain (if any hops occurred) */}
      {resolutionData && resolutionData.redirect_hops.length > 0 && (
        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3.5 space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="font-mono uppercase tracking-wider text-slate-400">
              Redirect Chain ({resolutionData.redirect_count} Redirect Hop{resolutionData.redirect_count === 1 ? "" : "s"})
            </span>
            <span className="text-[11px] text-slate-400">{resolutionData.resolution_note}</span>
          </div>
          <div className="space-y-1.5">
            {resolutionData.redirect_hops.map((hop) => (
              <div
                key={hop.hop}
                className="flex flex-wrap items-center gap-2 rounded-lg border border-slate-800/80 bg-slate-900/60 px-3 py-1.5 text-xs font-mono"
              >
                <Badge tone="neutral">Hop #{hop.hop}</Badge>
                <span className="text-slate-200 break-all">{hop.url}</span>
                {hop.status_code && (
                  <span className="text-cyan-400 text-[11px]">[HTTP {hop.status_code}]</span>
                )}
                {hop.location && (
                  <>
                    <ArrowRight className="h-3.5 w-3.5 text-amber-400 shrink-0" />
                    <span className="text-amber-300 break-all">{hop.location}</span>
                  </>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Plain-Language Lookalike, Character-Substitution & Homograph Warnings */}
      <div className="space-y-2.5" data-testid="advanced-link-warnings-list">
        <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
          Plain-Language Domain & Link Warnings
        </span>

        {combinedWarnings.length > 0 ? (
          <div className="grid gap-2.5">
            {combinedWarnings.map((w, idx) => (
              <div
                key={`${w.code}-${idx}`}
                data-testid={`advanced-url-warning-${w.code}`}
                className={cn(
                  "rounded-xl border p-3.5 space-y-1",
                  w.severity === "high"
                    ? "border-rose-500/35 bg-rose-950/20 text-rose-100"
                    : "border-amber-500/35 bg-amber-950/20 text-amber-100"
                )}
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2 font-semibold text-xs">
                    <ShieldAlert
                      className={cn(
                        "h-4 w-4 shrink-0",
                        w.severity === "high" ? "text-rose-400" : "text-amber-400"
                      )}
                    />
                    <span>{w.title}</span>
                  </div>
                  <Badge tone={w.severity === "high" ? "danger" : "warning"}>
                    {w.severity.toUpperCase()} RISK
                  </Badge>
                </div>
                <p className="text-xs text-slate-200 leading-relaxed pl-6">{w.plain_explanation}</p>
              </div>
            ))}
          </div>
        ) : (
          <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3.5 flex items-start gap-2.5 text-xs text-slate-300">
            <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
            <span>
              No character-substitution lookalikes (e.g. 0→o, 1→l, rn→m), Punycode homographs, or URL shorteners were detected in this link&apos;s hostname.
            </span>
          </div>
        )}
      </div>

      {/* Mandatory Safety Disclaimer: Never claim a URL is safe just because no warning was detected */}
      <div
        className="flex items-start gap-2.5 rounded-xl border border-amber-500/25 bg-amber-950/15 px-3.5 py-2.5 text-[11px] text-amber-200/90 leading-relaxed"
        data-testid="url-non-guarantee-disclaimer"
      >
        <Info className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
        <span>
          <strong>Safety Notice:</strong>{" "}
          {resolutionData?.safety_disclaimer ||
            "The absence of structural or redirect warnings does NOT guarantee that a website is safe or trustworthy. Newly registered phishing pages or compromised legitimate sites may show zero lexical warnings—never enter passwords, OTPs, or financial details on unfamiliar links."}
        </span>
      </div>
    </Card>
  );
}
