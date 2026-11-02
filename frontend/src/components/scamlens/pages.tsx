import { ApiDiagnosticsPanel } from "./api-diagnostics";
export { LearnPractisePage } from "./learn-practise-page";
export { SettingsInformationPage, type SettingsInfoTab } from "./settings-info-page";
export { SecurityAlertCenterView } from "./alert-center";
export { EmailAnalyzerSection } from "./email-analyzer";
export { ExplainabilityCard, LanguageTransparencyCard } from "./explainable-ai";
export { UrlIntelligenceCard } from "./url-intelligence";
import { ExplainabilityCard, LanguageTransparencyCard } from "./explainable-ai";
import { UrlIntelligenceCard } from "./url-intelligence";
import { EmailAnalyzerSection } from "./email-analyzer";
import { SecurityAlertCenterView } from "./alert-center";
import { Fragment, useMemo, useRef, useState, type ChangeEvent, type DragEvent } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { AnimatePresence, motion } from "motion/react";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  ArrowUpDown,
  BarChart3,
  BrainCircuit,
  Calendar,
  CheckCircle2,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ChevronUp,
  CircleGauge,
  Clock3,
  Cpu,
  Database,
  Download,
  FileCheck2,
  FileSearch,
  FileSpreadsheet,
  FileText,
  Filter,
  History,
  Layers,
  Link2,
  ListChecks,
  Loader2,
  LockKeyhole,
  Mail,
  MessageSquareText,
  Network,
  Radar,
  RefreshCw,
  ScanText,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
  Upload,
  XCircle,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ApiNotice, ChartEmpty, EmptyState, KpiCard, PageHeader, Panel } from "./primitives";
import { ScamlensApiError, scamlensApi } from "@/lib/scamlens-api";
import { useScamlensPreferences } from "@/lib/scamlens-preferences";
import { healthQueryOptions, historyQueryOptions, modelInfoQueryOptions } from "@/lib/scamlens-queries";
import type { AnalysisResult, BatchAnalysisResponse, ScanRecord } from "@/lib/scamlens-types";
import { cn } from "@/lib/utils";

const messageExamples = {
  "Normal Team Message": "Hi team, the project review meeting has been moved to 3:00 PM in Room 204. Please bring your progress notes.",
  "Prize / Lottery Scam": "Congratulations! You have won a ₹50,000 cash reward in our lucky draw. Claim immediately at http://prize-claim-verify.example/win before midnight!",
  "Urgent Bank / KYC Alert": "URGENT: Your bank account will be suspended within 24 hours due to incomplete KYC. Update your PAN and OTP now to avoid account freeze.",
  "Delivery Phishing SMS": "Your parcel #IND88392 is on hold due to an incomplete address. Confirm delivery fee at http://speedpost-track-update.example/pay",
} as const;

const urlExamples = {
  "Safe HTTPS Documentation URL": "https://docs.python.org/3/library/urllib.parse.html",
  "Suspicious Login Lure (HTTP)": "http://secure-login-account-verify-update.example/signin/confirm?user=admin",
  "IP-Based Banking Phishing URL": "http://192.168.10.45/netbanking/kyc-verification/login.php",
  "Shortened URL Example": "https://bit.ly/3xYz99ClaimReward",
} as const;

type RequestStatus = "idle" | "loading" | "error" | "success";

function apiError(error: unknown) {
  return error instanceof ScamlensApiError || error instanceof Error
    ? error.message
    : "The backend could not complete this request.";
}

function formatProbability(value: number) {
  return `${value.toLocaleString(undefined, { minimumFractionDigits: 1, maximumFractionDigits: 2 })}%`;
}

function formatTime(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function formatShortDate(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value.slice(0, 10);
  return date.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function formatFileSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function toneForRisk(risk: AnalysisResult["riskLevel"] | string) {
  return risk === "Low"
    ? "text-safe"
    : risk === "Suspicious"
      ? "text-warning"
      : "text-danger";
}

function badgeClassForRisk(risk: AnalysisResult["riskLevel"] | string) {
  if (risk === "Low") return "border-safe/35 bg-safe/10 text-safe";
  if (risk === "Suspicious") return "border-warning/35 bg-warning/10 text-warning";
  if (risk === "High") return "border-orange-500/40 bg-orange-500/15 text-orange-600 dark:text-orange-400";
  return "border-danger/40 bg-danger/15 text-danger";
}

function badgeClassForPrediction(prediction: AnalysisResult["prediction"] | string) {
  return prediction === "Scam/Phishing"
    ? "border-danger/40 bg-danger/15 text-danger"
    : "border-safe/35 bg-safe/10 text-safe";
}

function csvCell(value: string | number | undefined) {
  const text = String(value ?? "");
  return `"${text.replaceAll('"', '""')}"`;
}

function AnalysisResultView({ result }: { result: AnalysisResult }) {
  const { shouldReduceMotion } = useScamlensPreferences();
  const isScam = result.prediction === "Scam/Phishing";
  const pct = Math.min(100, Math.max(0, result.riskProbability));

  return (
    <motion.div
      initial={shouldReduceMotion ? false : { opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: shouldReduceMotion ? 0 : 0.25 }}
      className="space-y-5"
    >
      <ApiNotice kind="success" message={`Live inference completed by ${result.model}.`} />

      {/* Top Verdict Banner with Animated Risk Meter */}
      <div
        className={cn(
          "rounded-xl border p-4 sm:p-5",
          isScam
            ? "border-danger/45 bg-gradient-to-br from-danger/15 via-card to-card"
            : "border-safe/40 bg-gradient-to-br from-safe/12 via-card to-card"
        )}
      >
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div
              className={cn(
                "grid size-11 shrink-0 place-items-center rounded-xl border",
                isScam ? "border-danger/40 bg-danger/20 text-danger" : "border-safe/40 bg-safe/20 text-safe"
              )}
            >
              {isScam ? <ShieldAlert className="size-6" /> : <ShieldCheck className="size-6" />}
            </div>
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                Classification Verdict
              </p>
              <h3 className={cn("text-lg font-bold", isScam ? "text-danger" : "text-safe")}>
                {result.prediction}
              </h3>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <span className={cn("rounded-full border px-3 py-1 text-xs font-semibold", badgeClassForRisk(result.riskLevel))}>
              {result.riskLevel} Risk
            </span>
            <span className="rounded-full border border-border bg-secondary px-3 py-1 font-mono text-xs font-bold text-foreground">
              {formatProbability(pct)}
            </span>
          </div>
        </div>

        {/* Visual Risk Score Bar */}
        <div className="mt-4">
          <div className="mb-1.5 flex items-center justify-between text-xs">
            <span className="text-muted-foreground">Scam / Phishing Probability Meter</span>
            <span className="font-mono font-semibold text-foreground">{formatProbability(pct)}</span>
          </div>
          <div className="h-2.5 w-full overflow-hidden rounded-full bg-secondary">
            <motion.div
              initial={shouldReduceMotion ? false : { width: 0 }}
              animate={{ width: `${pct}%` }}
              transition={{ duration: shouldReduceMotion ? 0 : 0.6, ease: "easeOut" }}
              className={cn(
                "h-full rounded-full",
                result.riskLevel === "Low"
                  ? "bg-safe"
                  : result.riskLevel === "Suspicious"
                    ? "bg-warning"
                    : "bg-danger"
              )}
            />
          </div>
        </div>
      </div>

      {/* Metadata Grid */}
      <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2 md:grid-cols-3 sm:gap-3">
        <div className="rounded-lg border border-border bg-secondary/30 p-3 sm:p-3.5">
          <p className="text-[11px] text-muted-foreground">Prediction</p>
          <p className="mt-1 text-sm font-semibold text-foreground">{result.prediction}</p>
        </div>
        <div className="rounded-lg border border-border bg-secondary/30 p-3 sm:p-3.5">
          <p className="text-[11px] text-muted-foreground">Risk Probability</p>
          <p className="mt-1 font-mono text-sm font-semibold text-foreground">{formatProbability(result.riskProbability)}</p>
        </div>
        <div className="rounded-lg border border-border bg-secondary/30 p-3 sm:p-3.5">
          <p className="text-[11px] text-muted-foreground">Risk Level</p>
          <p className={cn("mt-1 text-sm font-semibold", toneForRisk(result.riskLevel))}>{result.riskLevel}</p>
        </div>
        <div className="rounded-lg border border-border bg-secondary/30 p-3 sm:p-3.5">
          <p className="text-[11px] text-muted-foreground">Classifier Model</p>
          <p className="mt-1 truncate text-sm font-semibold text-foreground">{result.model}</p>
        </div>
        {result.riskScore !== undefined && (
          <div className="rounded-lg border border-border bg-secondary/30 p-3 sm:p-3.5">
            <p className="text-[11px] text-muted-foreground">Risk Score (0–100)</p>
            <p className="mt-1 font-mono text-sm font-semibold text-foreground">
              {result.riskScore.toLocaleString(undefined, { maximumFractionDigits: 2 })}
            </p>
          </div>
        )}
        {result.scanId !== undefined && (
          <div className="rounded-lg border border-border bg-secondary/30 p-3 sm:p-3.5">
            <p className="text-[11px] text-muted-foreground">Audit Scan ID</p>
            <p className="mt-1 font-mono text-sm font-semibold text-primary">#{result.scanId}</p>
          </div>
        )}
        {result.timestamp && (
          <div className="rounded-lg border border-border bg-secondary/30 p-3 sm:col-span-2 md:col-span-3 sm:p-3.5">
            <p className="text-[11px] text-muted-foreground">Recorded Timestamp</p>
            <p className="mt-1 text-xs font-medium text-foreground">{formatTime(result.timestamp)}</p>
          </div>
        )}
      </div>

      {/* Detection Indicators & Security Guidance */}
      <div className="space-y-3">
        <motion.div
          initial={shouldReduceMotion ? false : { opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: shouldReduceMotion ? 0 : 0.24, delay: shouldReduceMotion ? 0 : 0.08 }}
          className="rounded-lg border border-border bg-secondary/20 p-4"
        >
          <p className="flex items-center gap-2 text-xs font-semibold text-foreground">
            <ListChecks className="size-4 text-primary" />
            Detection Indicators ({result.indicators.length})
          </p>
          {result.indicators.length ? (
            <ul className="mt-2.5 space-y-1.5 text-xs leading-5 text-muted-foreground">
              {result.indicators.map((item, idx) => (
                <motion.li
                  key={item}
                  initial={shouldReduceMotion ? false : { opacity: 0, x: -6 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{
                    duration: shouldReduceMotion ? 0 : 0.2,
                    delay: shouldReduceMotion ? 0 : 0.1 + idx * 0.04,
                  }}
                  className="flex items-start gap-2"
                >
                  <CheckCircle2 className="mt-0.5 size-3.5 shrink-0 text-primary" />
                  <span>{item}</span>
                </motion.li>
              ))}
            </ul>
          ) : (
            <p className="mt-2 text-xs text-muted-foreground">No specific risk indicators triggered.</p>
          )}
        </motion.div>

        <motion.div
          initial={shouldReduceMotion ? false : { opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: shouldReduceMotion ? 0 : 0.24, delay: shouldReduceMotion ? 0 : 0.16 }}
          className="rounded-lg border border-primary/25 bg-primary/5 p-4"
        >
          <p className="flex items-center gap-2 text-xs font-semibold text-foreground">
            <LockKeyhole className="size-4 text-primary" />
            Recommended Security Action
          </p>
          <p className="mt-1.5 text-xs leading-5 text-muted-foreground">{result.guidance}</p>
        </motion.div>
      </div>

      {/* 1. Explainable AI Token Attributions */}
      {result.explainability && (
        <div className="pt-2">
          <ExplainabilityCard explainability={result.explainability} />
        </div>
      )}

      {/* 2. Multilingual Script & Regional Dialect Indicators */}
      {result.languageInfo && (
        <div className="pt-2">
          <LanguageTransparencyCard languageInfo={result.languageInfo} />
        </div>
      )}

      {/* 3. Deep Static URL Intelligence Breakdown */}
      {result.urlIntelligence && (
        <div className="pt-2">
          <UrlIntelligenceCard intelligence={result.urlIntelligence} />
        </div>
      )}
    </motion.div>
  );
}

function HistoryStatus({ loading, error, empty }: { loading: boolean; error: Error | null; empty?: boolean }) {
  if (loading) return <ApiNotice kind="loading" message="Loading records from the Python backend." />;
  if (error) return <ApiNotice kind="error" message={apiError(error)} />;
  if (empty) return <EmptyState compact title="No scans recorded" description="The backend returned no completed scans." />;
  return null;
}

function HistoryBars({ records, mode }: { records: ScanRecord[]; mode: "risk" | "prediction" | "type" }) {
  const { shouldReduceMotion } = useScamlensPreferences();
  const total = Math.max(records.length, 1);
  const entries =
    mode === "risk"
      ? (["Low", "Suspicious", "High", "Very High"] as const).map(
          (label) =>
            [
              label,
              records.filter((r) => r.riskLevel === label).length,
              label === "Low"
                ? "bg-safe"
                : label === "Suspicious"
                  ? "bg-warning"
                  : label === "High"
                    ? "bg-orange-500"
                    : "bg-danger",
            ] as const
        )
      : mode === "prediction"
        ? (["Legitimate", "Scam/Phishing"] as const).map(
            (label) =>
              [
                label,
                records.filter((r) => r.prediction === label).length,
                label === "Legitimate" ? "bg-safe" : "bg-danger",
              ] as const
          )
        : (["message", "url"] as const).map(
            (label) =>
              [
                label === "message" ? "Messages (SMS / Email)" : "URLs / Links",
                records.filter((r) => r.inputType === label).length,
                label === "message" ? "bg-primary" : "bg-cyan-400",
              ] as const
          );

  const max = Math.max(...entries.map(([, count]) => count), 1);

  return (
    <div className="space-y-4">
      {entries.map(([label, count, barColor]) => {
        const pct = ((count / total) * 100).toFixed(1);
        return (
          <div key={label}>
            <div className="mb-1.5 flex items-center justify-between text-xs">
              <span className="font-medium text-foreground">{label}</span>
              <span className="font-mono text-muted-foreground">
                <strong className="text-foreground">{count}</strong> ({pct}%)
              </span>
            </div>
            <div className="h-2.5 overflow-hidden rounded-full bg-muted">
              <motion.div
                initial={shouldReduceMotion ? false : { width: 0 }}
                animate={{ width: `${(count / max) * 100}%` }}
                transition={{ duration: shouldReduceMotion ? 0 : 0.5, ease: "easeOut" }}
                className={cn("h-full rounded-full", barColor)}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ============================================================================
// 1. DASHBOARD PAGE (Distinct compact telemetry banner — NO duplicate phone hero)
// ============================================================================
export function DashboardPage() {
  const { shouldReduceMotion } = useScamlensPreferences();
  const health = useQuery(healthQueryOptions());
  const modelInfo = useQuery(modelInfoQueryOptions());
  const history = useQuery(historyQueryOptions());

  const connected = health.isSuccess && health.data.healthy;
  const records = history.data ?? [];
  const scam = records.filter((r) => r.prediction === "Scam/Phishing").length;
  const legitimate = records.filter((r) => r.prediction === "Legitimate").length;
  const high = records.filter((r) => r.riskLevel === "High" || r.riskLevel === "Very High").length;
  const note = history.isSuccess ? "From backend history" : history.isError ? "History unavailable" : "Awaiting backend data";
  const latestScan = records[0];

  return (
    <div className="space-y-7">
      <PageHeader
        eyebrow="Operational Command Center"
        title="Security Dashboard"
        description="Monitor live machine-learning detection activity, risk distribution, and recent message or URL inspections across your workspace."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Button asChild className="min-h-10 flex-1 transition-transform active:scale-97 sm:flex-initial">
              <Link to="/message-analyzer">
                <Sparkles className="size-4" /> Analyze Message
              </Link>
            </Button>
            <Button asChild variant="outline" className="min-h-10 flex-1 transition-transform active:scale-97 sm:flex-initial">
              <Link to="/url-analyzer">
                <Link2 className="size-4" /> Scan URL
              </Link>
            </Button>
            <span
              className={cn(
                "inline-flex min-h-10 w-full items-center justify-center gap-2 rounded-lg border px-3 py-2 text-xs font-medium sm:w-auto",
                connected ? "border-safe/30 bg-safe/10 text-safe" : "border-warning/30 bg-warning/10 text-warning"
              )}
            >
              <span className={cn("size-2 rounded-full", connected ? "bg-safe animate-pulse" : "bg-warning")} />
              {health.isLoading ? "Checking backend..." : connected ? "ML Engine Online" : "Backend Unavailable"}
            </span>
          </div>
        }
      />

      {/* Compact Live AI Telemetry & Threat Pulse Banner (Theme-Adaptive for Light & Dark Mode) */}
      <motion.section
        initial={shouldReduceMotion ? false : { opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: shouldReduceMotion ? 0 : 0.28, ease: "easeOut" }}
        className="relative overflow-hidden rounded-xl border border-primary/25 bg-gradient-to-r from-sky-50/95 via-cyan-50/60 to-indigo-50/75 p-4 shadow-panel sm:p-5 dark:border-cyan-500/25 dark:from-[#07101F] dark:via-[#0A1628] dark:to-[#07101F]"
      >
        <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(to_right,rgba(14,165,233,0.06)_1px,transparent_1px),linear-gradient(to_bottom,rgba(14,165,233,0.06)_1px,transparent_1px)] bg-[size:24px_24px] dark:bg-[linear-gradient(to_right,rgba(56,189,248,0.04)_1px,transparent_1px),linear-gradient(to_bottom,rgba(56,189,248,0.04)_1px,transparent_1px)]" />
        <div className="relative z-10 grid gap-4 lg:grid-cols-[1.3fr_1fr] lg:items-center lg:gap-5">
          <div className="min-w-0 space-y-2.5">
            <div className="inline-flex items-center gap-2 rounded-full border border-primary/30 bg-primary/10 px-3 py-1 text-[10px] font-semibold uppercase tracking-wider text-primary sm:text-[11px] dark:border-cyan-500/30 dark:bg-cyan-500/10 dark:text-cyan-300">
              <Activity className="size-3.5 text-primary dark:text-cyan-400" />
              Live Detection Pipeline Telemetry
            </div>
            <h2 className="text-base font-bold text-foreground sm:text-xl dark:text-slate-100">
              {modelInfo.data?.model ?? "Random Forest (Class-Balanced)"} • 10,043 Static Features
            </h2>
            <p className="max-w-2xl text-xs leading-relaxed text-muted-foreground sm:text-sm dark:text-slate-300">
              Real-time local inference combining word &amp; character TF-IDF n-grams with 43 lexical, urgency, and URL structural indicators. All URLs are inspected statically without network execution.
            </p>
            <div className="flex flex-wrap items-center gap-2 pt-1 text-[11px]">
              <span className="rounded-md border border-border bg-card/90 px-2.5 py-1 font-mono font-semibold text-primary dark:border-slate-700 dark:bg-slate-900/90 dark:text-cyan-300">
                Holdout Accuracy: 99.10%
              </span>
              <span className="rounded-md border border-border bg-card/90 px-2.5 py-1 font-mono font-semibold text-safe dark:border-slate-700 dark:bg-slate-900/90 dark:text-teal-300">
                ROC-AUC: 0.9936
              </span>
              <span className="rounded-md border border-border bg-card/90 px-2.5 py-1 font-mono text-muted-foreground dark:border-slate-700 dark:bg-slate-900/90 dark:text-slate-300">
                SQLite Audit Persistence: Active
              </span>
            </div>
          </div>

          {/* Right side: Latest Workspace Scan Pulse */}
          <motion.div
            whileHover={shouldReduceMotion ? { y: 0 } : { y: -2 }}
            transition={{ duration: 0.2 }}
            className="min-w-0 rounded-xl border border-border bg-card/90 p-3.5 shadow-2xs transition-colors hover:border-primary/40 sm:p-4 dark:border-slate-800 dark:bg-slate-950/85 dark:hover:border-cyan-500/35"
          >
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border pb-2.5 dark:border-slate-800">
              <span className="flex items-center gap-1.5 text-xs font-semibold text-foreground dark:text-slate-200">
                <Radar className="size-4 text-primary dark:text-cyan-400" /> Latest Recorded Scan
              </span>
              {latestScan ? (
                <span className={cn("rounded-full border px-2 py-0.5 text-[10px] font-semibold", badgeClassForRisk(latestScan.riskLevel))}>
                  {latestScan.riskLevel} Risk ({formatProbability(latestScan.riskProbability)})
                </span>
              ) : (
                <span className="text-[11px] text-muted-foreground dark:text-slate-400">No scans yet</span>
              )}
            </div>
            {latestScan ? (
              <div className="mt-3 space-y-2">
                <p className="truncate text-xs font-medium text-foreground dark:text-slate-100">{latestScan.inputPreview}</p>
                <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-muted-foreground dark:text-slate-400">
                  <span className="font-semibold uppercase tracking-wider text-primary dark:text-cyan-400">{latestScan.inputType}</span>
                  <span>Verdict: <strong className="text-foreground dark:text-slate-200">{latestScan.prediction}</strong></span>
                  <span>{formatTime(latestScan.timestamp)}</span>
                </div>
              </div>
            ) : (
              <p className="mt-3 text-xs text-muted-foreground dark:text-slate-400">
                Run a message, URL, or batch CSV scan to populate live telemetry.
              </p>
            )}
          </motion.div>
        </div>

        {/* Visual 4-Stage Detection Pipeline Flow */}
        <div className="relative z-10 mt-4 grid gap-2.5 border-t border-border/80 pt-4 sm:mt-5 sm:grid-cols-2 lg:grid-cols-4 dark:border-slate-800/80">
          {[
            {
              step: "Stage 01",
              title: "Input Sanitization",
              detail: "SMS, Email, Static URL & CSV validation",
              icon: MessageSquareText,
            },
            {
              step: "Stage 02",
              title: "10,043 Feature Vector",
              detail: "Word/Char TF-IDF + 43 lexical signals",
              icon: Layers,
            },
            {
              step: "Stage 03",
              title: "Random Forest Ensemble",
              detail: "200 class-balanced decision trees",
              icon: Cpu,
            },
            {
              step: "Stage 04",
              title: "Explainable Audit",
              detail: "Risk tier, indicators & SQLite history",
              icon: Database,
            },
          ].map((stage, index) => {
            const StageIcon = stage.icon;
            return (
              <motion.div
                key={stage.step}
                initial={shouldReduceMotion ? false : { opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                whileHover={shouldReduceMotion ? { y: 0 } : { y: -2 }}
                transition={{
                  duration: shouldReduceMotion ? 0 : 0.22,
                  delay: shouldReduceMotion ? 0 : 0.06 + index * 0.04,
                }}
                className="flex min-w-0 items-start gap-3 rounded-lg border border-border bg-card/85 p-3 transition-colors hover:border-primary/45 dark:border-slate-800/90 dark:bg-slate-950/60 dark:hover:border-cyan-500/40"
              >
                <span className="grid size-8 shrink-0 place-items-center rounded-md border border-primary/25 bg-primary/10 text-primary dark:border-cyan-500/25 dark:bg-cyan-500/10 dark:text-cyan-300">
                  <StageIcon className="size-4" />
                </span>
                <div className="min-w-0">
                  <p className="font-mono text-[10px] font-semibold uppercase tracking-wider text-primary dark:text-cyan-400">
                    {stage.step}
                  </p>
                  <p className="truncate text-xs font-semibold text-foreground dark:text-slate-100">{stage.title}</p>
                  <p className="mt-0.5 truncate text-[11px] text-muted-foreground dark:text-slate-400">{stage.detail}</p>
                </div>
              </motion.div>
            );
          })}
        </div>
      </motion.section>

      {/* 4 Primary KPI Cards */}
      <div className="grid gap-3.5 sm:grid-cols-2 sm:gap-4 xl:grid-cols-4">
        <KpiCard label="Total Scans" icon={FileSearch} value={history.isSuccess ? records.length : undefined} note={note} delay={0.02} />
        <KpiCard label="Scam / Phishing Detected" icon={ShieldAlert} tone="danger" value={history.isSuccess ? scam : undefined} note={note} delay={0.06} />
        <KpiCard label="Legitimate Detected" icon={ShieldCheck} tone="safe" value={history.isSuccess ? legitimate : undefined} note={note} delay={0.1} />
        <KpiCard label="High & Very High Risk" icon={AlertTriangle} tone="warning" value={history.isSuccess ? high : undefined} note={note} delay={0.14} />
      </div>

      {history.isLoading || history.isError ? <HistoryStatus loading={history.isLoading} error={history.error} /> : null}

      {/* Distribution Panels */}
      <div className="grid gap-6 xl:grid-cols-[1.35fr_1fr]">
        <Panel title="Risk Level Distribution" description="Live breakdown of completed scans across the four severity tiers." delay={0.08}>
          {records.length ? <HistoryBars records={records} mode="risk" /> : <ChartEmpty label="Risk levels" />}
        </Panel>
        <Panel title="Legitimate vs Scam / Phishing" description="Overall classification balance across all stored records." delay={0.12}>
          {records.length ? <HistoryBars records={records} mode="prediction" /> : <ChartEmpty label="Prediction classes" />}
        </Panel>
      </div>

      {/* Recent Activity & Quick Actions */}
      <div className="grid gap-6 xl:grid-cols-[1.45fr_1fr]">
        <Panel
          title="Recent Scan Activity"
          description="The newest message and URL inspections persisted in SQLite."
          delay={0.14}
          action={
            <Button asChild variant="ghost" size="sm" className="min-h-9">
              <Link to="/scan-history">
                View All <ArrowRight className="size-3.5" />
              </Link>
            </Button>
          }
        >
          {records.length ? (
            <div className="space-y-2.5">
              {records.slice(0, 6).map((record, idx) => (
                <motion.div
                  key={record.id}
                  initial={shouldReduceMotion ? false : { opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  whileHover={shouldReduceMotion ? { x: 0 } : { x: 2 }}
                  transition={{
                    duration: shouldReduceMotion ? 0 : 0.2,
                    delay: shouldReduceMotion ? 0 : idx * 0.035,
                  }}
                  className="flex flex-col gap-2 rounded-lg border border-border bg-secondary/25 p-3 transition-colors hover:border-primary/30 hover:bg-secondary/45 sm:grid sm:grid-cols-[76px_minmax(0,1fr)_auto_auto] sm:items-center sm:gap-3"
                >
                  <div className="flex items-center justify-between gap-2 sm:contents">
                    <span className="inline-flex items-center justify-center rounded border border-primary/25 bg-primary/10 px-2 py-0.5 text-[10px] font-semibold uppercase text-primary">
                      {record.inputType}
                    </span>
                    <span className={cn("text-xs font-semibold sm:order-4", record.prediction === "Scam/Phishing" ? "text-danger" : "text-safe")}>
                      {record.prediction}
                    </span>
                  </div>
                  <div className="min-w-0 sm:order-2">
                    <p className="truncate text-xs font-medium text-foreground">{record.inputPreview}</p>
                    <p className="text-[10px] text-muted-foreground">{formatTime(record.timestamp)}</p>
                  </div>
                  <div className="flex items-center justify-between sm:order-3 sm:justify-end">
                    <span className={cn("rounded-full border px-2.5 py-0.5 text-[10px] font-semibold", badgeClassForRisk(record.riskLevel))}>
                      {record.riskLevel} ({formatProbability(record.riskProbability)})
                    </span>
                  </div>
                </motion.div>
              ))}
            </div>
          ) : (
            <EmptyState compact title="No scans recorded" description="The backend has not returned any completed scans." />
          )}
        </Panel>

        <Panel title="Quick Launch Modules" description="Jump directly to a specialized inspection or reporting workflow." delay={0.18}>
          <div className="space-y-2.5">
            {[
              {
                to: "/message-analyzer",
                icon: MessageSquareText,
                title: "Message Analyzer",
                subtitle: "SMS, Email & Chat text",
              },
              {
                to: "/url-analyzer",
                icon: Link2,
                title: "Static URL Analyzer",
                subtitle: "Zero-visit lexical check",
              },
              {
                to: "/batch-scanner",
                icon: Upload,
                title: "Batch CSV Scanner",
                subtitle: "Bulk dataset classification",
              },
              {
                to: "/reports",
                icon: FileText,
                title: "Security Reports",
                subtitle: "Export PDF & CSV audits",
              },
              {
                to: "/learn-practise",
                icon: BrainCircuit,
                title: "Learn & Practise",
                subtitle: "Interactive phishing academy",
              },
              {
                to: "/settings-information",
                icon: Cpu,
                title: "Settings & Information",
                subtitle: "AI models, architecture & motion",
              },
            ].map((mod, idx) => {
              const ModIcon = mod.icon;
              return (
                <motion.div
                  key={mod.to}
                  initial={shouldReduceMotion ? false : { opacity: 0, x: 6 }}
                  animate={{ opacity: 1, x: 0 }}
                  whileHover={shouldReduceMotion ? { x: 0 } : { x: 3 }}
                  transition={{
                    duration: shouldReduceMotion ? 0 : 0.2,
                    delay: shouldReduceMotion ? 0 : idx * 0.035,
                  }}
                >
                  <Button
                    asChild
                    variant="outline"
                    className="group h-auto min-h-12 w-full justify-between px-3.5 py-2.5 text-left whitespace-normal transition-colors hover:border-primary/40"
                  >
                    <Link to={mod.to}>
                      <span className="flex min-w-0 items-center gap-3 pr-2">
                        <ModIcon className="size-4 shrink-0 text-primary transition-transform group-hover:scale-110" />
                        <span className="flex min-w-0 flex-col sm:flex-row sm:items-center sm:gap-2">
                          <strong className="truncate text-xs font-semibold text-foreground sm:text-sm">{mod.title}</strong>
                          <span className="truncate text-[11px] text-muted-foreground sm:text-xs">{mod.subtitle}</span>
                        </span>
                      </span>
                      <ArrowRight className="size-4 shrink-0 transition-transform group-hover:translate-x-0.5" />
                    </Link>
                  </Button>
                </motion.div>
              );
            })}
          </div>
        </Panel>
      </div>

      <ApiDiagnosticsPanel />
    </div>
  );
}

// ============================================================================
// 2. MESSAGE ANALYZER PAGE
// ============================================================================
export function MessageAnalyzerPage() {
  const { shouldReduceMotion } = useScamlensPreferences();
  const [mode, setMode] = useState<"message" | "email">("message");
  const [message, setMessage] = useState("");
  const [status, setStatus] = useState<RequestStatus>("idle");
  const [error, setError] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const queryClient = useQueryClient();

  async function analyze() {
    if (message.trim().length < 3) {
      setError("Enter at least 3 characters to analyze.");
      setStatus("error");
      setResult(null);
      return;
    }
    setStatus("loading");
    setResult(null);
    try {
      const response = await scamlensApi.analyzeMessage({ message });
      setResult(response);
      setStatus("success");
      void queryClient.invalidateQueries({ queryKey: ["scamlens", "history"] });
    } catch (err) {
      setError(apiError(err));
      setStatus("error");
    }
  }

  return (
    <div className="space-y-7">
      <PageHeader
        eyebrow="NLP Threat Inspection"
        title="Message Analyzer"
        description="Inspect SMS, WhatsApp, email, or chat messages for scam lures, social engineering urgency, and embedded phishing links using the trained Random Forest classifier."
      />

      {/* Analysis Mode Toggle */}
      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={() => {
            setMode("message");
            setResult(null);
            setStatus("idle");
          }}
          className={cn(
            "flex items-center gap-2 rounded-lg border px-4 py-2 text-xs font-semibold transition-all sm:text-sm",
            mode === "message"
              ? "border-primary bg-primary text-primary-foreground shadow-sm"
              : "border-border bg-card text-muted-foreground hover:bg-secondary hover:text-foreground"
          )}
        >
          <ScanText className="size-4" />
          <span>SMS &amp; Text Message Analyzer</span>
        </button>

        <button
          type="button"
          onClick={() => {
            setMode("email");
            setResult(null);
            setStatus("idle");
          }}
          className={cn(
            "flex items-center gap-2 rounded-lg border px-4 py-2 text-xs font-semibold transition-all sm:text-sm",
            mode === "email"
              ? "border-primary bg-primary text-primary-foreground shadow-sm"
              : "border-border bg-card text-muted-foreground hover:bg-secondary hover:text-foreground"
          )}
        >
          <Mail className="size-4" />
          <span>Email Phishing Analyzer</span>
          <span className="rounded bg-primary-foreground/20 px-1.5 py-0.5 text-[10px] font-bold">New</span>
        </button>
      </div>

      {mode === "email" ? (
        <EmailAnalyzerSection onResultUpdated={setResult} />
      ) : (
      <div className="grid gap-6 xl:grid-cols-[1.05fr_.95fr]">
        <Panel
          title="Message Content Input"
          description="Paste the suspicious text below. Avoid submitting personal passwords or private OTPs."
          delay={0.04}
        >
          <div className="mb-2 flex items-center justify-between">
            <label className="text-xs font-semibold text-foreground" htmlFor="message">
              SMS / Email / Chat Text
            </label>
            <span className="font-mono text-xs text-muted-foreground">
              {message.length.toLocaleString()} / 10,000 chars
            </span>
          </div>

          <div className="rounded-lg transition-shadow duration-200 focus-within:shadow-[0_0_24px_-6px_rgba(56,189,248,0.28)]">
            <Textarea
              id="message"
              value={message}
              onChange={(e) => {
                setMessage(e.target.value.slice(0, 10000));
                setStatus("idle");
                setResult(null);
              }}
              placeholder="Paste suspicious SMS, email, or message text here to evaluate its scam probability..."
              className="min-h-64 resize-y font-sans text-sm leading-relaxed transition-colors duration-200 focus-visible:border-primary/60"
              maxLength={10000}
            />
          </div>

          <div className="mt-2 flex items-center justify-between text-xs text-muted-foreground">
            <span className="flex items-center gap-1.5">
              <CheckCircle2 className="size-3.5 text-safe" />
              Connected to live FastAPI Random Forest model (minimum 3 characters)
            </span>
            {message.trim().length > 0 && message.trim().length < 3 && (
              <span className="text-warning">Need {3 - message.trim().length} more char(s)</span>
            )}
          </div>

          <div className="mt-5 flex flex-wrap items-center gap-2.5">
            <Button
              onClick={analyze}
              disabled={status === "loading"}
              className="min-h-11 flex-1 transition-transform active:scale-97 sm:min-h-10 sm:flex-initial"
            >
              {status === "loading" ? <Loader2 className="size-4 animate-spin" /> : <Sparkles className="size-4" />}
              {status === "loading" ? "Scanning Message..." : "Scan Message"}
            </Button>
            <Button
              variant="outline"
              disabled={!message && status === "idle"}
              className="min-h-11 flex-1 transition-transform active:scale-97 sm:min-h-10 sm:flex-initial"
              onClick={() => {
                setMessage("");
                setStatus("idle");
                setError("");
                setResult(null);
              }}
            >
              <Trash2 className="size-4" /> Clear Input
            </Button>
          </div>

          {/* Clearly marked Example Messages */}
          <div className="mt-6 border-t border-border pt-5">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <p className="text-xs font-semibold text-foreground">Load Sample Test Message</p>
              <span className="rounded border border-border bg-secondary px-2 py-0.5 text-[10px] font-medium text-muted-foreground">
                Example Inputs — Click to Populate
              </span>
            </div>
            <div className="grid gap-2 sm:grid-cols-2">
              {Object.entries(messageExamples).map(([label, value], idx) => (
                <motion.button
                  key={label}
                  type="button"
                  initial={shouldReduceMotion ? false : { opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  whileHover={shouldReduceMotion ? { y: 0 } : { y: -2 }}
                  whileTap={shouldReduceMotion ? { scale: 1 } : { scale: 0.985 }}
                  transition={{
                    duration: shouldReduceMotion ? 0 : 0.2,
                    delay: shouldReduceMotion ? 0 : idx * 0.035,
                  }}
                  onClick={() => {
                    setMessage(value);
                    setStatus("idle");
                    setError("");
                    setResult(null);
                  }}
                  className="flex min-h-12 flex-col items-start rounded-lg border border-border bg-secondary/30 p-3 text-left transition-colors hover:border-primary/45 hover:bg-secondary/60"
                >
                  <span className="text-xs font-semibold text-foreground">{label}</span>
                  <span className="mt-1 line-clamp-1 text-[11px] text-muted-foreground">{value}</span>
                </motion.button>
              ))}
            </div>
          </div>
        </Panel>

        <Panel
          title="Live AI Classification Result"
          description="Real prediction, probability score, risk indicators, and safety guidance from the backend."
          delay={0.08}
        >
          <AnimatePresence mode="wait">
            {result ? (
              <motion.div
                key={`msg-result-${result.scanId ?? result.timestamp ?? result.riskProbability}`}
                initial={shouldReduceMotion ? false : { opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={shouldReduceMotion ? { opacity: 1 } : { opacity: 0, y: -6 }}
                transition={{ duration: shouldReduceMotion ? 0 : 0.24 }}
              >
                <AnalysisResultView result={result} />
              </motion.div>
            ) : status === "loading" ? (
              <motion.div
                key="msg-loading"
                initial={shouldReduceMotion ? false : { opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={shouldReduceMotion ? { opacity: 1 } : { opacity: 0 }}
                transition={{ duration: shouldReduceMotion ? 0 : 0.2 }}
                className="space-y-4"
              >
                <ApiNotice
                  kind="loading"
                  message="Extracting 10,043 TF-IDF & lexical features and querying the trained Random Forest classifier..."
                />
                <div className="relative overflow-hidden rounded-lg border border-primary/30 bg-primary/5 p-5 dark:border-cyan-500/30 dark:bg-slate-950/80">
                  <div className="flex items-center gap-3 text-xs font-medium text-primary dark:text-cyan-300">
                    <span className="size-2.5 shrink-0 rounded-full bg-primary animate-ping dark:bg-cyan-400" />
                    <span>Running live offline ML inference on FastAPI backend...</span>
                  </div>
                  <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-secondary dark:bg-slate-800">
                    <div className="h-full w-2/3 animate-pulse rounded-full bg-gradient-to-r from-primary to-accent dark:from-cyan-500 dark:to-teal-400" />
                  </div>
                </div>
              </motion.div>
            ) : (
              <motion.div
                key={`msg-idle-${status}`}
                initial={shouldReduceMotion ? false : { opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={shouldReduceMotion ? { opacity: 1 } : { opacity: 0 }}
                transition={{ duration: shouldReduceMotion ? 0 : 0.2 }}
              >
                <ApiNotice kind={status} message={status === "error" ? error : undefined} />
                <div className="mt-5 grid grid-cols-1 gap-3 sm:grid-cols-2">
                  {["Prediction", "Risk Probability", "Risk Level", "Classifier Model"].map((item, idx) => (
                    <motion.div
                      key={item}
                      initial={shouldReduceMotion ? false : { opacity: 0, y: 6 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{
                        duration: shouldReduceMotion ? 0 : 0.2,
                        delay: shouldReduceMotion ? 0 : idx * 0.04,
                      }}
                      className="rounded-lg border border-border bg-secondary/30 p-4"
                    >
                      <p className="text-xs text-muted-foreground">{item}</p>
                      <p className="mt-2 text-sm font-medium text-muted-foreground">Awaiting scan</p>
                    </motion.div>
                  ))}
                </div>
                <div className="mt-4 rounded-lg border border-dashed border-border bg-muted/15 p-4 text-xs text-muted-foreground">
                  <p className="font-medium text-foreground">How Message Scanning Works</p>
                  <p className="mt-1 leading-5">
                    When you click <strong>Scan Message</strong>, the text is sent to <code>POST /api/analyze/message</code>. The backend extracts word/character n-grams and 43 structural indicators (urgency cues, currency lures, OTP/KYC requests, embedded URLs) to compute an exact probability score.
                  </p>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </Panel>
      </div>
      )}
    </div>
  );
}

// ============================================================================
// 3. URL ANALYZER PAGE
// ============================================================================
const urlChecks = [
  ["HTTPS Protocol", LockKeyhole, "Checks whether transport uses TLS (https://) or plain HTTP"],
  ["URL Length & Depth", CircleGauge, "Detects abnormally long URLs used to hide deceptive paths"],
  ["Domain Structure", Network, "Evaluates primary domain tokens and hyphens"],
  ["Subdomain Count", ListChecks, "Flags excessive subdomain chaining (e.g. login.secure.bank.example)"],
  ["Raw IP Hostname", Search, "Detects numeric IPv4 addresses replacing domain names"],
  ["@ Symbol Obfuscation", AlertTriangle, "Checks for credential-prefix redirects (@ in URL authority)"],
  ["Phishing Keywords", ShieldAlert, "Scans for verify, login, update, kyc, claim, reward, free"],
  ["URL Shortener Service", Link2, "Identifies bit.ly, tinyurl, t.co, and masked redirects"],
  ["Special Character Density", FileSearch, "Measures digits, query parameters, and encoded symbols"],
] as const;

export function UrlAnalyzerPage() {
  const { shouldReduceMotion } = useScamlensPreferences();
  const [url, setUrl] = useState("");
  const [status, setStatus] = useState<RequestStatus>("idle");
  const [error, setError] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const queryClient = useQueryClient();

  async function analyze() {
    const trimmed = url.trim();
    try {
      const parsed = new URL(trimmed);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        setError("URL must start with http:// or https://.");
        setStatus("error");
        setResult(null);
        return;
      }
    } catch {
      setError("Enter a complete, valid URL including http:// or https://.");
      setStatus("error");
      setResult(null);
      return;
    }
    setStatus("loading");
    setResult(null);
    try {
      const response = await scamlensApi.analyzeUrl({ url: trimmed });
      setResult(response);
      setStatus("success");
      void queryClient.invalidateQueries({ queryKey: ["scamlens", "history"] });
    } catch (err) {
      setError(apiError(err));
      setStatus("error");
    }
  }

  return (
    <div className="space-y-7">
      <PageHeader
        eyebrow="Zero-Execution Lexical Inspection"
        title="Static URL Analyzer"
        description="Evaluate suspicious web links for phishing patterns, domain obfuscation, and structural anomalies without ever visiting or executing the target address."
      />

      <Panel
        title="Suspicious URL Input"
        description="Paste a complete URL starting with http:// or https://. The string is analyzed statically as text."
        delay={0.04}
      >
        <div className="grid gap-3 md:grid-cols-[minmax(0,1fr)_auto_auto]">
          <div className="min-w-0 rounded-md transition-shadow duration-200 focus-within:shadow-[0_0_24px_-6px_rgba(56,189,248,0.28)]">
            <Input
              value={url}
              onChange={(e) => {
                setUrl(e.target.value.slice(0, 2048));
                setStatus("idle");
                setResult(null);
              }}
              placeholder="https://example.com/login/verify-account"
              className="h-11 font-mono text-sm transition-colors duration-200 focus-visible:border-primary/60 md:h-9"
              maxLength={2048}
            />
          </div>
          <div className="flex flex-wrap items-center gap-2.5 md:contents">
            <Button
              onClick={analyze}
              disabled={status === "loading"}
              className="min-h-11 flex-1 transition-transform active:scale-97 md:min-h-9 md:flex-initial"
            >
              {status === "loading" ? <Loader2 className="size-4 animate-spin" /> : <FileSearch className="size-4" />}
              {status === "loading" ? "Inspecting URL..." : "Scan URL"}
            </Button>
            <Button
              variant="outline"
              disabled={!url && status === "idle"}
              className="min-h-11 flex-1 transition-transform active:scale-97 md:min-h-9 md:flex-initial"
              onClick={() => {
                setUrl("");
                setStatus("idle");
                setError("");
                setResult(null);
              }}
            >
              <Trash2 className="size-4" /> Clear
            </Button>
          </div>
        </div>

        <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground">
          <span className="flex items-start gap-2 sm:items-center">
            <LockKeyhole className="mt-0.5 size-3.5 shrink-0 text-safe sm:mt-0" />
            <span>
              <strong>Safety Guarantee:</strong> SCAMLENS AI never opens, fetches, renders, or navigates to submitted URLs.
            </span>
          </span>
          <span className="font-mono">{url.length} / 2,048 chars</span>
        </div>

        {/* Example URLs */}
        <div className="mt-5 border-t border-border pt-4">
          <div className="mb-2.5 flex flex-wrap items-center justify-between gap-2">
            <span className="text-xs font-semibold text-foreground">Load Example URL for Static Testing</span>
            <span className="rounded border border-border bg-secondary px-2 py-0.5 text-[10px] text-muted-foreground">
              Inert Text Examples
            </span>
          </div>
          <div className="grid gap-2 sm:grid-cols-2">
            {Object.entries(urlExamples).map(([label, sampleUrl], idx) => (
              <motion.button
                key={label}
                type="button"
                initial={shouldReduceMotion ? false : { opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                whileHover={shouldReduceMotion ? { y: 0 } : { y: -2 }}
                whileTap={shouldReduceMotion ? { scale: 1 } : { scale: 0.985 }}
                transition={{
                  duration: shouldReduceMotion ? 0 : 0.2,
                  delay: shouldReduceMotion ? 0 : idx * 0.035,
                }}
                onClick={() => {
                  setUrl(sampleUrl);
                  setStatus("idle");
                  setError("");
                  setResult(null);
                }}
                className="flex min-h-12 min-w-0 flex-col items-start rounded-lg border border-border bg-secondary/30 p-2.5 text-left transition-colors hover:border-primary/45 hover:bg-secondary/60"
              >
                <span className="text-xs font-semibold text-foreground">{label}</span>
                <span className="mt-0.5 w-full truncate font-mono text-[11px] text-primary">{sampleUrl}</span>
              </motion.button>
            ))}
          </div>
        </div>
      </Panel>

      <div className="grid gap-6 xl:grid-cols-[1.1fr_.9fr]">
        <Panel
          title="Static Lexical & Structural Checks"
          description="9 structural dimensions inspected by the Python URL feature extractor."
          delay={0.08}
        >
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {urlChecks.map(([label, Icon, desc], idx) => (
              <motion.div
                key={label}
                initial={shouldReduceMotion ? false : { opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                whileHover={shouldReduceMotion ? { y: 0 } : { y: -2 }}
                transition={{
                  duration: shouldReduceMotion ? 0 : 0.22,
                  delay: shouldReduceMotion ? 0 : idx * 0.03,
                }}
                className={cn(
                  "flex flex-col justify-between rounded-lg border p-3.5 transition-all duration-200 hover:border-primary/40",
                  result
                    ? "border-primary/30 bg-primary/5 shadow-[0_0_18px_-8px_rgba(56,189,248,0.25)]"
                    : "border-border bg-secondary/30"
                )}
              >
                <div className="flex items-center justify-between gap-2">
                  <Icon className="size-4 text-primary" />
                  <span
                    className={cn(
                      "rounded px-1.5 py-0.5 text-[10px] font-semibold transition-colors",
                      result ? "bg-safe/15 text-safe" : "bg-secondary text-muted-foreground"
                    )}
                  >
                    {result ? "Evaluated" : "Standby"}
                  </span>
                </div>
                <div className="mt-2.5">
                  <p className="text-xs font-semibold text-foreground">{label}</p>
                  <p className="mt-1 text-[11px] leading-snug text-muted-foreground">{desc}</p>
                </div>
              </motion.div>
            ))}
          </div>
        </Panel>

        <Panel title="URL Risk Assessment" description="Classification verdict, indicators, and security recommendation." delay={0.12}>
          <AnimatePresence mode="wait">
            {result ? (
              <motion.div
                key={`url-result-${result.scanId ?? result.timestamp ?? result.riskProbability}`}
                initial={shouldReduceMotion ? false : { opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={shouldReduceMotion ? { opacity: 1 } : { opacity: 0, y: -6 }}
                transition={{ duration: shouldReduceMotion ? 0 : 0.24 }}
              >
                <AnalysisResultView result={result} />
              </motion.div>
            ) : status === "loading" ? (
              <motion.div
                key="url-loading"
                initial={shouldReduceMotion ? false : { opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={shouldReduceMotion ? { opacity: 1 } : { opacity: 0 }}
                transition={{ duration: shouldReduceMotion ? 0 : 0.2 }}
                className="space-y-4"
              >
                <ApiNotice
                  kind="loading"
                  message="Inspecting URL lexical structure and querying the Python Random Forest service..."
                />
                <div className="relative overflow-hidden rounded-lg border border-primary/30 bg-primary/5 p-5 dark:border-cyan-500/30 dark:bg-slate-950/80">
                  <div className="flex items-center gap-3 text-xs font-medium text-primary dark:text-cyan-300">
                    <span className="size-2.5 shrink-0 rounded-full bg-primary animate-ping dark:bg-cyan-400" />
                    <span>Running zero-execution static lexical check on FastAPI backend...</span>
                  </div>
                  <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-secondary dark:bg-slate-800">
                    <div className="h-full w-2/3 animate-pulse rounded-full bg-gradient-to-r from-primary to-accent dark:from-cyan-500 dark:to-teal-400" />
                  </div>
                </div>
              </motion.div>
            ) : (
              <motion.div
                key={`url-idle-${status}`}
                initial={shouldReduceMotion ? false : { opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={shouldReduceMotion ? { opacity: 1 } : { opacity: 0 }}
                transition={{ duration: shouldReduceMotion ? 0 : 0.2 }}
              >
                <ApiNotice
                  kind={status}
                  message={
                    status === "error"
                      ? error
                      : "Submit a URL above to view its phishing probability and structural indicators."
                  }
                />
              </motion.div>
            )}
          </AnimatePresence>
        </Panel>
      </div>
    </div>
  );
}

// ============================================================================
// 4. BATCH CSV SCANNER PAGE (Drag-and-drop, column selector, accurate counts)
// ============================================================================
type CsvPreview = {
  name: string;
  size: number;
  headers: string[];
  rows: string[][];
  count: number;
  raw: File;
};

function parseCsvRow(line: string) {
  const cells: string[] = [];
  let cell = "";
  let quoted = false;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (character === '"') {
      if (quoted && line[index + 1] === '"') {
        cell += '"';
        index += 1;
      } else {
        quoted = !quoted;
      }
    } else if (character === "," && !quoted) {
      cells.push(cell.trim());
      cell = "";
    } else {
      cell += character;
    }
  }
  cells.push(cell.trim());
  return cells;
}

const PREFERRED_COLUMNS = ["text", "message", "content", "sms", "body", "url", "input", "email"];

export function BatchScannerPage() {
  const { shouldReduceMotion } = useScamlensPreferences();
  const inputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<CsvPreview | null>(null);
  const [selectedColumn, setSelectedColumn] = useState<string>("");
  const [isDragging, setIsDragging] = useState(false);
  const [error, setError] = useState("");
  const [status, setStatus] = useState<RequestStatus>("idle");
  const [batchMeta, setBatchMeta] = useState<BatchAnalysisResponse | null>(null);
  const [resultFilter, setResultFilter] = useState<"ALL" | "SCAM" | "LEGITIMATE">("ALL");
  const queryClient = useQueryClient();

  function processSelectedFile(selected: File | undefined) {
    if (!selected) return;
    if (!selected.name.toLowerCase().endsWith(".csv")) {
      setError("Invalid file type. Please upload a .csv file.");
      setFile(null);
      return;
    }
    if (selected.size === 0) {
      setError("The selected CSV file is empty (0 bytes).");
      setFile(null);
      return;
    }
    if (selected.size > 5 * 1024 * 1024) {
      setError("The CSV file exceeds the 5 MB maximum size limit.");
      setFile(null);
      return;
    }

    const reader = new FileReader();
    reader.onerror = () => {
      setError("Could not read the selected file. Verify file permissions and UTF-8 encoding.");
      setFile(null);
    };
    reader.onload = () => {
      const rawText = String(reader.result ?? "").replace(/^\uFEFF/, "");
      const lines = rawText
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter((l) => l.length > 0);
      if (lines.length < 2) {
        setError("The CSV file must contain a header row and at least one data row.");
        setFile(null);
        return;
      }
      const parsed = lines.map(parseCsvRow);
      const headerRow = parsed[0]?.map((h, idx) => h || `Column_${idx + 1}`) ?? [];
      if (headerRow.length === 0 || headerRow.every((h) => !h.trim())) {
        setError("The CSV header row is empty or malformed.");
        setFile(null);
        return;
      }

      // Auto-select preferred column if present, otherwise first column
      const lowerMap = new Map(headerRow.map((h) => [h.toLowerCase().trim(), h]));
      let autoCol = headerRow[0] ?? "text";
      for (const candidate of PREFERRED_COLUMNS) {
        if (lowerMap.has(candidate)) {
          autoCol = lowerMap.get(candidate)!;
          break;
        }
      }

      setError("");
      setStatus("idle");
      setBatchMeta(null);
      setSelectedColumn(autoCol);
      setFile({
        name: selected.name,
        size: selected.size,
        headers: headerRow.slice(0, 8),
        rows: parsed.slice(1, 7).map((row) => row.slice(0, 8)),
        count: parsed.length - 1,
        raw: selected,
      });
    };
    reader.readAsText(selected, "utf-8");
  }

  function handleFileChange(event: ChangeEvent<HTMLInputElement>) {
    processSelectedFile(event.target.files?.[0]);
  }

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setIsDragging(false);
    const dropped = event.dataTransfer.files?.[0];
    processSelectedFile(dropped);
  }

  function clearFile() {
    setFile(null);
    setSelectedColumn("");
    setError("");
    setStatus("idle");
    setBatchMeta(null);
    if (inputRef.current) inputRef.current.value = "";
  }

  function loadSampleCsv() {
    const sampleContent = [
      "id,channel,message",
      '101,SMS,"Congratulations! You have won a Rs 50,000 cash prize. Claim now at http://lucky-reward-claim.example/win"',
      '102,Email,"Hi team, please find the project architecture notes attached for tomorrow\'s 10 AM review."',
      '103,SMS,"URGENT: Your SBI bank account will be blocked today. Verify PAN and OTP immediately at http://sbi-kyc-update.example"',
      '104,WhatsApp,"Hey! Are we still meeting at the library at 4 PM to practice the presentation?"',
      '105,URL,"http://192.168.1.200/secure-login/verify-account/password-reset.php"',
    ].join("\n");
    const sampleFile = new File([sampleContent], "scamlens_sample_dataset.csv", { type: "text/csv" });
    processSelectedFile(sampleFile);
  }

  async function scan() {
    if (!file) return;
    setStatus("loading");
    setError("");
    setBatchMeta(null);
    try {
      const response = await scamlensApi.analyzeBatch(file.raw, selectedColumn);
      setBatchMeta(response);
      setStatus("success");
      void queryClient.invalidateQueries({ queryKey: ["scamlens", "history"] });
    } catch (err) {
      setError(apiError(err));
      setStatus("error");
    }
  }

  const results = batchMeta?.results ?? [];
  const filteredResults = useMemo(() => {
    if (resultFilter === "SCAM") return results.filter((r) => r.prediction === "Scam/Phishing");
    if (resultFilter === "LEGITIMATE") return results.filter((r) => r.prediction === "Legitimate");
    return results;
  }, [results, resultFilter]);

  function downloadCsv() {
    if (!results.length) return;
    const headers = [
      "Row ID",
      "Timestamp",
      "Input Type",
      "Submitted Content",
      "Prediction",
      "Risk Probability (%)",
      "Risk Level",
      "Indicators",
      "Security Guidance",
      "Model",
    ];
    const rows = results.map((r) => [
      r.id,
      r.timestamp,
      r.inputType,
      r.inputPreview,
      r.prediction,
      r.riskProbability.toFixed(2),
      r.riskLevel,
      r.indicators.join("; "),
      r.guidance,
      r.model,
    ]);
    const content = [headers, ...rows].map((row) => row.map(csvCell).join(",")).join("\n");
    const objectUrl = URL.createObjectURL(new Blob([content], { type: "text/csv;charset=utf-8;" }));
    const anchor = document.createElement("a");
    anchor.href = objectUrl;
    anchor.download = `scamlens-batch-results-${new Date().toISOString().slice(0, 10)}.csv`;
    anchor.click();
    URL.revokeObjectURL(objectUrl);
  }

  const legitimateCount = results.filter((r) => r.prediction === "Legitimate").length;
  const scamCount = results.filter((r) => r.prediction === "Scam/Phishing").length;
  const highRiskCount = results.filter((r) => r.riskLevel === "High" || r.riskLevel === "Very High").length;
  const selectedColIndex = file ? Math.max(0, file.headers.indexOf(selectedColumn)) : 0;

  return (
    <div className="space-y-7">
      <PageHeader
        eyebrow="Bulk Dataset Classification"
        title="Batch CSV Scanner"
        description="Upload a CSV dataset of messages or URLs, select the target column to inspect, and run real batch classification through the FastAPI Random Forest engine."
        actions={
          <div className="flex w-full flex-wrap items-center gap-2 sm:w-auto">
            <Button
              variant="secondary"
              size="sm"
              onClick={loadSampleCsv}
              className="min-h-10 flex-1 transition-transform active:scale-97 sm:min-h-8 sm:flex-initial"
            >
              <FileSpreadsheet className="size-4" /> Load Sample CSV
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={!results.length}
              onClick={downloadCsv}
              className="min-h-10 flex-1 transition-transform active:scale-97 sm:min-h-8 sm:flex-initial"
            >
              <Download className="size-4" /> Export Results CSV ({results.length})
            </Button>
          </div>
        }
      />

      {/* Drag & Drop Upload Zone */}
      <Panel
        title="1. Upload & Validate CSV Dataset"
        description="Drag and drop a .csv file (max 5 MB, UTF-8) or browse from your computer."
        delay={0.04}
        action={
          file && (
            <Button variant="ghost" size="sm" onClick={clearFile} className="text-muted-foreground hover:text-danger">
              <Trash2 className="size-4" /> Remove File
            </Button>
          )
        }
      >
        <input ref={inputRef} type="file" accept=".csv,text/csv" onChange={handleFileChange} className="sr-only" />

        <motion.div
          animate={{ scale: isDragging && !shouldReduceMotion ? 1.01 : 1 }}
          whileHover={shouldReduceMotion ? { y: 0 } : { y: -1.5 }}
          transition={{ duration: 0.2 }}
          onDragOver={(e) => {
            e.preventDefault();
            setIsDragging(true);
          }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={handleDrop}
          onClick={() => inputRef.current?.click()}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") inputRef.current?.click();
          }}
          className={cn(
            "flex min-h-44 cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed p-6 text-center transition-colors",
            isDragging
              ? "border-primary bg-primary/10 shadow-[0_0_25px_rgba(34,211,238,0.15)]"
              : file
                ? "border-safe/40 bg-safe/5 hover:border-safe/60"
                : "border-border bg-muted/20 hover:border-primary/40 hover:bg-muted/35"
          )}
        >
          <AnimatePresence mode="wait">
            {file ? (
              <motion.div
                key={`csv-selected-${file.name}`}
                initial={shouldReduceMotion ? false : { opacity: 0, scale: 0.96 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={shouldReduceMotion ? { opacity: 1 } : { opacity: 0, scale: 0.96 }}
                transition={{ duration: shouldReduceMotion ? 0 : 0.2 }}
                className="flex flex-col items-center"
              >
                <span className="grid size-12 place-items-center rounded-xl border border-safe/40 bg-safe/15 text-safe">
                  <FileCheck2 className="size-6" />
                </span>
                <p className="mt-3 text-sm font-semibold text-foreground">{file.name}</p>
                <div className="mt-1.5 flex flex-wrap items-center justify-center gap-2 text-xs text-muted-foreground">
                  <span className="rounded border border-border bg-secondary px-2 py-0.5 font-mono">
                    {formatFileSize(file.size)}
                  </span>
                  <span className="rounded border border-border bg-secondary px-2 py-0.5 font-mono">
                    {file.count.toLocaleString()} data rows
                  </span>
                  <span className="rounded border border-safe/30 bg-safe/10 px-2 py-0.5 font-medium text-safe">
                    ✓ Valid CSV Structure
                  </span>
                </div>
                <p className="mt-2 text-xs text-primary underline">Click or drop another file to replace</p>
              </motion.div>
            ) : (
              <motion.div
                key="csv-empty"
                initial={shouldReduceMotion ? false : { opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={shouldReduceMotion ? { opacity: 1 } : { opacity: 0 }}
                transition={{ duration: shouldReduceMotion ? 0 : 0.18 }}
                className="flex flex-col items-center"
              >
                <span className="grid size-12 place-items-center rounded-xl bg-primary/10 text-primary">
                  <Upload className="size-6" />
                </span>
                <p className="mt-3 text-sm font-semibold text-foreground">
                  Drag &amp; drop your CSV file here, or click to Browse Files
                </p>
                <p className="mt-1 max-w-md text-xs text-muted-foreground">
                  Supports standard comma-separated values (.csv) up to 5 MB with a header row.
                </p>
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>

        {error && status !== "error" && (
          <motion.div
            initial={shouldReduceMotion ? false : { opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            className="mt-4 flex items-center gap-2 rounded-lg border border-danger/40 bg-danger/10 px-3.5 py-2.5 text-xs text-danger"
          >
            <XCircle className="size-4 shrink-0" />
            <span>{error}</span>
          </motion.div>
        )}
      </Panel>

      {file ? (
        <>
          {/* KPI Summary Row */}
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
            <KpiCard
              label="Rows in CSV"
              icon={FileText}
              value={batchMeta?.totalRows ?? file.count}
              note={`File: ${formatFileSize(file.size)}`}
              delay={0.02}
            />
            <KpiCard
              label="Successfully Scanned"
              icon={FileSearch}
              value={status === "success" ? (batchMeta?.processedRows ?? results.length) : undefined}
              note={
                status === "success"
                  ? batchMeta?.failedRows
                    ? `${batchMeta.failedRows} empty/skipped row(s)`
                    : "100% rows processed"
                  : "Ready to scan"
              }
              delay={0.05}
            />
            <KpiCard
              label="Legitimate"
              icon={ShieldCheck}
              tone="safe"
              value={status === "success" ? legitimateCount : undefined}
              note={status === "success" ? "Verified by backend" : undefined}
              delay={0.08}
            />
            <KpiCard
              label="Scam / Phishing"
              icon={ShieldAlert}
              tone="danger"
              value={status === "success" ? scamCount : undefined}
              note={status === "success" ? "Flagged by backend" : undefined}
              delay={0.11}
            />
            <KpiCard
              label="High / Very High Risk"
              icon={AlertTriangle}
              tone="warning"
              value={status === "success" ? highRiskCount : undefined}
              note={status === "success" ? "Priority review" : undefined}
              delay={0.14}
            />
          </div>

          {/* Column Selection & File Preview Panel */}
          <Panel
            title={`2. Configure Target Column & Preview (${file.name})`}
            description={`Showing first ${file.rows.length} of ${file.count.toLocaleString()} rows. The highlighted column will be sent to the ML classifier.`}
            delay={0.08}
            action={
              <div className="flex w-full flex-col gap-2.5 sm:w-auto sm:flex-row sm:flex-wrap sm:items-center sm:gap-3">
                <div className="flex items-center justify-between gap-2 sm:justify-start">
                  <label htmlFor="csv-column-select" className="text-xs font-medium text-muted-foreground">
                    Column to Scan:
                  </label>
                  <select
                    id="csv-column-select"
                    value={selectedColumn}
                    onChange={(e) => setSelectedColumn(e.target.value)}
                    className="h-10 min-w-36 rounded-md border border-border bg-secondary px-3 text-xs font-semibold text-foreground focus:border-primary focus:outline-none sm:h-9"
                  >
                    {file.headers.map((h) => (
                      <option key={h} value={h}>
                        {h}
                      </option>
                    ))}
                  </select>
                </div>
                <Button
                  onClick={scan}
                  disabled={status === "loading"}
                  className="min-h-10 w-full transition-transform active:scale-97 sm:min-h-9 sm:w-auto"
                >
                  {status === "loading" ? <Loader2 className="size-4 animate-spin" /> : <Sparkles className="size-4" />}
                  {status === "loading" ? `Scanning ${file.count} rows...` : `Run Batch Scan (${file.count} rows)`}
                </Button>
              </div>
            }
          >
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    {file.headers.map((h, idx) => (
                      <TableHead
                        key={h}
                        className={cn(
                          idx === selectedColIndex && "bg-primary/15 text-primary font-bold"
                        )}
                      >
                        {h} {idx === selectedColIndex && " (Selected)"}
                      </TableHead>
                    ))}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {file.rows.map((row, i) => (
                    <TableRow key={i} className="transition-colors hover:bg-secondary/35">
                      {file.headers.map((_, j) => (
                        <TableCell
                          key={j}
                          className={cn(
                            "max-w-72 truncate text-xs",
                            j === selectedColIndex && "bg-primary/5 font-medium text-foreground"
                          )}
                        >
                          {row[j] || "—"}
                        </TableCell>
                      ))}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </Panel>

          {/* Batch Scan Results Panel */}
          <Panel
            title="3. Batch Classification Results"
            description={
              batchMeta?.selectedColumn
                ? `Analyzed column "${batchMeta.selectedColumn}" • ${results.length} records classified and persisted to scan history.`
                : "Real predictions returned by POST /api/analyze/batch."
            }
            delay={0.12}
            action={
              results.length > 0 && (
                <div className="flex flex-wrap items-center gap-1.5">
                  {(["ALL", "SCAM", "LEGITIMATE"] as const).map((f) => (
                    <Button
                      key={f}
                      size="sm"
                      variant={resultFilter === f ? "default" : "outline"}
                      onClick={() => setResultFilter(f)}
                      className="min-h-9 text-xs transition-transform active:scale-97 sm:h-8"
                    >
                      {f === "ALL"
                        ? `All (${results.length})`
                        : f === "SCAM"
                          ? `Scam (${scamCount})`
                          : `Legitimate (${legitimateCount})`}
                    </Button>
                  ))}
                </div>
              )
            }
          >
            {status === "loading" ? (
              <ApiNotice
                kind="loading"
                message={`Analyzing ${file.count} rows from column "${selectedColumn}" via the FastAPI Random Forest service...`}
              />
            ) : status === "error" ? (
              <div className="space-y-3">
                <ApiNotice kind="error" message={error} />
                <Button variant="outline" size="sm" onClick={scan}>
                  <RefreshCw className="size-3.5" /> Retry Batch Scan
                </Button>
              </div>
            ) : results.length ? (
              <div className="space-y-4">
                {batchMeta?.errors && batchMeta.errors.length > 0 && (
                  <div className="rounded-lg border border-warning/40 bg-warning/10 p-3 text-xs text-warning">
                    <p className="font-semibold">
                      Note: {batchMeta.failedRows ?? batchMeta.errors.length} row(s) were skipped during processing:
                    </p>
                    <ul className="mt-1 list-disc pl-5">
                      {batchMeta.errors.slice(0, 5).map((errText, idx) => (
                        <li key={idx}>{errText}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Mobile Card List (visible on < md screens) */}
                <div className="space-y-3 md:hidden">
                  {filteredResults.map((r, idx) => (
                    <motion.div
                      key={`mobile-batch-${r.id}`}
                      initial={shouldReduceMotion ? false : { opacity: 0, y: 6 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{
                        duration: shouldReduceMotion ? 0 : 0.2,
                        delay: shouldReduceMotion ? 0 : Math.min(idx * 0.025, 0.3),
                      }}
                      className="rounded-xl border border-border bg-secondary/20 p-3.5 space-y-2.5"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="rounded border border-primary/25 bg-primary/10 px-2 py-0.5 text-[10px] font-semibold uppercase text-primary">
                          {r.inputType}
                        </span>
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span
                            className={cn(
                              "inline-flex rounded-full border px-2 py-0.5 text-[10px] font-semibold",
                              badgeClassForPrediction(r.prediction)
                            )}
                          >
                            {r.prediction}
                          </span>
                          <span
                            className={cn(
                              "inline-flex rounded-full border px-2 py-0.5 text-[10px] font-semibold",
                              badgeClassForRisk(r.riskLevel)
                            )}
                          >
                            {r.riskLevel} ({formatProbability(r.riskProbability)})
                          </span>
                        </div>
                      </div>
                      <p className="break-words text-xs font-medium text-foreground">{r.inputPreview}</p>
                      <p className="text-[11px] leading-relaxed text-muted-foreground">
                        {r.indicators[0] ?? r.guidance}
                      </p>
                    </motion.div>
                  ))}
                </div>

                {/* Desktop Table (visible on md+ screens) */}
                <div className="hidden overflow-x-auto md:block">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-20">Type</TableHead>
                        <TableHead>Submitted Content</TableHead>
                        <TableHead>Prediction</TableHead>
                        <TableHead>Probability</TableHead>
                        <TableHead>Risk Level</TableHead>
                        <TableHead>Primary Indicator / Guidance</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {filteredResults.map((r, idx) => (
                        <motion.tr
                          key={r.id}
                          initial={shouldReduceMotion ? false : { opacity: 0, y: 6 }}
                          animate={{ opacity: 1, y: 0 }}
                          transition={{
                            duration: shouldReduceMotion ? 0 : 0.2,
                            delay: shouldReduceMotion ? 0 : Math.min(idx * 0.025, 0.3),
                          }}
                          className="border-b border-border transition-colors hover:bg-secondary/35"
                        >
                          <TableCell className="uppercase text-xs font-semibold text-primary">{r.inputType}</TableCell>
                          <TableCell className="max-w-80 truncate text-xs font-medium text-foreground">
                            {r.inputPreview}
                          </TableCell>
                          <TableCell>
                            <span
                              className={cn(
                                "inline-flex rounded-full border px-2.5 py-0.5 text-[11px] font-semibold",
                                badgeClassForPrediction(r.prediction)
                              )}
                            >
                              {r.prediction}
                            </span>
                          </TableCell>
                          <TableCell className="font-mono text-xs">{formatProbability(r.riskProbability)}</TableCell>
                          <TableCell>
                            <span
                              className={cn(
                                "inline-flex rounded-full border px-2.5 py-0.5 text-[11px] font-semibold",
                                badgeClassForRisk(r.riskLevel)
                              )}
                            >
                              {r.riskLevel}
                            </span>
                          </TableCell>
                          <TableCell className="max-w-64 truncate text-xs text-muted-foreground">
                            {r.indicators[0] ?? r.guidance}
                          </TableCell>
                        </motion.tr>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </div>
            ) : (
              <EmptyState
                compact
                title="Ready to Run Batch Classification"
                description={`Click "Run Batch Scan (${file.count} rows)" above to classify column "${selectedColumn}".`}
              />
            )}
          </Panel>
        </>
      ) : (
        <EmptyState
          title="No CSV Dataset Loaded"
          description="Drag and drop a CSV file above, browse from your computer, or click 'Load Sample CSV' in the top right to test batch scanning immediately."
        />
      )}
    </div>
  );
}

// ============================================================================
// 5. ANALYTICS PAGE (Real scan data, time/channel filters, date trend chart)
// ============================================================================
export function AnalyticsPage() {
  const { shouldReduceMotion } = useScamlensPreferences();
  const history = useQuery(historyQueryOptions());
  const allRecords = history.data ?? [];

  const [daysFilter, setDaysFilter] = useState<0 | 7 | 30>(0);
  const [channelFilter, setChannelFilter] = useState<"all" | "message" | "url">("all");

  const records = useMemo(() => {
    const now = Date.now();
    return allRecords.filter((r) => {
      if (channelFilter !== "all" && r.inputType !== channelFilter) return false;
      if (daysFilter > 0) {
        const ts = new Date(r.timestamp).getTime();
        if (!Number.isNaN(ts) && now - ts > daysFilter * 86_400_000) return false;
      }
      return true;
    });
  }, [allRecords, daysFilter, channelFilter]);

  const scam = records.filter((r) => r.prediction === "Scam/Phishing").length;
  const rate = records.length ? (scam / records.length) * 100 : 0;
  const messages = records.filter((r) => r.inputType === "message").length;
  const urls = records.filter((r) => r.inputType === "url").length;
  const avgRisk = records.length
    ? records.reduce((acc, r) => acc + r.riskProbability, 0) / records.length
    : 0;

  // Group scan counts by date (up to last 7 active dates)
  const dateTrend = useMemo(() => {
    const counts = new Map<string, { total: number; scam: number }>();
    for (const r of records) {
      const key = formatShortDate(r.timestamp);
      const curr = counts.get(key) ?? { total: 0, scam: 0 };
      curr.total += 1;
      if (r.prediction === "Scam/Phishing") curr.scam += 1;
      counts.set(key, curr);
    }
    return Array.from(counts.entries()).slice(0, 7).reverse();
  }, [records]);

  const maxDateCount = Math.max(...dateTrend.map(([, v]) => v.total), 1);
  const note = history.isSuccess
    ? `Filtered from ${allRecords.length} total record(s)`
    : history.isError
      ? "Backend unavailable"
      : "Awaiting backend data";

  return (
    <div className="space-y-7">
      <PageHeader
        eyebrow="Security Intelligence"
        title="Threat Analytics"
        description="Explore real classification volume, severity distribution, and date-by-date detection trends computed directly from persisted scan records."
        actions={
          <div className="flex w-full flex-wrap items-center gap-2 sm:w-auto">
            <div className="flex flex-wrap items-center rounded-lg border border-border bg-card p-1">
              {([
                [0, "All Time"],
                [7, "Last 7 Days"],
                [30, "Last 30 Days"],
              ] as const).map(([days, label]) => {
                const active = daysFilter === days;
                return (
                  <button
                    key={days}
                    type="button"
                    onClick={() => setDaysFilter(days)}
                    className={cn(
                      "relative min-h-8 rounded-md px-2.5 py-1 text-xs font-medium transition-colors",
                      active ? "text-primary-foreground" : "text-muted-foreground hover:text-foreground"
                    )}
                  >
                    {active && (
                      <motion.span
                        layoutId="analytics-days-pill"
                        transition={
                          shouldReduceMotion
                            ? { duration: 0 }
                            : { type: "spring", stiffness: 400, damping: 30 }
                        }
                        className="pointer-events-none absolute inset-0 rounded-md bg-primary shadow-sm"
                      />
                    )}
                    <span className="relative z-10">{label}</span>
                  </button>
                );
              })}
            </div>
            <div className="flex flex-wrap items-center rounded-lg border border-border bg-card p-1">
              {([
                ["all", "All Channels"],
                ["message", "Messages"],
                ["url", "URLs"],
              ] as const).map(([ch, label]) => {
                const active = channelFilter === ch;
                return (
                  <button
                    key={ch}
                    type="button"
                    onClick={() => setChannelFilter(ch)}
                    className={cn(
                      "relative min-h-8 rounded-md px-2.5 py-1 text-xs font-medium transition-colors",
                      active ? "text-primary-foreground" : "text-muted-foreground hover:text-foreground"
                    )}
                  >
                    {active && (
                      <motion.span
                        layoutId="analytics-channel-pill"
                        transition={
                          shouldReduceMotion
                            ? { duration: 0 }
                            : { type: "spring", stiffness: 400, damping: 30 }
                        }
                        className="pointer-events-none absolute inset-0 rounded-md bg-primary shadow-sm"
                      />
                    )}
                    <span className="relative z-10">{label}</span>
                  </button>
                );
              })}
            </div>
          </div>
        }
      />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <KpiCard label="Matching Scans" icon={FileSearch} value={history.isSuccess ? records.length : undefined} note={note} delay={0.02} />
        <KpiCard
          label="Scam Detection Rate"
          icon={ShieldAlert}
          tone="danger"
          value={history.isSuccess && records.length ? formatProbability(rate) : "0.0%"}
          note={`${scam} Scam / Phishing detected`}
          delay={0.06}
        />
        <KpiCard
          label="Average Risk Probability"
          icon={CircleGauge}
          tone="warning"
          value={history.isSuccess && records.length ? formatProbability(avgRisk) : "0.0%"}
          note="Mean ML probability across filter"
          delay={0.1}
        />
        <KpiCard
          label="Channel Split (Msg / URL)"
          icon={Layers}
          value={history.isSuccess ? `${messages} / ${urls}` : undefined}
          note="Messages vs Static URLs"
          delay={0.14}
        />
      </div>

      {history.isLoading || history.isError ? <HistoryStatus loading={history.isLoading} error={history.error} /> : null}

      <div className="grid gap-6 xl:grid-cols-2">
        <Panel title="Scan Activity by Date" description="Daily scan volume and flagged scam count across active dates." delay={0.06}>
          {dateTrend.length ? (
            <div className="space-y-3.5">
              {dateTrend.map(([dateLabel, stats], idx) => (
                <motion.div
                  key={dateLabel}
                  initial={shouldReduceMotion ? false : { opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{
                    duration: shouldReduceMotion ? 0 : 0.22,
                    delay: shouldReduceMotion ? 0 : idx * 0.04,
                  }}
                  className="space-y-1.5"
                >
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-medium text-foreground">{dateLabel}</span>
                    <span className="font-mono text-muted-foreground">
                      <strong className="text-foreground">{stats.total}</strong> total •{" "}
                      <span className="text-danger">{stats.scam} scam</span>
                    </span>
                  </div>
                  <div className="flex h-3 w-full overflow-hidden rounded-full bg-muted">
                    <motion.div
                      initial={shouldReduceMotion ? false : { width: 0 }}
                      animate={{ width: `${(stats.scam / maxDateCount) * 100}%` }}
                      transition={{ duration: shouldReduceMotion ? 0 : 0.5, ease: "easeOut" }}
                      className="h-full bg-danger"
                      title={`Scam: ${stats.scam}`}
                    />
                    <motion.div
                      initial={shouldReduceMotion ? false : { width: 0 }}
                      animate={{ width: `${((stats.total - stats.scam) / maxDateCount) * 100}%` }}
                      transition={{ duration: shouldReduceMotion ? 0 : 0.5, delay: shouldReduceMotion ? 0 : 0.06, ease: "easeOut" }}
                      className="h-full bg-safe"
                      title={`Legitimate: ${stats.total - stats.scam}`}
                    />
                  </div>
                </motion.div>
              ))}
              <div className="flex items-center gap-4 pt-2 text-[11px] text-muted-foreground">
                <span className="flex items-center gap-1.5">
                  <span className="size-2.5 rounded-full bg-danger" /> Scam / Phishing
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="size-2.5 rounded-full bg-safe" /> Legitimate
                </span>
              </div>
            </div>
          ) : (
            <ChartEmpty label="Scans by date" />
          )}
        </Panel>

        <Panel title="Risk Level Breakdown" description="Proportion of scans falling into Low, Suspicious, High, and Very High tiers." delay={0.1}>
          {records.length ? <HistoryBars records={records} mode="risk" /> : <ChartEmpty label="Risk composition" />}
        </Panel>

        <Panel title="Legitimate vs Scam / Phishing" description="Binary classification outcome comparison." delay={0.14}>
          {records.length ? <HistoryBars records={records} mode="prediction" /> : <ChartEmpty label="Prediction classes" />}
        </Panel>

        <Panel title="Input Channel Distribution" description="Comparison between SMS/email message scans and static URL scans." delay={0.18}>
          {records.length ? <HistoryBars records={records} mode="type" /> : <ChartEmpty label="Input types" />}
        </Panel>
      </div>
    </div>
  );
}

// ============================================================================
// 6. AI & MODELS PAGE (Distinguish Holdout Test Metrics vs Live Workspace Stats)
// ============================================================================
export function ModelsPage() {
  const query = useQuery(modelInfoQueryOptions());
  const history = useQuery(historyQueryOptions());
  const info = query.data;
  const records = history.data ?? [];

  const metricLabels: Record<string, string> = {
    accuracy: "Holdout Accuracy",
    precision: "Precision (Scam Class)",
    recall: "Recall (Sensitivity)",
    f1_score: "F1 Score (Binary)",
    macro_f1: "Macro-Averaged F1",
    roc_auc: "ROC-AUC Score",
  };

  const numericMetrics: [string, number][] = info?.metrics
    ? (Object.entries(info.metrics).filter(([k, v]) => typeof v === "number" && k in metricLabels) as [string, number][])
    : [];

  const trainingSamples = info?.metrics?.["training_samples"];
  const testSamples = info?.metrics?.["test_samples"];
  const cvF1Mean = info?.metrics?.["cv_f1_mean"];

  const liveScamCount = records.filter((r) => r.prediction === "Scam/Phishing").length;
  const liveLegitCount = records.filter((r) => r.prediction === "Legitimate").length;

  return (
    <div className="space-y-7">
      <PageHeader
        eyebrow="Machine Learning Architecture"
        title="AI & Models"
        description="Verified training metadata, holdout evaluation metrics, and feature extraction architecture reported directly by the Python Random Forest service."
      />

      {query.isLoading ? (
        <ApiNotice kind="loading" message="Loading model information from the Python backend." />
      ) : query.isError ? (
        <ApiNotice kind="error" message={apiError(query.error)} />
      ) : !info ? (
        <EmptyState title="No model information" description="The backend has not returned model details." />
      ) : (
        <>
          {/* Summary cards */}
          <div className="grid gap-4 md:grid-cols-3">
            <div className="rounded-lg border border-primary/30 bg-card p-5 shadow-panel md:col-span-2">
              <div className="flex items-center justify-between">
                <p className="text-xs font-semibold uppercase tracking-wider text-primary">Active Production Classifier</p>
                <span className="rounded-full border border-safe/35 bg-safe/10 px-2.5 py-0.5 text-[10px] font-semibold text-safe">
                  Loaded &amp; Verified
                </span>
              </div>
              <p className="mt-2 text-lg font-bold text-foreground">{info.model ?? "Not provided"}</p>
              <p className="mt-1 text-xs text-muted-foreground">
                Selected after benchmarking {info.candidateModels?.length ?? 6} candidate algorithms on stratified 80/20 split.
              </p>
            </div>
            <div className="rounded-lg border border-border bg-card p-5 shadow-panel">
              <p className="text-xs text-muted-foreground">Model Artifact Version</p>
              <p className="mt-2 font-mono text-lg font-bold text-foreground">{info.version ?? "1.0.0"}</p>
              {cvF1Mean !== undefined && (
                <p className="mt-1 text-xs text-muted-foreground">5-Fold CV F1: {Number(cvF1Mean).toFixed(2)}%</p>
              )}
            </div>
            <div className="rounded-lg border border-border bg-card p-5 shadow-panel md:col-span-3">
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Training &amp; Evaluation Corpus</p>
              <p className="mt-1.5 text-sm font-semibold text-foreground">{info.dataset ?? "Not provided"}</p>
            </div>
          </div>

          {/* Dataset size breakdown */}
          <div className="grid gap-4 sm:grid-cols-3">
            <div className="rounded-lg border border-border bg-card p-5">
              <p className="text-xs text-muted-foreground">Total Corpus Samples</p>
              <p className="mt-2 font-mono text-2xl font-bold text-foreground">
                {info.datasetSize?.toLocaleString() ?? "Not provided"}
              </p>
              <p className="mt-1 text-[11px] text-muted-foreground">100% deduplicated SMS &amp; Phishing corpus</p>
            </div>
            <div className="rounded-lg border border-border bg-card p-5">
              <p className="text-xs text-muted-foreground">Training Set (80% Split)</p>
              <p className="mt-2 font-mono text-2xl font-bold text-foreground">
                {trainingSamples !== undefined && trainingSamples !== "N/A"
                  ? Number(trainingSamples).toLocaleString()
                  : "Not provided"}
              </p>
              <p className="mt-1 text-[11px] text-muted-foreground">Used for TF-IDF fit &amp; tree induction</p>
            </div>
            <div className="rounded-lg border border-border bg-card p-5">
              <p className="text-xs text-muted-foreground">Holdout Test Set (20% Split)</p>
              <p className="mt-2 font-mono text-2xl font-bold text-foreground">
                {testSamples !== undefined ? Number(testSamples).toLocaleString() : "Not provided"}
              </p>
              <p className="mt-1 text-[11px] text-muted-foreground">Unseen samples for evaluation metrics below</p>
            </div>
          </div>

          {/* Clear Distinction: Offline Holdout Evaluation Metrics vs Live Workspace Scan Statistics */}
          <div className="grid gap-6 xl:grid-cols-[1.35fr_1fr]">
            <Panel
              title="Measured Holdout Test-Set Metrics (Offline Evaluation)"
              description="Verified performance on the 1,115-sample unseen test partition (saved_models/model_metadata.json)."
            >
              {numericMetrics.length ? (
                <div className="grid gap-3.5 sm:grid-cols-2 lg:grid-cols-3">
                  {numericMetrics.map(([key, value]) => (
                    <div key={key} className="rounded-lg border border-border bg-secondary/35 p-4">
                      <p className="text-xs text-muted-foreground">{metricLabels[key] ?? key}</p>
                      <p className="mt-2 font-mono text-2xl font-bold text-primary">
                        {key === "roc_auc" ? value.toFixed(4) : `${value.toFixed(2)}%`}
                      </p>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState compact title="Evaluation values not provided" description="No performance values are shown until the backend returns them." />
              )}
            </Panel>

            <Panel
              title="Live Workspace Scan Statistics (Runtime Usage)"
              description="Real-time counts from your local SQLite scan history (separate from offline test metrics)."
            >
              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-lg border border-border bg-secondary/30 p-4">
                  <p className="text-xs text-muted-foreground">Live Scans Executed</p>
                  <p className="mt-1.5 font-mono text-2xl font-bold text-foreground">{records.length}</p>
                </div>
                <div className="rounded-lg border border-border bg-secondary/30 p-4">
                  <p className="text-xs text-muted-foreground">Flagged Scam / Phishing</p>
                  <p className="mt-1.5 font-mono text-2xl font-bold text-danger">{liveScamCount}</p>
                </div>
                <div className="rounded-lg border border-border bg-secondary/30 p-4">
                  <p className="text-xs text-muted-foreground">Verified Legitimate</p>
                  <p className="mt-1.5 font-mono text-2xl font-bold text-safe">{liveLegitCount}</p>
                </div>
                <div className="rounded-lg border border-border bg-secondary/30 p-4">
                  <p className="text-xs text-muted-foreground">Supported Channels</p>
                  <p className="mt-1.5 text-sm font-semibold capitalize text-foreground">
                    {info.supportedAnalysisTypes?.join(", ") ?? "message, url, batch"}
                  </p>
                </div>
              </div>
            </Panel>
          </div>

          {/* Feature Engineering & Random Forest Pipeline Explanation */}
          <div className="grid gap-6 lg:grid-cols-2">
            <Panel
              title="10,043-Dimensional Feature Extraction Pipeline"
              description="Three-branch feature engineering vector constructed for every incoming text or URL."
            >
              {info.features?.length ? (
                <div className="space-y-3">
                  {info.features.map((item, i) => (
                    <div key={item} className="flex items-start gap-3 rounded-lg border border-border bg-secondary/25 p-3.5">
                      <span className="grid size-7 shrink-0 place-items-center rounded-md bg-primary/15 font-mono text-xs font-bold text-primary">
                        0{i + 1}
                      </span>
                      <div>
                        <p className="text-sm font-semibold text-foreground">{item}</p>
                        <p className="mt-0.5 text-xs text-muted-foreground">
                          {i === 0
                            ? "Captures word-level vocabulary and two-word scam collocations (e.g., 'claim prize', 'account suspended')."
                            : i === 1
                              ? "Captures sub-word character n-grams to detect obfuscated spellings, leetspeak, and deceptive domain substrings."
                              : "Extracts 43 explicit heuristic signals: URL counts, IP literals, @ redirects, urgency keywords, currency symbols, and uppercase ratios."}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState compact title="No feature information" description="The backend did not return feature details." />
              )}
            </Panel>

            <Panel
              title="Why Class-Balanced Random Forest?"
              description="How the classifier combines ensemble tree voting with rule-based calibration."
            >
              <div className="space-y-3 text-xs leading-6 text-muted-foreground">
                <p>
                  Real-world communication datasets are naturally imbalanced (~86.6% legitimate vs. ~13.4% scam). A naive classifier can achieve high accuracy simply by predicting &ldquo;Legitimate&rdquo; for borderline threats.
                </p>
                <p>
                  SCAMLENS AI trains a <strong className="text-foreground">200-estimator Random Forest with balanced class weights</strong>, penalizing missed scam messages heavily during impurity splitting. Each decision tree votes on the 10,043-feature sparse vector to produce a calibrated base probability.
                </p>
                <div className="mt-3 rounded-lg border border-primary/25 bg-primary/5 p-3.5">
                  <p className="font-semibold text-foreground">Candidate Models Evaluated During Training:</p>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {(info.candidateModels ?? []).map((cand) => (
                      <span
                        key={cand}
                        className={cn(
                          "rounded border px-2 py-0.5 text-[11px] font-medium",
                          cand === info.model
                            ? "border-primary bg-primary/20 text-primary font-semibold"
                            : "border-border bg-secondary text-muted-foreground"
                        )}
                      >
                        {cand} {cand === info.model && "★"}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </Panel>
          </div>
        </>
      )}
    </div>
  );
}

// ============================================================================
// 7. SCAN HISTORY PAGE (Search, filter, sort, pagination, expandable row detail)
// ============================================================================
const historyFilters = ["All", "Scam", "Legitimate", "Low", "Suspicious", "High", "Very High"] as const;
type SortOption = "newest" | "oldest" | "risk_desc" | "risk_asc";
const PAGE_SIZE = 12;

export function HistoryPage() {
  const { shouldReduceMotion } = useScamlensPreferences();
  const [viewMode, setViewMode] = useState<"history" | "alert_center">("history");
  const [filter, setFilter] = useState<string>("All");
  const [query, setQuery] = useState("");
  const [sortBy, setSortBy] = useState<SortOption>("newest");
  const [page, setPage] = useState(1);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const history = useQuery(historyQueryOptions());

  const filteredAndSorted = useMemo(() => {
    const term = query.trim().toLowerCase();
    const filtered = (history.data ?? []).filter((record) => {
      const queryMatch =
        !term ||
        record.inputPreview.toLowerCase().includes(term) ||
        record.guidance.toLowerCase().includes(term) ||
        record.inputType.toLowerCase().includes(term);
      const filterMatch =
        filter === "All" ||
        (filter === "Scam"
          ? record.prediction === "Scam/Phishing"
          : filter === "Legitimate"
            ? record.prediction === "Legitimate"
            : record.riskLevel === filter);
      return queryMatch && filterMatch;
    });

    return [...filtered].sort((a, b) => {
      if (sortBy === "risk_desc") return b.riskProbability - a.riskProbability;
      if (sortBy === "risk_asc") return a.riskProbability - b.riskProbability;
      const tA = new Date(a.timestamp).getTime() || 0;
      const tB = new Date(b.timestamp).getTime() || 0;
      return sortBy === "oldest" ? tA - tB : tB - tA;
    });
  }, [history.data, filter, query, sortBy]);

  const totalPages = Math.max(1, Math.ceil(filteredAndSorted.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages);
  const paginatedRecords = filteredAndSorted.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);

  return (
    <div className="space-y-7">
      <PageHeader
        eyebrow="Persistent Audit Log"
        title="Scan History"
        description="Search, filter, sort, and inspect all message, URL, and batch scan records stored in the SQLite database."
      />

      {/* View Mode Toggle: All History vs Security Alert Center */}
      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={() => setViewMode("history")}
          className={cn(
            "flex items-center gap-2 rounded-lg border px-4 py-2 text-xs font-semibold transition-all sm:text-sm",
            viewMode === "history"
              ? "border-primary bg-primary text-primary-foreground shadow-sm"
              : "border-border bg-card text-muted-foreground hover:bg-secondary hover:text-foreground"
          )}
        >
          <History className="size-4" />
          <span>All Scan History ({history.data?.length ?? 0})</span>
        </button>

        <button
          type="button"
          onClick={() => setViewMode("alert_center")}
          className={cn(
            "flex items-center gap-2 rounded-lg border px-4 py-2 text-xs font-semibold transition-all sm:text-sm",
            viewMode === "alert_center"
              ? "border-primary bg-primary text-primary-foreground shadow-sm"
              : "border-border bg-card text-muted-foreground hover:bg-secondary hover:text-foreground"
          )}
        >
          <ShieldAlert className="size-4" />
          <span>Security Alert Center</span>
          <span className="rounded bg-danger/20 px-1.5 py-0.5 text-[10px] font-bold text-danger dark:text-rose-300">
            High-Risk Triage
          </span>
        </button>
      </div>

      {viewMode === "alert_center" ? (
        <SecurityAlertCenterView />
      ) : (
      <Panel
        title={`Persisted Analysis Records (${filteredAndSorted.length})`}
        description="Click any row to expand its full explanation summary and risk metadata."
        delay={0.04}
      >
        {/* Search, Sort & Filter Controls */}
        <div className="mb-5 space-y-3">
          <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center sm:justify-between">
            <div className="relative w-full min-w-0 flex-1 rounded-md transition-shadow duration-200 focus-within:shadow-[0_0_20px_-6px_rgba(56,189,248,0.28)] sm:max-w-lg">
              <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setPage(1);
                }}
                placeholder="Search message text, URL, or explanation..."
                className="h-10 pl-9 transition-colors duration-200 focus-visible:border-primary/60 sm:h-9"
              />
            </div>

            <div className="flex items-center justify-between gap-2 sm:justify-start">
              <div className="flex items-center gap-1.5">
                <ArrowUpDown className="size-4 text-muted-foreground" />
                <label htmlFor="history-sort" className="text-xs font-medium text-muted-foreground">
                  Sort by:
                </label>
              </div>
              <select
                id="history-sort"
                value={sortBy}
                onChange={(e) => {
                  setSortBy(e.target.value as SortOption);
                  setPage(1);
                }}
                className="h-10 rounded-md border border-border bg-secondary px-3 text-xs font-semibold text-foreground focus:border-primary focus:outline-none sm:h-9"
              >
                <option value="newest">Newest First</option>
                <option value="oldest">Oldest First</option>
                <option value="risk_desc">Highest Risk Probability</option>
                <option value="risk_asc">Lowest Risk Probability</option>
              </select>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            {historyFilters.map((item) => {
              const active = filter === item;
              return (
                <motion.button
                  key={item}
                  type="button"
                  whileHover={shouldReduceMotion ? { y: 0 } : { y: -1 }}
                  whileTap={shouldReduceMotion ? { scale: 1 } : { scale: 0.97 }}
                  onClick={() => {
                    setFilter(item);
                    setPage(1);
                  }}
                  className={cn(
                    "relative min-h-9 rounded-md border px-3 text-xs font-semibold transition-colors sm:min-h-8",
                    active
                      ? "border-primary text-primary-foreground"
                      : "border-border bg-card text-muted-foreground hover:border-primary/40 hover:text-foreground"
                  )}
                >
                  {active && (
                    <motion.span
                      layoutId="history-filter-pill"
                      transition={
                        shouldReduceMotion
                          ? { duration: 0 }
                          : { type: "spring", stiffness: 400, damping: 30 }
                      }
                      className="pointer-events-none absolute inset-0 rounded-md bg-primary shadow-sm"
                    />
                  )}
                  <span className="relative z-10">{item}</span>
                </motion.button>
              );
            })}
          </div>
        </div>

        {history.isLoading || history.isError ? (
          <HistoryStatus loading={history.isLoading} error={history.error} />
        ) : (
          <>
            {/* Mobile Expandable Card List (visible on < md screens) */}
            <div className="space-y-3 md:hidden">
              {paginatedRecords.length ? (
                paginatedRecords.map((record, idx) => {
                  const isExpanded = expandedId === record.id;
                  return (
                    <motion.div
                      key={`mobile-hist-${record.id}`}
                      initial={shouldReduceMotion ? false : { opacity: 0, y: 5 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{
                        duration: shouldReduceMotion ? 0 : 0.18,
                        delay: shouldReduceMotion ? 0 : Math.min(idx * 0.025, 0.25),
                      }}
                      className="overflow-hidden rounded-xl border border-border bg-card shadow-xs"
                    >
                      <button
                        type="button"
                        onClick={() => setExpandedId(isExpanded ? null : record.id)}
                        className="flex w-full flex-col gap-2.5 p-3.5 text-left transition-colors hover:bg-secondary/35"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-xs font-semibold text-muted-foreground">#{record.id}</span>
                            <span className="rounded border border-primary/25 bg-primary/10 px-2 py-0.5 text-[10px] font-semibold uppercase text-primary">
                              {record.inputType}
                            </span>
                            <span className="text-[11px] text-muted-foreground">{formatTime(record.timestamp)}</span>
                          </div>
                          <motion.span
                            animate={{ rotate: isExpanded ? 180 : 0 }}
                            transition={{ duration: shouldReduceMotion ? 0 : 0.2 }}
                            className="inline-flex text-muted-foreground"
                          >
                            <ChevronDown className="size-4" />
                          </motion.span>
                        </div>

                        <p className="line-clamp-2 break-words text-xs font-medium text-foreground">
                          {record.inputPreview}
                        </p>

                        <div className="flex flex-wrap items-center gap-1.5">
                          <span
                            className={cn(
                              "inline-flex rounded-full border px-2.5 py-0.5 text-[11px] font-semibold",
                              badgeClassForPrediction(record.prediction)
                            )}
                          >
                            {record.prediction}
                          </span>
                          <span
                            className={cn(
                              "inline-flex rounded-full border px-2.5 py-0.5 text-[11px] font-semibold",
                              badgeClassForRisk(record.riskLevel)
                            )}
                          >
                            {record.riskLevel} ({formatProbability(record.riskProbability)})
                          </span>
                        </div>
                      </button>

                      <AnimatePresence initial={false}>
                        {isExpanded && (
                          <motion.div
                            initial={shouldReduceMotion ? false : { opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: "auto" }}
                            exit={shouldReduceMotion ? { opacity: 1 } : { opacity: 0, height: 0 }}
                            transition={{ duration: shouldReduceMotion ? 0 : 0.22, ease: "easeOut" }}
                            className="overflow-hidden border-t border-border bg-secondary/20"
                          >
                            <div className="space-y-3 p-3.5 text-xs">
                              <div>
                                <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                                  Full Submitted Content
                                </p>
                                <p className="mt-1 break-all rounded border border-border bg-card p-2.5 font-mono text-xs text-foreground">
                                  {record.inputPreview}
                                </p>
                              </div>
                              <div>
                                <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                                  Explanation &amp; Security Guidance
                                </p>
                                <p className="mt-1 leading-relaxed text-muted-foreground">
                                  {record.guidance || "Classified by SCAMLENS AI Random Forest pipeline."}
                                </p>
                              </div>
                              <div className="grid grid-cols-2 gap-2">
                                <div className="rounded border border-border bg-card p-2">
                                  <span className="text-[10px] text-muted-foreground">Audit ID</span>
                                  <p className="font-mono font-semibold text-foreground">#{record.id}</p>
                                </div>
                                <div className="rounded border border-border bg-card p-2">
                                  <span className="text-[10px] text-muted-foreground">Model</span>
                                  <p className="truncate font-semibold text-foreground">{record.model}</p>
                                </div>
                              </div>
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </motion.div>
                  );
                })
              ) : (
                <EmptyState
                  compact
                  title={history.data?.length ? "No matching scans" : "No scan history"}
                  description={
                    history.data?.length
                      ? "Adjust the search query or filter pills above."
                      : "The backend returned no completed analyses."
                  }
                />
              )}
            </div>

            {/* Desktop Table (visible on md+ screens) */}
            <div className="hidden overflow-x-auto md:block">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-14">ID</TableHead>
                    <TableHead>Date / Time</TableHead>
                    <TableHead>Channel</TableHead>
                    <TableHead>Submitted Input Preview</TableHead>
                    <TableHead>Prediction</TableHead>
                    <TableHead>Probability</TableHead>
                    <TableHead>Risk Level</TableHead>
                    <TableHead className="w-10"></TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {paginatedRecords.length ? (
                    paginatedRecords.map((record, idx) => {
                      const isExpanded = expandedId === record.id;
                      return (
                        <Fragment key={record.id}>
                          <motion.tr
                            initial={shouldReduceMotion ? false : { opacity: 0, y: 5 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{
                              duration: shouldReduceMotion ? 0 : 0.18,
                              delay: shouldReduceMotion ? 0 : Math.min(idx * 0.025, 0.25),
                            }}
                            onClick={() => setExpandedId(isExpanded ? null : record.id)}
                            className="cursor-pointer border-b border-border transition-colors hover:bg-secondary/40"
                          >
                            <TableCell className="font-mono text-xs text-muted-foreground">#{record.id}</TableCell>
                            <TableCell className="whitespace-nowrap text-xs">{formatTime(record.timestamp)}</TableCell>
                            <TableCell>
                              <span className="rounded border border-primary/25 bg-primary/10 px-2 py-0.5 text-[10px] font-semibold uppercase text-primary">
                                {record.inputType}
                              </span>
                            </TableCell>
                            <TableCell className="max-w-80 truncate text-xs font-medium text-foreground">
                              {record.inputPreview}
                            </TableCell>
                            <TableCell>
                              <span
                                className={cn(
                                  "inline-flex rounded-full border px-2.5 py-0.5 text-[11px] font-semibold",
                                  badgeClassForPrediction(record.prediction)
                                )}
                              >
                                {record.prediction}
                              </span>
                            </TableCell>
                            <TableCell className="font-mono text-xs font-semibold">
                              {formatProbability(record.riskProbability)}
                            </TableCell>
                            <TableCell>
                              <span
                                className={cn(
                                  "inline-flex rounded-full border px-2.5 py-0.5 text-[11px] font-semibold",
                                  badgeClassForRisk(record.riskLevel)
                                )}
                              >
                                {record.riskLevel}
                              </span>
                            </TableCell>
                            <TableCell>
                              <motion.span
                                animate={{ rotate: isExpanded ? 180 : 0 }}
                                transition={{ duration: shouldReduceMotion ? 0 : 0.2 }}
                                className="inline-flex text-muted-foreground"
                              >
                                <ChevronDown className="size-4" />
                              </motion.span>
                            </TableCell>
                          </motion.tr>
                          <AnimatePresence initial={false}>
                            {isExpanded && (
                              <TableRow key={`${record.id}-detail`} className="bg-secondary/20">
                                <TableCell colSpan={8} className="p-0">
                                  <motion.div
                                    initial={shouldReduceMotion ? false : { opacity: 0, height: 0 }}
                                    animate={{ opacity: 1, height: "auto" }}
                                    exit={shouldReduceMotion ? { opacity: 1 } : { opacity: 0, height: 0 }}
                                    transition={{ duration: shouldReduceMotion ? 0 : 0.22, ease: "easeOut" }}
                                    className="overflow-hidden"
                                  >
                                    <div className="p-4">
                                      <div className="grid gap-3 rounded-lg border border-border bg-card p-4 sm:grid-cols-2">
                                        <div className="sm:col-span-2">
                                          <p className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                                            Full Submitted Content
                                          </p>
                                          <p className="mt-1 break-all rounded border border-border bg-secondary/30 p-2.5 font-mono text-xs text-foreground">
                                            {record.inputPreview}
                                          </p>
                                        </div>
                                        <div>
                                          <p className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                                            Explanation &amp; Security Guidance
                                          </p>
                                          <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
                                            {record.guidance || "Classified by SCAMLENS AI Random Forest pipeline."}
                                          </p>
                                        </div>
                                        <div className="grid grid-cols-2 gap-2 text-xs">
                                          <div className="rounded border border-border bg-secondary/20 p-2.5">
                                            <span className="text-[10px] text-muted-foreground">Audit ID</span>
                                            <p className="font-mono font-semibold text-foreground">#{record.id}</p>
                                          </div>
                                          <div className="rounded border border-border bg-secondary/20 p-2.5">
                                            <span className="text-[10px] text-muted-foreground">Model</span>
                                            <p className="truncate font-semibold text-foreground">{record.model}</p>
                                          </div>
                                        </div>

                                        {/* Incident Dossier Download */}
                                        <div className="sm:col-span-2 flex flex-wrap items-center justify-between gap-2 border-t border-border pt-3">
                                          <div className="flex items-center gap-2">
                                            <span className="text-[11px] text-muted-foreground">Triage Status:</span>
                                            <span className="rounded border border-primary/20 bg-primary/10 px-2 py-0.5 text-[10px] font-semibold uppercase text-primary">
                                              {record.reviewStatus ?? "unreviewed"}
                                            </span>
                                            {record.reviewNotes && (
                                              <span className="text-xs text-muted-foreground italic truncate max-w-xs">
                                                — "{record.reviewNotes}"
                                              </span>
                                            )}
                                          </div>
                                          <Button
                                            size="sm"
                                            variant="outline"
                                            onClick={(e) => {
                                              e.stopPropagation();
                                              void scamlensApi.downloadIncidentPdf(record.id);
                                            }}
                                            className="h-8 gap-1.5 text-xs"
                                          >
                                            <Download className="size-3.5 text-primary" />
                                            <span>Export Incident PDF</span>
                                          </Button>
                                        </div>
                                      </div>
                                    </div>
                                  </motion.div>
                                </TableCell>
                              </TableRow>
                            )}
                          </AnimatePresence>
                        </Fragment>
                      );
                    })
                  ) : (
                    <TableRow>
                      <TableCell colSpan={8}>
                        <EmptyState
                          compact
                          title={history.data?.length ? "No matching scans" : "No scan history"}
                          description={
                            history.data?.length
                              ? "Adjust the search query or filter pills above."
                              : "The backend returned no completed analyses."
                          }
                        />
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </div>

            {/* Pagination Footer */}
            {filteredAndSorted.length > PAGE_SIZE && (
              <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-border pt-4 text-xs text-muted-foreground">
                <span>
                  Showing {(safePage - 1) * PAGE_SIZE + 1}–
                  {Math.min(safePage * PAGE_SIZE, filteredAndSorted.length)} of {filteredAndSorted.length} records
                </span>
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={safePage <= 1}
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                    className="min-h-9 sm:min-h-8"
                  >
                    <ChevronLeft className="size-4" /> Previous
                  </Button>
                  <span className="font-mono font-semibold text-foreground">
                    Page {safePage} of {totalPages}
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={safePage >= totalPages}
                    onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                    className="min-h-9 sm:min-h-8"
                  >
                    Next <ChevronRight className="size-4" />
                  </Button>
                </div>
              </div>
            )}
          </>
        )}
      </Panel>
      )}
    </div>
  );
}

// ============================================================================
// 8. REPORTS PAGE (Real PDF Report Generator & CSV Audit Export)
// ============================================================================
const REPORT_SCOPES = [
  { id: "all", label: "All Completed Scans" },
  { id: "scam", label: "Scam / Phishing Detections Only" },
  { id: "legitimate", label: "Legitimate Scans Only" },
  { id: "high_risk", label: "High & Very High Risk Only" },
  { id: "message", label: "Message Scans Only (SMS / Email)" },
  { id: "url", label: "Static URL Scans Only" },
] as const;

const REPORT_PERIODS = [
  { days: 0, label: "All Time" },
  { days: 7, label: "Last 7 Days" },
  { days: 30, label: "Last 30 Days" },
  { days: 90, label: "Last 90 Days" },
] as const;

export function ReportsPage() {
  const { shouldReduceMotion } = useScamlensPreferences();
  const history = useQuery(historyQueryOptions());
  const modelInfo = useQuery(modelInfoQueryOptions());
  const allRecords = history.data ?? [];

  const [scope, setScope] = useState<string>("all");
  const [days, setDays] = useState<number>(0);
  const [pdfStatus, setPdfStatus] = useState<RequestStatus>("idle");
  const [pdfMessage, setPdfMessage] = useState<string>("");

  const filteredRecords = useMemo(() => {
    const now = Date.now();
    return allRecords.filter((r) => {
      if (days > 0) {
        const ts = new Date(r.timestamp).getTime();
        if (!Number.isNaN(ts) && now - ts > days * 86_400_000) return false;
      }
      if (scope === "scam") return r.prediction === "Scam/Phishing";
      if (scope === "legitimate") return r.prediction === "Legitimate";
      if (scope === "high_risk") return r.riskLevel === "High" || r.riskLevel === "Very High";
      if (scope === "message") return r.inputType === "message";
      if (scope === "url") return r.inputType === "url";
      return true;
    });
  }, [allRecords, scope, days]);

  const scamCount = filteredRecords.filter((r) => r.prediction === "Scam/Phishing").length;
  const legitCount = filteredRecords.filter((r) => r.prediction === "Legitimate").length;
  const highRiskCount = filteredRecords.filter((r) => r.riskLevel === "High" || r.riskLevel === "Very High").length;
  const scamRate = filteredRecords.length ? (scamCount / filteredRecords.length) * 100 : 0;

  async function handleDownloadPdf() {
    setPdfStatus("loading");
    setPdfMessage("");
    try {
      const { filename, size } = await scamlensApi.downloadReportPdf({
        scope,
        days,
        limit: 100,
      });
      setPdfStatus("success");
      setPdfMessage(`Downloaded ${filename} (${formatFileSize(size)}) from backend PDF generator.`);
    } catch (err) {
      setPdfStatus("error");
      setPdfMessage(apiError(err));
    }
  }

  function handleExportCsv() {
    if (!filteredRecords.length) return;
    const headers = [
      "Scan ID",
      "Timestamp",
      "Channel",
      "Prediction",
      "Risk Probability (%)",
      "Risk Level",
      "Submitted Content",
      "Explanation / Guidance",
      "Classifier Model",
    ];
    const rows = filteredRecords.map((r) => [
      r.id,
      r.timestamp,
      r.inputType,
      r.prediction,
      r.riskProbability.toFixed(2),
      r.riskLevel,
      r.inputPreview,
      r.guidance,
      r.model,
    ]);
    const content = [headers, ...rows].map((row) => row.map(csvCell).join(",")).join("\n");
    const url = URL.createObjectURL(new Blob([content], { type: "text/csv;charset=utf-8;" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `SCAMLENS_AI_Audit_Records_${scope}_${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  }

  const scopeLabel = REPORT_SCOPES.find((s) => s.id === scope)?.label ?? "All Completed Scans";
  const periodLabel = REPORT_PERIODS.find((p) => p.days === days)?.label ?? "All Time";

  return (
    <div className="space-y-7">
      <PageHeader
        eyebrow="Executive Security Documentation"
        title="Security Audit Reports"
        description="Configure report scope and time window, preview real calculated statistics and risk breakdowns, and download a formatted multi-page PDF report or CSV dataset."
        actions={
          <div className="flex w-full flex-wrap items-center gap-2.5 sm:w-auto">
            <Button
              onClick={handleDownloadPdf}
              disabled={pdfStatus === "loading"}
              className="min-h-10 flex-1 transition-transform active:scale-97 sm:min-h-9 sm:flex-initial"
            >
              {pdfStatus === "loading" ? <Loader2 className="size-4 animate-spin" /> : <Download className="size-4" />}
              {pdfStatus === "loading" ? "Generating PDF..." : "Download PDF Report"}
            </Button>
            <Button
              variant="outline"
              disabled={!filteredRecords.length}
              onClick={handleExportCsv}
              className="min-h-10 flex-1 transition-transform active:scale-97 sm:min-h-9 sm:flex-initial"
            >
              <FileSpreadsheet className="size-4" /> Export Records CSV ({filteredRecords.length})
            </Button>
          </div>
        }
      />

      {pdfStatus !== "idle" && (
        <ApiNotice
          kind={pdfStatus}
          message={
            pdfStatus === "loading"
              ? "Requesting native PDF report compilation from GET /api/reports/pdf..."
              : pdfMessage
          }
        />
      )}

      {/* Report Configuration & Live Preview Split */}
      <div className="grid gap-6 xl:grid-cols-[360px_1fr]">
        {/* Left Column: Report Filters & Metadata */}
        <div className="space-y-6">
          <Panel title="Report Configuration" description="Filter the records included in the generated PDF and CSV export." delay={0.04}>
            <div className="space-y-4">
              <div>
                <label htmlFor="report-scope" className="mb-1.5 block text-xs font-semibold text-foreground">
                  Report Scope / Category
                </label>
                <select
                  id="report-scope"
                  value={scope}
                  onChange={(e) => {
                    setScope(e.target.value);
                    setPdfStatus("idle");
                  }}
                  className="h-10 w-full rounded-md border border-border bg-secondary px-3 text-xs font-semibold text-foreground focus:border-primary focus:outline-none"
                >
                  {REPORT_SCOPES.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.label}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label htmlFor="report-period" className="mb-1.5 block text-xs font-semibold text-foreground">
                  Date / Time Window
                </label>
                <select
                  id="report-period"
                  value={days}
                  onChange={(e) => {
                    setDays(Number(e.target.value));
                    setPdfStatus("idle");
                  }}
                  className="h-10 w-full rounded-md border border-border bg-secondary px-3 text-xs font-semibold text-foreground focus:border-primary focus:outline-none"
                >
                  {REPORT_PERIODS.map((p) => (
                    <option key={p.days} value={p.days}>
                      {p.label}
                    </option>
                  ))}
                </select>
              </div>

              <div className="rounded-lg border border-border bg-secondary/30 p-3.5 text-xs space-y-1.5">
                <div className="flex justify-between gap-2">
                  <span className="text-muted-foreground">Selected Scope:</span>
                  <span className="text-right font-semibold text-foreground">{scopeLabel}</span>
                </div>
                <div className="flex justify-between gap-2">
                  <span className="text-muted-foreground">Time Window:</span>
                  <span className="text-right font-semibold text-foreground">{periodLabel}</span>
                </div>
                <div className="flex justify-between gap-2">
                  <span className="text-muted-foreground">Matching Records:</span>
                  <span className="font-mono font-bold text-primary">{filteredRecords.length}</span>
                </div>
                <div className="flex justify-between gap-2">
                  <span className="text-muted-foreground">Active Classifier:</span>
                  <span className="text-right font-semibold text-foreground">{modelInfo.data?.model ?? "Random Forest"}</span>
                </div>
              </div>

              <Button className="min-h-10 w-full transition-transform active:scale-98" onClick={handleDownloadPdf} disabled={pdfStatus === "loading"}>
                {pdfStatus === "loading" ? <Loader2 className="size-4 animate-spin" /> : <FileText className="size-4" />}
                Generate &amp; Download PDF
              </Button>
            </div>
          </Panel>

          <Panel title="Risk Tier Breakdown" description="Distribution inside the selected report scope." delay={0.08}>
            {filteredRecords.length ? (
              <HistoryBars records={filteredRecords} mode="risk" />
            ) : (
              <EmptyState compact title="No records in scope" description="No scans match the current filter." />
            )}
          </Panel>
        </div>

        {/* Right Column: Live Document Preview */}
        <Panel
          title="SCAMLENS AI — Security Analysis Report Preview"
          description="Live preview of the executive summary and audit table that will be compiled into your PDF download."
          delay={0.06}
        >
          <motion.div
            key={`${scope}-${days}`}
            initial={shouldReduceMotion ? false : { opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: shouldReduceMotion ? 0 : 0.22 }}
            className="space-y-6 rounded-xl border border-border bg-secondary/15 p-3.5 sm:p-5"
          >
            {/* Document Header */}
            <div className="flex flex-wrap items-start justify-between gap-4 border-b border-border pb-4">
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-widest text-primary">
                  Official Threat Intelligence Audit
                </p>
                <h3 className="mt-1 text-base font-bold text-foreground sm:text-lg">
                  SCAMLENS AI Security Analysis Report
                </h3>
                <p className="mt-0.5 text-xs text-muted-foreground">
                  Scope: <strong>{scopeLabel}</strong> • Window: <strong>{periodLabel}</strong>
                </p>
              </div>
              <div className="flex items-center gap-2 rounded-lg border border-primary/30 bg-primary/10 px-3 py-2 text-xs font-semibold text-primary">
                <ShieldCheck className="size-5" />
                <span>Verified ML Audit</span>
              </div>
            </div>

            {/* 4 Executive Summary KPIs */}
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <motion.div
                whileHover={shouldReduceMotion ? { y: 0 } : { y: -2 }}
                className="rounded-lg border border-border bg-card p-3.5 transition-colors hover:border-primary/35"
              >
                <p className="text-[11px] text-muted-foreground">Total Scans in Scope</p>
                <p className="mt-1 font-mono text-xl font-bold text-foreground">{filteredRecords.length}</p>
              </motion.div>
              <motion.div
                whileHover={shouldReduceMotion ? { y: 0 } : { y: -2 }}
                className="rounded-lg border border-danger/30 bg-danger/10 p-3.5 transition-colors hover:border-danger/50"
              >
                <p className="text-[11px] text-danger">Scam / Phishing</p>
                <p className="mt-1 font-mono text-xl font-bold text-danger">
                  {scamCount} ({formatProbability(scamRate)})
                </p>
              </motion.div>
              <motion.div
                whileHover={shouldReduceMotion ? { y: 0 } : { y: -2 }}
                className="rounded-lg border border-safe/30 bg-safe/10 p-3.5 transition-colors hover:border-safe/50"
              >
                <p className="text-[11px] text-safe">Legitimate Verified</p>
                <p className="mt-1 font-mono text-xl font-bold text-safe">{legitCount}</p>
              </motion.div>
              <motion.div
                whileHover={shouldReduceMotion ? { y: 0 } : { y: -2 }}
                className="rounded-lg border border-warning/30 bg-warning/10 p-3.5 transition-colors hover:border-warning/50"
              >
                <p className="text-[11px] text-warning">High / Very High Risk</p>
                <p className="mt-1 font-mono text-xl font-bold text-warning">{highRiskCount}</p>
              </motion.div>
            </div>

            {/* Detailed Audit Records Table */}
            <div>
              <div className="mb-2.5 flex flex-wrap items-center justify-between gap-2">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Detailed Audit Records ({filteredRecords.length})
                </h4>
                <span className="text-[11px] text-muted-foreground">
                  Up to 100 records included in PDF table
                </span>
              </div>

              {filteredRecords.length ? (
                <>
                  {/* Mobile Card List (< md) */}
                  <div className="space-y-2.5 md:hidden">
                    {filteredRecords.slice(0, 12).map((r) => (
                      <div key={`rep-mob-${r.id}`} className="rounded-lg border border-border bg-card p-3 space-y-2">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <span className="font-mono text-xs text-muted-foreground">
                            #{r.id} • {formatTime(r.timestamp)}
                          </span>
                          <span className="uppercase text-[10px] font-semibold text-primary">{r.inputType}</span>
                        </div>
                        <p className="break-words text-xs font-medium text-foreground">{r.inputPreview}</p>
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span
                            className={cn(
                              "inline-flex rounded-full border px-2 py-0.5 text-[10px] font-semibold",
                              badgeClassForPrediction(r.prediction)
                            )}
                          >
                            {r.prediction}
                          </span>
                          <span
                            className={cn(
                              "inline-flex rounded-full border px-2 py-0.5 text-[10px] font-semibold",
                              badgeClassForRisk(r.riskLevel)
                            )}
                          >
                            {r.riskLevel} ({formatProbability(r.riskProbability)})
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Desktop Table (md+) */}
                  <div className="hidden overflow-x-auto rounded-lg border border-border bg-card md:block">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead className="w-14">ID</TableHead>
                          <TableHead>Timestamp</TableHead>
                          <TableHead>Type</TableHead>
                          <TableHead>Verdict</TableHead>
                          <TableHead>Risk</TableHead>
                          <TableHead>Content Preview</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {filteredRecords.slice(0, 12).map((r, idx) => (
                          <motion.tr
                            key={r.id}
                            initial={shouldReduceMotion ? false : { opacity: 0, y: 4 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{
                              duration: shouldReduceMotion ? 0 : 0.18,
                              delay: shouldReduceMotion ? 0 : idx * 0.025,
                            }}
                            className="border-b border-border transition-colors hover:bg-secondary/35"
                          >
                            <TableCell className="font-mono text-xs text-muted-foreground">#{r.id}</TableCell>
                            <TableCell className="whitespace-nowrap text-xs">{formatTime(r.timestamp)}</TableCell>
                            <TableCell className="uppercase text-xs font-semibold text-primary">{r.inputType}</TableCell>
                            <TableCell>
                              <span
                                className={cn(
                                  "inline-flex rounded-full border px-2 py-0.5 text-[10px] font-semibold",
                                  badgeClassForPrediction(r.prediction)
                                )}
                              >
                                {r.prediction}
                              </span>
                            </TableCell>
                            <TableCell>
                              <span
                                className={cn(
                                  "inline-flex rounded-full border px-2 py-0.5 text-[10px] font-semibold",
                                  badgeClassForRisk(r.riskLevel)
                                )}
                              >
                                {r.riskLevel} ({formatProbability(r.riskProbability)})
                              </span>
                            </TableCell>
                            <TableCell className="max-w-64 truncate text-xs text-foreground">
                              {r.inputPreview}
                            </TableCell>
                          </motion.tr>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                </>
              ) : (
                <EmptyState
                  compact
                  title="No Scan Records Match Selected Period / Scope"
                  description="Try switching the Report Scope to 'All Completed Scans' or Time Window to 'All Time'."
                />
              )}
            </div>
          </motion.div>
        </Panel>
      </div>
    </div>
  );
}

// ============================================================================
// 9. ABOUT PROJECT PAGE (Academic & Technical BCA Major Project Overview)
// ============================================================================
export function AboutPage() {
  const techStack = [
    { category: "Frontend UI", items: ["React 19", "TypeScript", "TanStack Start / Router", "Tailwind CSS", "Motion (Framer)"] },
    { category: "Backend & API", items: ["Python 3.12", "FastAPI", "Pydantic v2", "Uvicorn ASGI", "Multipart CSV & Native PDF"] },
    { category: "Machine Learning", items: ["scikit-learn", "Class-Balanced Random Forest", "Word & Char TF-IDF", "43 Lexical & URL Signals"] },
    { category: "Storage & Auth", items: ["SQLite3 Audit Persistence", "Supabase Auth (Email/Session)", "Zero-Execution Static URL Guard"] },
  ] as const;

  const architectureStages = [
    {
      step: "01",
      title: "User Input & Auth Layer",
      desc: "Authenticated analysts submit suspicious SMS/email text, URLs, or bulk CSV files through the React workspace.",
    },
    {
      step: "02",
      title: "Text Normalization & Static URL Parser",
      desc: "The FastAPI service sanitizes input and parses URL structure lexically without making any external network requests.",
    },
    {
      step: "03",
      title: "10,043-Feature Vectorizer",
      desc: "Combines 5,000 word n-grams, 5,000 character n-grams, and 43 engineered indicators (urgency, prize lures, IP hosts, shorteners).",
    },
    {
      step: "04",
      title: "Random Forest & Risk Calibration",
      desc: "200 decision trees compute base scam probability, refined by structural risk rules into Low, Suspicious, High, or Very High tiers.",
    },
    {
      step: "05",
      title: "SQLite Audit & PDF Reporting",
      desc: "Every scan is logged to SQLite with explainable indicators and can be exported as a formatted PDF or CSV audit report.",
    },
  ] as const;

  return (
    <div className="space-y-7">
      <PageHeader
        eyebrow="Final-Year BCA Major Project Documentation"
        title="About SCAMLENS AI"
        description="An end-to-end Intelligent Scam and Phishing Detection System combining classical NLP feature engineering, ensemble machine learning, explainable risk indicators, and safe static URL inspection."
      />

      {/* Project Overview & Core Objectives */}
      <div className="grid gap-6 lg:grid-cols-[1.25fr_1fr]">
        <Panel title="Project Overview & Problem Statement">
          <div className="space-y-3 text-sm leading-7 text-muted-foreground">
            <p>
              Phishing links, deceptive SMS alerts (&ldquo;smishing&rdquo;), fraudulent KYC suspension warnings, and lottery lures represent some of the most widespread cybersecurity threats facing everyday users and organizations. Traditional blacklists often fail against newly registered domains orZero-Day message templates.
            </p>
            <p>
              <strong className="text-foreground">SCAMLENS AI</strong> addresses this gap by inspecting the intrinsic linguistic, structural, and lexical patterns of messages and URLs before a user clicks. Rather than acting as a black box, the system pairs every machine-learning probability score with human-readable <strong className="text-foreground">Detection Indicators</strong> and actionable <strong className="text-foreground">Security Guidance</strong>.
            </p>
          </div>
        </Panel>

        <Panel title="Key Engineering Objectives">
          <ul className="space-y-2.5 text-xs leading-6 text-muted-foreground">
            {[
              "Achieve >98% classification accuracy and high recall on real-world SMS & phishing datasets using interpretable ensemble models.",
              "Perform 100% static, zero-execution URL analysis so malicious links are never visited or triggered during inspection.",
              "Provide explainable risk tiers (Low, Suspicious, High, Very High) backed by specific lexical triggers.",
              "Support high-throughput Batch CSV dataset scanning with user-selectable columns and downloadable results.",
              "Generate standalone, multi-page PDF security audit reports directly from the persisted SQLite history.",
            ].map((obj) => (
              <li key={obj} className="flex items-start gap-2.5">
                <CheckCircle2 className="mt-1 size-4 shrink-0 text-primary" />
                <span>{obj}</span>
              </li>
            ))}
          </ul>
        </Panel>
      </div>

      {/* System Architecture Flow */}
      <Panel
        title="System Architecture & Processing Pipeline"
        description="Five-stage data flow from frontend submission to machine-learning inference and persistent reporting."
      >
        <div className="grid gap-4 md:grid-cols-5">
          {architectureStages.map((stage) => (
            <div key={stage.step} className="relative rounded-xl border border-border bg-secondary/30 p-4">
              <span className="inline-block rounded bg-primary/15 px-2 py-0.5 font-mono text-xs font-bold text-primary">
                STAGE {stage.step}
              </span>
              <h3 className="mt-2.5 text-sm font-semibold text-foreground">{stage.title}</h3>
              <p className="mt-1.5 text-xs leading-relaxed text-muted-foreground">{stage.desc}</p>
            </div>
          ))}
        </div>
      </Panel>

      {/* Technology Stack */}
      <Panel title="Technology Stack" description="Modern full-stack architecture connecting a type-safe React frontend with a Python ML microservice.">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {techStack.map((group) => (
            <div key={group.category} className="rounded-lg border border-border bg-secondary/20 p-4">
              <p className="text-xs font-semibold uppercase tracking-wider text-primary">{group.category}</p>
              <div className="mt-3 flex flex-wrap gap-1.5">
                {group.items.map((item) => (
                  <span key={item} className="rounded border border-border bg-card px-2.5 py-1 text-xs font-medium text-foreground">
                    {item}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </Panel>

      {/* Limitations & Future Scope */}
      <div className="grid gap-6 lg:grid-cols-2">
        <Panel title="Current Scope & Known Limitations">
          <ul className="space-y-3 text-xs leading-6 text-muted-foreground">
            {[
              "Static URL inspection evaluates lexical and structural signals only; it does not fetch live WHOIS records, DNS certificates, or rendered DOM content.",
              "Model predictions reflect patterns learned from the 5,574-sample English training corpus; regional or transliterated languages may require additional training data.",
              "Legitimate marketing messages that heavily use urgency or prize-style phrasing may occasionally trigger a 'Suspicious' warning.",
              "SCAMLENS AI is a decision-support tool designed to assist human judgment rather than replace enterprise network firewalls.",
            ].map((item) => (
              <li key={item} className="flex items-start gap-2.5">
                <AlertTriangle className="mt-1 size-4 shrink-0 text-warning" />
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </Panel>

        <Panel title="Future Enhancements">
          <div className="grid gap-3 sm:grid-cols-2">
            {[
              ["Multilingual Regional NLP", "Extend TF-IDF and transformer embeddings to Hindi, Kannada, Tamil, and Hinglish SMS lures."],
              ["Live Domain Age & TLS Probe", "Optional sandboxed WHOIS and certificate transparency checks for newly registered domains."],
              ["Browser Extension Guard", "Real-time hover inspection for webmail clients and social media messaging tabs."],
              ["SHAP Token Attribution", "Word-by-word Shapley additive explanations highlighting exact token weights inline."],
            ].map(([title, desc]) => (
              <div key={title} className="rounded-lg border border-border bg-secondary/30 p-3.5">
                <BrainCircuit className="size-4 text-primary" />
                <p className="mt-2 text-xs font-semibold text-foreground">{title}</p>
                <p className="mt-1 text-[11px] leading-relaxed text-muted-foreground">{desc}</p>
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </div>
  );
}
