import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { motion, AnimatePresence } from "motion/react";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  BrainCircuit,
  CheckCircle2,
  Cpu,
  Database,
  FileSearch,
  Info,
  Layers,
  LockKeyhole,
  Monitor,
  Moon,
  RefreshCw,
  RotateCcw,
  Server,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Sun,
  Trash2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { ApiNotice, EmptyState, PageHeader, Panel } from "./primitives";
import { ScamlensApiError, scamlensApi } from "@/lib/scamlens-api";
import { healthQueryOptions, historyQueryOptions, modelInfoQueryOptions } from "@/lib/scamlens-queries";
import { useScamlensPreferences } from "@/lib/scamlens-preferences";
import { cn } from "@/lib/utils";

export type SettingsInfoTab = "ai-models" | "about" | "settings";

function apiError(error: unknown) {
  return error instanceof ScamlensApiError || error instanceof Error
    ? error.message
    : "The backend could not complete this request.";
}

const TECH_STACK = [
  {
    category: "Frontend UI & Routing",
    items: ["React 19", "TypeScript 5.8", "TanStack Start / Router", "Tailwind CSS v4", "Motion (Framer)"],
  },
  {
    category: "Backend & REST API",
    items: ["Python 3.12", "FastAPI", "Pydantic v2", "Uvicorn ASGI", "Multipart CSV & Native PDF 1.4"],
  },
  {
    category: "Machine Learning Engine",
    items: ["scikit-learn", "Class-Balanced Random Forest (200 trees)", "Word & Char TF-IDF", "43 Lexical & URL Signals"],
  },
  {
    category: "Storage, Auth & Safety",
    items: ["SQLite3 Audit Persistence", "Supabase Auth (Email/Session)", "Zero-Execution Static URL Guard"],
  },
] as const;

const ARCHITECTURE_STAGES = [
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

const SYSTEM_COMPARISON = [
  {
    aspect: "Detection Mechanism",
    existing: "Static domain blacklists or basic keyword filters that fail when attackers slightly alter spelling or register new domains.",
    proposed: "10,043-feature ensemble Random Forest combining word n-grams, character n-grams, and 43 structural/lexical heuristics.",
  },
  {
    aspect: "Explainability",
    existing: "Opaque binary ('Safe' / 'Spam') labels that give users no reason why a message or link was flagged.",
    proposed: "Granular probability score, 4-tier Risk Level, human-readable Detection Indicators, and actionable Security Guidance.",
  },
  {
    aspect: "URL Inspection Safety",
    existing: "Often requires visiting or previewing the destination page, exposing the client to drive-by downloads or tracking.",
    proposed: "100% zero-execution static lexical inspection—malicious URLs are never fetched, rendered, or opened.",
  },
  {
    aspect: "Bulk & Audit Reporting",
    existing: "Single-message checking with no persistent audit trail or formal exportable documentation.",
    proposed: "Column-selectable Batch CSV Scanner, SQLite audit history, and multi-page native PDF Security Analysis Reports.",
  },
] as const;

const MAIN_MODULES = [
  {
    name: "Security Dashboard",
    desc: "Real-time KPI telemetry, risk tier distribution, classification balance, recent activity log, and live API diagnostics.",
  },
  {
    name: "Message Analyzer",
    desc: "Inspects SMS, WhatsApp, email, and chat content for social-engineering urgency, prize lures, KYC threats, and embedded links.",
  },
  {
    name: "Static URL Analyzer",
    desc: "Evaluates 9 structural URL dimensions (HTTPS, length, domain tokens, subdomains, IP literals, @ redirects, shorteners) safely offline.",
  },
  {
    name: "Batch CSV Scanner",
    desc: "Drag-and-drop dataset upload with custom column selection, row-level validation, batch ML classification, and CSV export.",
  },
  {
    name: "Learn & Practise Academy",
    desc: "Interactive 6-topic threat dissection guides and a 44-scenario randomized phishing detection quiz with phrase-spotting.",
  },
  {
    name: "Analytics & PDF Reports",
    desc: "Date/channel-filtered visual analytics plus downloadable multi-page PDF and CSV security audit reports.",
  },
] as const;

export function SettingsInformationPage({ initialTab = "ai-models" }: { initialTab?: SettingsInfoTab }) {
  const [activeTab, setActiveTab] = useState<SettingsInfoTab>(initialTab);
  const [quizResetDone, setQuizResetDone] = useState(false);

  useEffect(() => {
    setActiveTab(initialTab);
  }, [initialTab]);

  const queryClient = useQueryClient();
  const health = useQuery(healthQueryOptions());
  const modelQuery = useQuery(modelInfoQueryOptions());
  const history = useQuery(historyQueryOptions());
  const {
    prefs,
    osReducedMotion,
    shouldReduceMotion,
    resolvedTheme,
    setThemeMode,
    updatePreferences,
    resetPreferences,
  } = useScamlensPreferences();

  const info = modelQuery.data;
  const records = history.data ?? [];
  const connected = health.isSuccess && health.data.healthy;

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

  function handleClearQuizStorage() {
    try {
      window.localStorage.removeItem("scamlens_learn_practise_v1");
      setQuizResetDone(true);
      setTimeout(() => setQuizResetDone(false), 3500);
    } catch {
      // Ignore storage errors
    }
  }

  return (
    <div className="space-y-7">
      <PageHeader
        eyebrow="System Intelligence, Documentation & Preferences"
        title="Settings & Information"
        description="Explore the trained Random Forest machine-learning pipeline, review comprehensive BCA major project documentation and system architecture, and configure workspace preferences."
        actions={
          <div className="grid w-full grid-cols-1 gap-1 rounded-xl border border-border bg-card p-1 shadow-sm sm:flex sm:w-auto sm:flex-wrap sm:items-center sm:gap-1.5">
            {(
              [
                { id: "ai-models", label: "AI & Models", icon: BrainCircuit },
                { id: "about", label: "About Project", icon: Info },
                { id: "settings", label: "Application Settings", icon: Settings },
              ] as const
            ).map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setActiveTab(tab.id)}
                  className={cn(
                    "relative flex min-h-10 items-center justify-center gap-2 rounded-lg px-3.5 py-2 text-xs font-semibold transition-colors sm:min-h-9",
                    isActive
                      ? "text-primary-foreground"
                      : "text-muted-foreground hover:bg-secondary/60 hover:text-foreground"
                  )}
                >
                  {isActive && (
                    <motion.span
                      layoutId="settings-info-active-tab"
                      transition={
                        shouldReduceMotion
                          ? { duration: 0 }
                          : { type: "spring", stiffness: 380, damping: 30 }
                      }
                      className="pointer-events-none absolute inset-0 rounded-lg bg-primary shadow-sm"
                    />
                  )}
                  <Icon className="relative z-10 size-3.5 shrink-0" />
                  <span className="relative z-10">{tab.label}</span>
                </button>
              );
            })}
          </div>
        }
      />

      <AnimatePresence mode="wait">
        {/* =================================================================== */}
        {/* TAB A: AI & MODELS                                                  */}
        {/* =================================================================== */}
        {activeTab === "ai-models" && (
          <motion.div
            key="tab-ai-models"
            initial={shouldReduceMotion ? false : { opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={shouldReduceMotion ? { opacity: 1 } : { opacity: 0, y: -6 }}
            transition={{ duration: 0.22 }}
            className="space-y-7"
          >
            {modelQuery.isLoading ? (
              <ApiNotice kind="loading" message="Loading model information from the Python backend." />
            ) : modelQuery.isError ? (
              <ApiNotice kind="error" message={apiError(modelQuery.error)} />
            ) : !info ? (
              <EmptyState title="No model information" description="The backend has not returned model details." />
            ) : (
              <>
                {/* Top Summary Cards */}
                <div className="grid gap-4 md:grid-cols-3">
                  <div className="rounded-lg border border-primary/30 bg-card p-5 shadow-panel md:col-span-2">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <p className="text-xs font-semibold uppercase tracking-wider text-primary">
                        Active Production Classifier
                      </p>
                      <span
                        className={cn(
                          "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[10px] font-semibold",
                          connected
                            ? "border-safe/35 bg-safe/10 text-safe"
                            : "border-warning/35 bg-warning/10 text-warning"
                        )}
                      >
                        <span className={cn("size-1.5 rounded-full", connected ? "bg-safe" : "bg-warning")} />
                        {connected ? "Backend Connected & Model Loaded" : "Backend Unreachable"}
                      </span>
                    </div>
                    <p className="mt-2 text-lg font-bold text-foreground">{info.model ?? "Not provided"}</p>
                    <p className="mt-1 text-xs text-muted-foreground">
                      Selected after benchmarking {info.candidateModels?.length ?? 6} candidate algorithms on a stratified 80/20 train-test split.
                    </p>
                  </div>

                  <div className="rounded-lg border border-border bg-card p-5 shadow-panel">
                    <p className="text-xs text-muted-foreground">Model Artifact Version</p>
                    <p className="mt-2 font-mono text-lg font-bold text-foreground">{info.version ?? "1.0.0"}</p>
                    {cvF1Mean !== undefined && (
                      <p className="mt-1 text-xs text-muted-foreground">
                        5-Fold Stratified CV F1: <strong className="text-foreground">{Number(cvF1Mean).toFixed(2)}%</strong>
                      </p>
                    )}
                  </div>

                  <div className="rounded-lg border border-border bg-card p-5 shadow-panel md:col-span-3">
                    <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                      Training &amp; Evaluation Dataset Corpus
                    </p>
                    <p className="mt-1.5 text-sm font-semibold text-foreground">{info.dataset ?? "Not provided"}</p>
                  </div>
                </div>

                {/* Dataset Size Breakdown */}
                <div className="grid gap-4 sm:grid-cols-3">
                  <div className="rounded-lg border border-border bg-card p-5">
                    <p className="text-xs text-muted-foreground">Total Corpus Samples</p>
                    <p className="mt-2 font-mono text-2xl font-bold text-foreground">
                      {info.datasetSize?.toLocaleString() ?? "Not provided"}
                    </p>
                    <p className="mt-1 text-[11px] text-muted-foreground">Validated SMS &amp; Phishing corpus</p>
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

                {/* Classification Classes & Supported Analysis Types */}
                <div className="grid gap-6 md:grid-cols-2">
                  <div className="rounded-lg border border-border bg-card p-5">
                    <p className="text-xs font-semibold text-foreground">Classification Classes</p>
                    <p className="mt-0.5 text-xs text-muted-foreground">Binary target labels output by the classifier.</p>
                    <div className="mt-3 flex flex-wrap gap-2">
                      {info.classes?.length ? (
                        info.classes.map((item) => (
                          <span
                            key={item}
                            className={cn(
                              "rounded-md border px-3 py-1 text-xs font-semibold",
                              item.toLowerCase().includes("scam")
                                ? "border-danger/35 bg-danger/10 text-danger"
                                : "border-safe/35 bg-safe/10 text-safe"
                            )}
                          >
                            {item}
                          </span>
                        ))
                      ) : (
                        <span className="text-sm text-muted-foreground">Not provided</span>
                      )}
                    </div>
                  </div>

                  <div className="rounded-lg border border-border bg-card p-5">
                    <p className="text-xs font-semibold text-foreground">Supported Analysis Features</p>
                    <p className="mt-0.5 text-xs text-muted-foreground">Inspection modes served by the FastAPI ML engine.</p>
                    <div className="mt-3 flex flex-wrap gap-2">
                      {info.supportedAnalysisTypes?.length ? (
                        info.supportedAnalysisTypes.map((item) => (
                          <span
                            key={item}
                            className="rounded-md border border-primary/30 bg-primary/10 px-3 py-1 text-xs font-semibold capitalize text-primary"
                          >
                            {item} Analysis
                          </span>
                        ))
                      ) : (
                        <span className="text-sm text-muted-foreground">Not provided</span>
                      )}
                    </div>
                  </div>
                </div>

                {/* Measured Holdout Metrics vs Live Workspace Statistics */}
                <div className="grid gap-6 xl:grid-cols-[1.35fr_1fr]">
                  <Panel
                    title="Measured Holdout Test-Set Metrics (Offline Evaluation)"
                    description="Verified performance on the 1,115-sample unseen test partition (saved_models/model_metadata.json)."
                    delay={0.04}
                  >
                    {numericMetrics.length ? (
                      <div className="grid gap-3.5 sm:grid-cols-2 lg:grid-cols-3">
                        {numericMetrics.map(([key, value], idx) => (
                          <motion.div
                            key={key}
                            initial={shouldReduceMotion ? false : { opacity: 0, y: 8 }}
                            animate={{ opacity: 1, y: 0 }}
                            whileHover={shouldReduceMotion ? { y: 0 } : { y: -2 }}
                            transition={{
                              duration: shouldReduceMotion ? 0 : 0.22,
                              delay: shouldReduceMotion ? 0 : idx * 0.035,
                            }}
                            className="rounded-lg border border-border bg-secondary/35 p-4 transition-colors hover:border-primary/40"
                          >
                            <p className="text-xs text-muted-foreground">{metricLabels[key] ?? key}</p>
                            <p className="mt-2 font-mono text-2xl font-bold text-primary">
                              {key === "roc_auc" ? value.toFixed(4) : `${value.toFixed(2)}%`}
                            </p>
                          </motion.div>
                        ))}
                      </div>
                    ) : (
                      <EmptyState
                        compact
                        title="Evaluation values not provided"
                        description="No performance values are shown until the backend returns them."
                      />
                    )}

                    {/* Confusion Matrix if returned by backend */}
                    {info.confusionMatrix && info.confusionMatrix.length === 2 && (
                      <div className="mt-5 rounded-lg border border-border bg-secondary/20 p-4">
                        <p className="text-xs font-semibold text-foreground">
                          Holdout Confusion Matrix (1,115 Test Samples)
                        </p>
                        <div className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-4 text-xs">
                          <motion.div
                            whileHover={shouldReduceMotion ? { y: 0 } : { y: -1.5 }}
                            className="rounded border border-safe/30 bg-safe/10 p-2.5"
                          >
                            <span className="text-[10px] text-muted-foreground">True Negatives (Legit → Legit)</span>
                            <p className="mt-1 font-mono text-base font-bold text-safe">
                              {info.confusionMatrix[0]?.[0] ?? "—"}
                            </p>
                          </motion.div>
                          <motion.div
                            whileHover={shouldReduceMotion ? { y: 0 } : { y: -1.5 }}
                            className="rounded border border-warning/30 bg-warning/10 p-2.5"
                          >
                            <span className="text-[10px] text-muted-foreground">False Positives (Legit → Scam)</span>
                            <p className="mt-1 font-mono text-base font-bold text-warning">
                              {info.confusionMatrix[0]?.[1] ?? "—"}
                            </p>
                          </motion.div>
                          <motion.div
                            whileHover={shouldReduceMotion ? { y: 0 } : { y: -1.5 }}
                            className="rounded border border-warning/30 bg-warning/10 p-2.5"
                          >
                            <span className="text-[10px] text-muted-foreground">False Negatives (Scam → Legit)</span>
                            <p className="mt-1 font-mono text-base font-bold text-warning">
                              {info.confusionMatrix[1]?.[0] ?? "—"}
                            </p>
                          </motion.div>
                          <motion.div
                            whileHover={shouldReduceMotion ? { y: 0 } : { y: -1.5 }}
                            className="rounded border border-danger/30 bg-danger/10 p-2.5"
                          >
                            <span className="text-[10px] text-muted-foreground">True Positives (Scam → Scam)</span>
                            <p className="mt-1 font-mono text-base font-bold text-danger">
                              {info.confusionMatrix[1]?.[1] ?? "—"}
                            </p>
                          </motion.div>
                        </div>
                      </div>
                    )}
                  </Panel>

                  <Panel
                    title="Live Workspace Scan Statistics (Runtime Usage)"
                    description="Real-time counts from your local SQLite scan history (strictly separate from offline holdout test metrics)."
                    delay={0.08}
                  >
                    <div className="grid grid-cols-2 gap-3">
                      <motion.div
                        whileHover={shouldReduceMotion ? { y: 0 } : { y: -2 }}
                        className="rounded-lg border border-border bg-secondary/30 p-4 transition-colors hover:border-primary/35"
                      >
                        <p className="text-xs text-muted-foreground">Live Scans Executed</p>
                        <p className="mt-1.5 font-mono text-2xl font-bold text-foreground">{records.length}</p>
                      </motion.div>
                      <motion.div
                        whileHover={shouldReduceMotion ? { y: 0 } : { y: -2 }}
                        className="rounded-lg border border-border bg-secondary/30 p-4 transition-colors hover:border-danger/35"
                      >
                        <p className="text-xs text-muted-foreground">Flagged Scam / Phishing</p>
                        <p className="mt-1.5 font-mono text-2xl font-bold text-danger">{liveScamCount}</p>
                      </motion.div>
                      <motion.div
                        whileHover={shouldReduceMotion ? { y: 0 } : { y: -2 }}
                        className="rounded-lg border border-border bg-secondary/30 p-4 transition-colors hover:border-safe/35"
                      >
                        <p className="text-xs text-muted-foreground">Verified Legitimate</p>
                        <p className="mt-1.5 font-mono text-2xl font-bold text-safe">{liveLegitCount}</p>
                      </motion.div>
                      <motion.div
                        whileHover={shouldReduceMotion ? { y: 0 } : { y: -2 }}
                        className="rounded-lg border border-border bg-secondary/30 p-4 transition-colors hover:border-primary/35"
                      >
                        <p className="text-xs text-muted-foreground">Backend Engine Status</p>
                        <p className={cn("mt-1.5 text-sm font-bold", connected ? "text-safe" : "text-warning")}>
                          {connected ? "Healthy & Online" : "Offline"}
                        </p>
                      </motion.div>
                    </div>
                  </Panel>
                </div>

                {/* Feature Engineering & Random Forest Pipeline Explanation */}
                <div className="grid gap-6 lg:grid-cols-2">
                  <Panel
                    title="10,043-Dimensional Feature Extraction Pipeline"
                    description="Three-branch feature engineering vector constructed for every incoming text or URL."
                    delay={0.1}
                  >
                    {info.features?.length ? (
                      <div className="space-y-3">
                        {info.features.map((item, i) => (
                          <motion.div
                            key={item}
                            initial={shouldReduceMotion ? false : { opacity: 0, x: -6 }}
                            animate={{ opacity: 1, x: 0 }}
                            whileHover={shouldReduceMotion ? { x: 0 } : { x: 3 }}
                            transition={{
                              duration: shouldReduceMotion ? 0 : 0.2,
                              delay: shouldReduceMotion ? 0 : i * 0.05,
                            }}
                            className="flex items-start gap-3 rounded-lg border border-border bg-secondary/25 p-3.5 transition-colors hover:border-primary/35"
                          >
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
                          </motion.div>
                        ))}
                      </div>
                    ) : (
                      <EmptyState compact title="No feature information" description="The backend did not return feature details." />
                    )}
                  </Panel>

                  <Panel
                    title="Prediction Workflow & Random Forest Ensemble"
                    description="How SCAMLENS AI transforms raw text into an explainable risk verdict."
                  >
                    <div className="space-y-3 text-xs leading-6 text-muted-foreground">
                      <p>
                        Real-world communication datasets are naturally imbalanced (~86.6% legitimate vs. ~13.4% scam). A naive classifier can achieve high accuracy simply by predicting &ldquo;Legitimate&rdquo; for borderline threats.
                      </p>
                      <p>
                        SCAMLENS AI trains a <strong className="text-foreground">200-estimator Random Forest with balanced class weights</strong>, penalizing missed scam messages heavily during impurity splitting. Each decision tree votes on the 10,043-feature sparse vector to produce a calibrated base probability, which is combined with structural indicator checks to assign a final Risk Level (<strong className="text-safe">Low</strong>, <strong className="text-warning">Suspicious</strong>, <strong className="text-orange-400">High</strong>, or <strong className="text-danger">Very High</strong>).
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
                                  ? "border-primary bg-primary/20 font-semibold text-primary"
                                  : "border-border bg-secondary text-muted-foreground"
                              )}
                            >
                              {cand} {cand === info.model && "★ Selected"}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  </Panel>
                </div>
              </>
            )}
          </motion.div>
        )}

        {/* =================================================================== */}
        {/* TAB B: ABOUT PROJECT                                                */}
        {/* =================================================================== */}
        {activeTab === "about" && (
          <motion.div
            key="tab-about"
            initial={shouldReduceMotion ? false : { opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={shouldReduceMotion ? { opacity: 1 } : { opacity: 0, y: -6 }}
            transition={{ duration: 0.22 }}
            className="space-y-7"
          >
            {/* Project Overview & Objectives */}
            <div className="grid gap-6 lg:grid-cols-[1.25fr_1fr]">
              <Panel title="Project Overview & Problem Statement" description="Final-Year BCA Major Project — SCAMLENS AI">
                <div className="space-y-3 text-sm leading-7 text-muted-foreground">
                  <p>
                    Phishing links, deceptive SMS alerts (&ldquo;smishing&rdquo;), fraudulent KYC suspension warnings, and lottery lures represent some of the most widespread cybersecurity threats facing everyday users and organizations. Traditional blacklists often fail against newly registered domains or zero-day message templates.
                  </p>
                  <p>
                    <strong className="text-foreground">SCAMLENS AI — Intelligent Scam and Phishing Detection System</strong> addresses this gap by inspecting the intrinsic linguistic, structural, and lexical patterns of messages and URLs before a user clicks. Rather than acting as a black box, the system pairs every machine-learning probability score with human-readable <strong className="text-foreground">Detection Indicators</strong> and actionable <strong className="text-foreground">Security Guidance</strong>.
                  </p>
                </div>
              </Panel>

              <Panel title="Core Project Objectives" description="Engineering goals accomplished in this system.">
                <ul className="space-y-2.5 text-xs leading-6 text-muted-foreground">
                  {[
                    "Achieve >98% classification accuracy and high recall on real-world SMS & phishing datasets using interpretable ensemble models.",
                    "Perform 100% static, zero-execution URL analysis so malicious links are never visited or triggered during inspection.",
                    "Provide explainable risk tiers (Low, Suspicious, High, Very High) backed by specific lexical triggers.",
                    "Support high-throughput Batch CSV dataset scanning with user-selectable columns and downloadable results.",
                    "Generate standalone, multi-page PDF security audit reports directly from the persisted SQLite history.",
                    "Educate users through an interactive Learn & Practise module featuring 44 randomized phishing scenarios.",
                  ].map((obj) => (
                    <li key={obj} className="flex items-start gap-2.5">
                      <CheckCircle2 className="mt-1 size-4 shrink-0 text-primary" />
                      <span>{obj}</span>
                    </li>
                  ))}
                </ul>
              </Panel>
            </div>

            {/* Existing vs Proposed System Comparison */}
            <Panel
              title="Existing System vs. Proposed SCAMLENS AI System"
              description="Architectural improvements introduced by combining classical NLP, structural heuristics, and explainable reporting."
            >
              {/* Mobile Card View (< md) */}
              <div className="space-y-3 md:hidden">
                {SYSTEM_COMPARISON.map((row) => (
                  <div key={`mob-comp-${row.aspect}`} className="rounded-lg border border-border bg-secondary/20 p-3.5 space-y-2 text-xs">
                    <p className="font-bold text-foreground">{row.aspect}</p>
                    <div className="rounded border border-border bg-card p-2.5">
                      <span className="font-semibold text-muted-foreground">Conventional: </span>
                      <span className="text-muted-foreground">{row.existing}</span>
                    </div>
                    <div className="rounded border border-primary/30 bg-primary/5 p-2.5">
                      <span className="font-semibold text-primary">SCAMLENS AI: </span>
                      <span className="text-foreground">{row.proposed}</span>
                    </div>
                  </div>
                ))}
              </div>

              {/* Desktop Table (md+) */}
              <div className="hidden overflow-x-auto md:block">
                <table className="w-full border-collapse text-left text-xs">
                  <thead>
                    <tr className="border-b border-border bg-secondary/40">
                      <th className="p-3.5 font-semibold text-foreground">Comparison Dimension</th>
                      <th className="p-3.5 font-semibold text-muted-foreground">Conventional / Existing Approach</th>
                      <th className="p-3.5 font-semibold text-primary">Proposed SCAMLENS AI System</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {SYSTEM_COMPARISON.map((row) => (
                      <tr key={row.aspect} className="hover:bg-secondary/20">
                        <td className="p-3.5 font-semibold text-foreground">{row.aspect}</td>
                        <td className="p-3.5 text-muted-foreground">{row.existing}</td>
                        <td className="p-3.5 text-foreground">{row.proposed}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Panel>

            {/* Visual System Architecture Flow Diagram */}
            <Panel
              title="System Architecture & Processing Pipeline"
              description="End-to-end 5-stage data flow from React client submission to FastAPI ML inference and SQLite/PDF persistence."
              delay={0.06}
            >
              <div className="grid gap-4 md:grid-cols-5">
                {ARCHITECTURE_STAGES.map((stage, index) => (
                  <motion.div
                    key={stage.step}
                    initial={shouldReduceMotion ? false : { opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    whileHover={shouldReduceMotion ? { y: 0 } : { y: -3 }}
                    transition={{
                      duration: shouldReduceMotion ? 0 : 0.22,
                      delay: shouldReduceMotion ? 0 : index * 0.045,
                    }}
                    className="relative flex flex-col justify-between rounded-xl border border-primary/25 bg-gradient-to-b from-secondary/40 to-card p-4 transition-colors hover:border-primary/50"
                  >
                    <div>
                      <div className="flex items-center justify-between">
                        <span className="inline-block rounded bg-primary/15 px-2 py-0.5 font-mono text-xs font-bold text-primary">
                          STAGE {stage.step}
                        </span>
                        {index < ARCHITECTURE_STAGES.length - 1 && (
                          <ArrowRight className="hidden size-4 text-primary/60 md:block" />
                        )}
                      </div>
                      <h3 className="mt-3 text-sm font-semibold text-foreground">{stage.title}</h3>
                      <p className="mt-1.5 text-xs leading-relaxed text-muted-foreground">{stage.desc}</p>
                    </div>
                    <div className="mt-3 border-t border-border/60 pt-2 text-[10px] font-mono text-muted-foreground">
                      {index === 0
                        ? "React + Supabase Auth"
                        : index === 1
                          ? "preprocessing.py"
                          : index === 2
                            ? "feature_extraction.py"
                            : index === 3
                              ? "predictor.py (RF)"
                              : "SQLite + report_service.py"}
                    </div>
                  </motion.div>
                ))}
              </div>
            </Panel>

            {/* Main Modules & Technology Stack */}
            <div className="grid gap-6 xl:grid-cols-2">
              <Panel title="Main System Modules" description="Core functional workspaces integrated inside SCAMLENS AI." delay={0.1}>
                <div className="grid gap-3 sm:grid-cols-2">
                  {MAIN_MODULES.map((m, idx) => (
                    <motion.div
                      key={m.name}
                      initial={shouldReduceMotion ? false : { opacity: 0, y: 6 }}
                      animate={{ opacity: 1, y: 0 }}
                      whileHover={shouldReduceMotion ? { y: 0 } : { y: -2 }}
                      transition={{
                        duration: shouldReduceMotion ? 0 : 0.2,
                        delay: shouldReduceMotion ? 0 : idx * 0.035,
                      }}
                      className="rounded-lg border border-border bg-secondary/25 p-3.5 transition-colors hover:border-primary/35"
                    >
                      <p className="text-xs font-bold text-foreground">{m.name}</p>
                      <p className="mt-1 text-[11px] leading-relaxed text-muted-foreground">{m.desc}</p>
                    </motion.div>
                  ))}
                </div>
              </Panel>

              <Panel title="Technology Stack" description="Full-stack tools and libraries powering the platform." delay={0.12}>
                <div className="grid gap-3.5 sm:grid-cols-2">
                  {TECH_STACK.map((group, idx) => (
                    <motion.div
                      key={group.category}
                      initial={shouldReduceMotion ? false : { opacity: 0, y: 6 }}
                      animate={{ opacity: 1, y: 0 }}
                      whileHover={shouldReduceMotion ? { y: 0 } : { y: -2 }}
                      transition={{
                        duration: shouldReduceMotion ? 0 : 0.2,
                        delay: shouldReduceMotion ? 0 : idx * 0.04,
                      }}
                      className="rounded-lg border border-border bg-secondary/20 p-3.5 transition-colors hover:border-primary/35"
                    >
                      <p className="text-xs font-semibold uppercase tracking-wider text-primary">{group.category}</p>
                      <div className="mt-2.5 flex flex-wrap gap-1.5">
                        {group.items.map((item) => (
                          <span
                            key={item}
                            className="rounded border border-border bg-card px-2 py-0.5 text-[11px] font-medium text-foreground"
                          >
                            {item}
                          </span>
                        ))}
                      </div>
                    </motion.div>
                  ))}
                </div>
              </Panel>
            </div>

            {/* Limitations & Future Enhancements */}
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
                    ["Sandboxed Domain Age Check", "Optional WHOIS and certificate transparency lookups for newly registered domains."],
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
          </motion.div>
        )}

        {/* =================================================================== */}
        {/* TAB C: APPLICATION SETTINGS                                         */}
        {/* =================================================================== */}
        {activeTab === "settings" && (
          <motion.div
            key="tab-settings"
            initial={shouldReduceMotion ? false : { opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={shouldReduceMotion ? { opacity: 1 } : { opacity: 0, y: -6 }}
            transition={{ duration: 0.22 }}
            className="space-y-7"
          >
            <div className="grid gap-6 xl:grid-cols-2">
              {/* Functional Theme, Animation & Accessibility Preferences */}
              <Panel
                title="Theme, Animation & Accessibility Preferences"
                description="Configure Dark Mode, Light Mode, or System appearance alongside UI animations and reduced-motion accessibility. Saved locally in your browser."
              >
                <div className="space-y-4">
                  {/* Theme Mode Selector */}
                  <div className="rounded-xl border border-border bg-secondary/25 p-4">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div>
                        <p className="text-sm font-semibold text-foreground">Theme &amp; Appearance Mode</p>
                        <p className="mt-0.5 text-xs text-muted-foreground">
                          Switch between Light Mode, Dark Mode, or follow your OS color scheme.
                        </p>
                      </div>
                      <span className="rounded-full border border-primary/35 bg-primary/10 px-2.5 py-0.5 text-[11px] font-semibold capitalize text-primary">
                        {prefs.themeMode === "system"
                          ? `System (${resolvedTheme})`
                          : `${prefs.themeMode} Mode`}
                      </span>
                    </div>

                    <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-3">
                      <motion.button
                        type="button"
                        whileHover={shouldReduceMotion ? { y: 0 } : { y: -2 }}
                        whileTap={shouldReduceMotion ? { scale: 1 } : { scale: 0.985 }}
                        onClick={() => setThemeMode("light")}
                        className={cn(
                          "flex flex-col items-start rounded-lg border p-3 text-left transition-colors",
                          prefs.themeMode === "light"
                            ? "border-primary bg-primary/15 text-foreground shadow-sm"
                            : "border-border bg-card text-muted-foreground hover:border-primary/35 hover:text-foreground"
                        )}
                      >
                        <span className="flex items-center gap-1.5 text-xs font-bold text-foreground">
                          <Sun className="size-3.5 text-primary" /> Light Mode
                        </span>
                        <span className="mt-1 text-[11px] text-muted-foreground">
                          Clean white cards, cool slate surfaces, and high-contrast cyber-blue accents.
                        </span>
                      </motion.button>

                      <motion.button
                        type="button"
                        whileHover={shouldReduceMotion ? { y: 0 } : { y: -2 }}
                        whileTap={shouldReduceMotion ? { scale: 1 } : { scale: 0.985 }}
                        onClick={() => setThemeMode("dark")}
                        className={cn(
                          "flex flex-col items-start rounded-lg border p-3 text-left transition-colors",
                          prefs.themeMode === "dark"
                            ? "border-primary bg-primary/15 text-foreground shadow-sm"
                            : "border-border bg-card text-muted-foreground hover:border-primary/35 hover:text-foreground"
                        )}
                      >
                        <span className="flex items-center gap-1.5 text-xs font-bold text-foreground">
                          <Moon className="size-3.5 text-primary" /> Dark Mode
                        </span>
                        <span className="mt-1 text-[11px] text-muted-foreground">
                          Deep navy &amp; charcoal command-center surfaces with cyan glows.
                        </span>
                      </motion.button>

                      <motion.button
                        type="button"
                        whileHover={shouldReduceMotion ? { y: 0 } : { y: -2 }}
                        whileTap={shouldReduceMotion ? { scale: 1 } : { scale: 0.985 }}
                        onClick={() => setThemeMode("system")}
                        className={cn(
                          "flex flex-col items-start rounded-lg border p-3 text-left transition-colors",
                          prefs.themeMode === "system"
                            ? "border-primary bg-primary/15 text-foreground shadow-sm"
                            : "border-border bg-card text-muted-foreground hover:border-primary/35 hover:text-foreground"
                        )}
                      >
                        <span className="flex items-center gap-1.5 text-xs font-bold text-foreground">
                          <Monitor className="size-3.5 text-primary" /> System Preference
                        </span>
                        <span className="mt-1 text-[11px] text-muted-foreground">
                          Automatically syncs with your device&apos;s light or dark setting.
                        </span>
                      </motion.button>
                    </div>
                  </div>

                  {/* Motion Mode Selector */}
                  <div className="rounded-xl border border-border bg-secondary/25 p-4">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div>
                        <p className="text-sm font-semibold text-foreground">Interface Animation Mode</p>
                        <p className="mt-0.5 text-xs text-muted-foreground">
                          Choose between full cybersecurity animations or instant reduced-motion rendering.
                        </p>
                      </div>
                      <span
                        className={cn(
                          "rounded-full border px-2.5 py-0.5 text-[11px] font-semibold",
                          shouldReduceMotion
                            ? "border-warning/35 bg-warning/10 text-warning"
                            : "border-safe/35 bg-safe/10 text-safe"
                        )}
                      >
                        {shouldReduceMotion ? "Reduced Motion Active" : "Full Animations Active"}
                      </span>
                    </div>

                    <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
                      <motion.button
                        type="button"
                        whileHover={shouldReduceMotion ? { y: 0 } : { y: -2 }}
                        whileTap={shouldReduceMotion ? { scale: 1 } : { scale: 0.985 }}
                        onClick={() => updatePreferences({ motionMode: "full" })}
                        className={cn(
                          "flex flex-col items-start rounded-lg border p-3 text-left transition-colors",
                          prefs.motionMode === "full"
                            ? "border-primary bg-primary/15 text-foreground shadow-sm"
                            : "border-border bg-card text-muted-foreground hover:border-primary/35 hover:text-foreground"
                        )}
                      >
                        <span className="flex items-center gap-1.5 text-xs font-bold text-foreground">
                          <Sparkles className="size-3.5 text-primary" /> Full Animations
                        </span>
                        <span className="mt-1 text-[11px] text-muted-foreground">
                          Smooth KPI counters, laser scan beams, and staggered card transitions.
                        </span>
                      </motion.button>

                      <motion.button
                        type="button"
                        whileHover={shouldReduceMotion ? { y: 0 } : { y: -2 }}
                        whileTap={shouldReduceMotion ? { scale: 1 } : { scale: 0.985 }}
                        onClick={() => updatePreferences({ motionMode: "reduced" })}
                        className={cn(
                          "flex flex-col items-start rounded-lg border p-3 text-left transition-colors",
                          prefs.motionMode === "reduced"
                            ? "border-primary bg-primary/15 text-foreground shadow-sm"
                            : "border-border bg-card text-muted-foreground hover:border-primary/35 hover:text-foreground"
                        )}
                      >
                        <span className="flex items-center gap-1.5 text-xs font-bold text-foreground">
                          <ShieldCheck className="size-3.5 text-primary" /> Reduced Motion
                        </span>
                        <span className="mt-1 text-[11px] text-muted-foreground">
                          Disables non-essential animations for immediate, low-distraction display.
                        </span>
                      </motion.button>
                    </div>
                  </div>

                  {/* System Reduced-Motion Sync Toggle */}
                  <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-border bg-secondary/25 p-4">
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-semibold text-foreground">
                        Respect OS / Browser <code>prefers-reduced-motion</code>
                      </p>
                      <p className="mt-0.5 text-xs text-muted-foreground">
                        Automatically switch to reduced motion when your operating system accessibility setting is enabled (OS currently reports:{" "}
                        <strong className="text-foreground">{osReducedMotion ? "Reduce Motion ON" : "Standard Motion"}</strong>).
                      </p>
                    </div>
                    <Button
                      type="button"
                      variant={prefs.honorSystemReducedMotion ? "default" : "outline"}
                      size="sm"
                      onClick={() =>
                        updatePreferences({ honorSystemReducedMotion: !prefs.honorSystemReducedMotion })
                      }
                    >
                      {prefs.honorSystemReducedMotion ? "Enabled" : "Disabled"}
                    </Button>
                  </div>

                  {/* Local Training Progress Reset & Restore Defaults */}
                  <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-border bg-secondary/25 p-4">
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-semibold text-foreground">Learn &amp; Practise Local Progress</p>
                      <p className="mt-0.5 text-xs text-muted-foreground">
                        Reset your locally stored quiz attempt history and explored topic badges without affecting SQLite scan records.
                      </p>
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      <Button type="button" variant="outline" size="sm" onClick={handleClearQuizStorage}>
                        <Trash2 className="size-3.5" /> {quizResetDone ? "Quiz Progress Cleared!" : "Reset Quiz Progress"}
                      </Button>
                      <Button type="button" variant="ghost" size="sm" onClick={resetPreferences}>
                        <RotateCcw className="size-3.5" /> Restore Defaults
                      </Button>
                    </div>
                  </div>
                </div>
              </Panel>

              {/* Live Backend & Model Connection Status + Application Info */}
              <div className="space-y-6">
                <Panel
                  title="Backend & Model Connection Status"
                  description="Live telemetry from the configured FastAPI ML service."
                  action={
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        void queryClient.invalidateQueries({ queryKey: ["scamlens"] });
                      }}
                    >
                      <RefreshCw className={cn("size-3.5", health.isFetching && "animate-spin")} /> Refresh Status
                    </Button>
                  }
                >
                  <div className="grid gap-3 sm:grid-cols-2 text-xs">
                    <div className="rounded-lg border border-border bg-secondary/30 p-3.5">
                      <span className="text-muted-foreground">Configured API Base URL</span>
                      <p className="mt-1 truncate font-mono font-semibold text-foreground">
                        {scamlensApi.baseUrl ?? "Not configured"}
                      </p>
                    </div>
                    <div className="rounded-lg border border-border bg-secondary/30 p-3.5">
                      <span className="text-muted-foreground">FastAPI Health Status</span>
                      <p className={cn("mt-1 font-semibold", connected ? "text-safe" : "text-warning")}>
                        {health.isLoading
                          ? "Checking..."
                          : connected
                            ? `Online (${health.data?.status ?? "healthy"})`
                            : "Unavailable"}
                      </p>
                    </div>
                    <div className="rounded-lg border border-border bg-secondary/30 p-3.5">
                      <span className="text-muted-foreground">Loaded ML Classifier</span>
                      <p className="mt-1 font-semibold text-foreground">
                        {info?.model ?? (modelQuery.isLoading ? "Loading..." : "Not available")}
                      </p>
                    </div>
                    <div className="rounded-lg border border-border bg-secondary/30 p-3.5">
                      <span className="text-muted-foreground">Application &amp; Model Version</span>
                      <p className="mt-1 font-mono font-semibold text-foreground">
                        SCAMLENS AI v{info?.version ?? "1.0.0"}
                      </p>
                    </div>
                  </div>
                </Panel>

                <Panel
                  title="Privacy, Security & Zero-Execution Architecture"
                  description="How SCAMLENS AI handles submitted data and external URLs."
                >
                  <div className="space-y-3 text-xs leading-6 text-muted-foreground">
                    <div className="flex items-start gap-2.5 rounded-lg border border-safe/30 bg-safe/5 p-3">
                      <LockKeyhole className="mt-0.5 size-4 shrink-0 text-safe" />
                      <span>
                        <strong className="text-foreground">Zero-Execution Static URL Inspection:</strong> Submitted URLs are parsed strictly as text strings. SCAMLENS AI never opens, fetches, previews, or executes external links.
                      </span>
                    </div>
                    <div className="flex items-start gap-2.5 rounded-lg border border-primary/25 bg-primary/5 p-3">
                      <Database className="mt-0.5 size-4 shrink-0 text-primary" />
                      <span>
                        <strong className="text-foreground">Local SQLite Audit Trail:</strong> Message, URL, and Batch CSV scans are stored locally in your workspace SQLite database (<code>database/scamlens.db</code>) and are never transmitted to third-party AI APIs.
                      </span>
                    </div>
                  </div>
                </Panel>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
