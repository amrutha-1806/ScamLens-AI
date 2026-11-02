import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { motion, AnimatePresence } from "motion/react";
import {
  AlertOctagon,
  AlertTriangle,
  ArrowUpDown,
  CheckCircle2,
  ChevronDown,
  Clock3,
  Download,
  FileCheck2,
  FileSearch,
  Filter,
  Layers,
  Loader2,
  LockKeyhole,
  MessageSquareText,
  Radar,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  UserCheck,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ApiNotice, EmptyState, KpiCard, Panel } from "./primitives";
import { scamlensApi, ScamlensApiError } from "@/lib/scamlens-api";
import { useScamlensPreferences } from "@/lib/scamlens-preferences";
import type { AlertReviewStatus, ScanRecord } from "@/lib/scamlens-types";
import { cn } from "@/lib/utils";

function statusClass(status?: AlertReviewStatus) {
  switch (status) {
    case "reviewed":
      return "border-safe/40 bg-safe/10 text-safe";
    case "investigating":
      return "border-primary/40 bg-primary/10 text-primary";
    case "flagged_fp":
      return "border-muted-foreground/30 bg-muted/40 text-muted-foreground";
    default:
      return "border-warning/40 bg-warning/10 text-warning";
  }
}

function statusLabel(status?: AlertReviewStatus) {
  switch (status) {
    case "reviewed":
      return "Reviewed / Cleared";
    case "investigating":
      return "Under Investigation";
    case "flagged_fp":
      return "Flagged False Positive";
    default:
      return "Unreviewed (Action Required)";
  }
}

export function SecurityAlertCenterView() {
  const { shouldReduceMotion } = useScamlensPreferences();
  const queryClient = useQueryClient();
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [search, setSearch] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [savingId, setSavingId] = useState<string | null>(null);

  // Review form state
  const [editingStatus, setEditingStatus] = useState<AlertReviewStatus>("unreviewed");
  const [editingNotes, setEditingNotes] = useState("");
  const [feedbackMsg, setFeedbackMsg] = useState<{ id: string; msg: string; err?: boolean } | null>(null);

  const alertsQuery = useQuery({
    queryKey: ["scamlens", "alerts", statusFilter],
    queryFn: () => scamlensApi.getAlerts(statusFilter, 100),
    staleTime: 10_000,
  });

  const alertsData = alertsQuery.data?.alerts ?? [];
  const unreviewedCount = alertsQuery.data?.unreviewed_count ?? 0;
  const highCount = alertsQuery.data?.high_count ?? 0;
  const veryHighCount = alertsQuery.data?.very_high_count ?? 0;

  const filteredAlerts = alertsData.filter((a) => {
    if (!search.trim()) return true;
    const term = search.toLowerCase();
    return (
      a.id.toLowerCase().includes(term) ||
      a.inputPreview.toLowerCase().includes(term) ||
      (a.reviewNotes && a.reviewNotes.toLowerCase().includes(term))
    );
  });

  async function handleDownloadPdf(id: string) {
    setDownloadingId(id);
    setFeedbackMsg(null);
    try {
      await scamlensApi.downloadIncidentPdf(id);
      setFeedbackMsg({ id, msg: "Forensic incident PDF downloaded successfully." });
    } catch (err) {
      const msg = err instanceof ScamlensApiError || err instanceof Error ? err.message : "PDF download failed.";
      setFeedbackMsg({ id, msg, err: true });
    } finally {
      setDownloadingId(null);
    }
  }

  async function handleSaveReview(id: string) {
    setSavingId(id);
    setFeedbackMsg(null);
    try {
      await scamlensApi.reviewAlert(id, {
        review_status: editingStatus,
        review_notes: editingNotes,
      });
      setFeedbackMsg({ id, msg: "Incident review status and analyst notes saved to database." });
      void queryClient.invalidateQueries({ queryKey: ["scamlens", "alerts"] });
      void queryClient.invalidateQueries({ queryKey: ["scamlens", "history"] });
    } catch (err) {
      const msg = err instanceof ScamlensApiError || err instanceof Error ? err.message : "Failed to update alert.";
      setFeedbackMsg({ id, msg, err: true });
    } finally {
      setSavingId(null);
    }
  }

  function handleToggleExpand(alert: ScanRecord) {
    if (expandedId === alert.id) {
      setExpandedId(null);
    } else {
      setExpandedId(alert.id);
      setEditingStatus(alert.reviewStatus ?? "unreviewed");
      setEditingNotes(alert.reviewNotes ?? "");
      setFeedbackMsg(null);
    }
  }

  return (
    <div className="space-y-6">
      {/* Alert KPI Summary Cards */}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <KpiCard
          label="Total High-Risk Incidents"
          icon={AlertOctagon}
          tone="danger"
          value={alertsData.length}
          note="Scored High or Very High by ML model"
          delay={0.02}
        />
        <KpiCard
          label="Unreviewed Incidents"
          icon={AlertTriangle}
          tone="warning"
          value={unreviewedCount}
          note="Pending security analyst triage"
          delay={0.05}
        />
        <KpiCard
          label="Very High Severity"
          icon={ShieldAlert}
          tone="danger"
          value={veryHighCount}
          note="Confidence > 75% scam / phishing"
          delay={0.08}
        />
        <KpiCard
          label="High Severity"
          icon={Radar}
          value={highCount}
          note="Confidence 50% - 75% scam"
          delay={0.11}
        />
      </div>

      {/* Filter and Search Bar */}
      <Panel
        title={`Security Alert Triage Center (${filteredAlerts.length})`}
        description="Review high-risk detections, record investigator notes, assign incident status, and export formal forensic dossier PDFs."
        delay={0.08}
      >
        <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center sm:justify-between">
          <div className="relative w-full min-w-0 flex-1 sm:max-w-md">
            <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by ID, keyword, or analyst notes..."
              className="h-9 pl-9 text-xs sm:text-sm"
            />
          </div>

          {/* Status filter tabs */}
          <div className="flex flex-wrap items-center gap-1">
            {[
              ["all", "All Alerts"],
              ["unreviewed", "Unreviewed"],
              ["investigating", "Investigating"],
              ["reviewed", "Reviewed"],
              ["flagged_fp", "False Positive"],
            ].map(([st, label]) => {
              const active = statusFilter === st;
              return (
                <button
                  key={st}
                  type="button"
                  onClick={() => setStatusFilter(st)}
                  className={cn(
                    "rounded-md border px-2.5 py-1 text-xs font-semibold transition-colors",
                    active
                      ? "border-primary bg-primary text-primary-foreground"
                      : "border-border bg-card text-muted-foreground hover:bg-secondary"
                  )}
                >
                  {label}
                </button>
              );
            })}
          </div>
        </div>

        {/* Alerts listing */}
        {alertsQuery.isLoading ? (
          <ApiNotice kind="loading" message="Loading security alerts from SQLite audit database..." />
        ) : alertsQuery.isError ? (
          <ApiNotice kind="error" message="Could not load security alerts from backend." />
        ) : filteredAlerts.length === 0 ? (
          <EmptyState
            compact
            title="No High-Risk Alerts Found"
            description={
              statusFilter === "all"
                ? "No high-risk scam detections are currently stored."
                : `No alerts match filter "${statusFilter}".`
            }
          />
        ) : (
          <div className="space-y-3">
            {filteredAlerts.map((alert, idx) => {
              const isExpanded = expandedId === alert.id;
              const isDownloading = downloadingId === alert.id;
              const isSaving = savingId === alert.id;

              return (
                <motion.div
                  key={alert.id}
                  initial={shouldReduceMotion ? false : { opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{
                    duration: shouldReduceMotion ? 0 : 0.18,
                    delay: shouldReduceMotion ? 0 : Math.min(idx * 0.02, 0.2),
                  }}
                  className="overflow-hidden rounded-xl border border-border bg-card shadow-2xs transition-colors hover:border-primary/40 dark:bg-slate-950/70"
                >
                  {/* Alert summary card row */}
                  <div
                    onClick={() => handleToggleExpand(alert)}
                    className="flex cursor-pointer flex-col gap-3 p-4 transition-colors hover:bg-secondary/35 sm:flex-row sm:items-center sm:justify-between"
                  >
                    <div className="min-w-0 flex-1 space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-xs font-bold text-foreground">#SL{alert.id.padStart(6, "0")}</span>
                        <span className="rounded border border-primary/25 bg-primary/10 px-2 py-0.5 text-[10px] font-semibold uppercase text-primary">
                          {alert.inputType}
                        </span>
                        <span className={cn("rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase", statusClass(alert.reviewStatus))}>
                          {statusLabel(alert.reviewStatus)}
                        </span>
                        <span className="text-[11px] text-muted-foreground">{alert.timestamp}</span>
                      </div>
                      <p className="line-clamp-2 break-all text-xs font-medium text-foreground sm:text-sm">
                        {alert.inputPreview}
                      </p>
                    </div>

                    <div className="flex items-center gap-3 sm:shrink-0">
                      <div className="text-right">
                        <span className="rounded-full border border-danger/40 bg-danger/10 px-2.5 py-0.5 text-xs font-bold text-danger">
                          {alert.riskLevel} ({alert.riskProbability.toFixed(1)}%)
                        </span>
                        {alert.reviewedAt && (
                          <p className="mt-1 text-[10px] text-muted-foreground">Triaged {alert.reviewedAt.slice(0, 10)}</p>
                        )}
                      </div>
                      <ChevronDown
                        className={cn("size-4 text-muted-foreground transition-transform", isExpanded && "rotate-180")}
                      />
                    </div>
                  </div>

                  {/* Expanded triage panel */}
                  <AnimatePresence>
                    {isExpanded && (
                      <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: "auto" }}
                        exit={{ opacity: 0, height: 0 }}
                        transition={{ duration: 0.2 }}
                        className="border-t border-border bg-secondary/15 p-4 sm:p-5"
                      >
                        <div className="grid gap-5 lg:grid-cols-[1.2fr_.8fr]">
                          {/* Left: Incident Details */}
                          <div className="space-y-3.5">
                            <div>
                              <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                                Submitted Content
                              </span>
                              <div className="mt-1 max-h-36 overflow-y-auto rounded-lg border border-border bg-card p-3 font-mono text-xs leading-relaxed text-foreground">
                                {alert.inputPreview}
                              </div>
                            </div>

                            {alert.guidance && (
                              <div>
                                <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                                  Automated Risk Guidance
                                </span>
                                <p className="mt-1 text-xs text-muted-foreground">{alert.guidance}</p>
                              </div>
                            )}

                            {/* Export Incident Dossier Button */}
                            <div className="pt-2">
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={() => handleDownloadPdf(alert.id)}
                                disabled={isDownloading}
                                className="gap-2"
                              >
                                {isDownloading ? (
                                  <Loader2 className="size-3.5 animate-spin" />
                                ) : (
                                  <Download className="size-3.5 text-primary" />
                                )}
                                <span>Export Incident Dossier (PDF)</span>
                              </Button>
                            </div>
                          </div>

                          {/* Right: Analyst Review Controls */}
                          <div className="space-y-3 rounded-lg border border-border bg-card p-4">
                            <h5 className="flex items-center gap-1.5 text-xs font-bold text-foreground">
                              <UserCheck className="size-4 text-primary" />
                              Analyst Triage &amp; Incident Notes
                            </h5>

                            <div>
                              <label htmlFor={`status-${alert.id}`} className="text-[11px] font-semibold text-muted-foreground">
                                Incident Review Status
                              </label>
                              <select
                                id={`status-${alert.id}`}
                                value={editingStatus}
                                onChange={(e) => setEditingStatus(e.target.value as AlertReviewStatus)}
                                className="mt-1 h-9 w-full rounded-md border border-border bg-secondary px-3 text-xs font-semibold text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                              >
                                <option value="unreviewed">Unreviewed (Pending)</option>
                                <option value="investigating">Under Investigation</option>
                                <option value="reviewed">Reviewed &amp; Confirmed Threat</option>
                                <option value="flagged_fp">Flagged as False Positive</option>
                              </select>
                            </div>

                            <div>
                              <label htmlFor={`notes-${alert.id}`} className="text-[11px] font-semibold text-muted-foreground">
                                Forensic / Investigator Notes
                              </label>
                              <Textarea
                                id={`notes-${alert.id}`}
                                value={editingNotes}
                                onChange={(e) => setEditingNotes(e.target.value)}
                                placeholder="Add analyst notes, indicators of compromise, or internal ticket reference..."
                                className="mt-1 min-h-20 text-xs"
                              />
                            </div>

                            <div className="flex items-center justify-between gap-2 pt-1">
                              <Button
                                size="sm"
                                onClick={() => handleSaveReview(alert.id)}
                                disabled={isSaving}
                                className="w-full sm:w-auto"
                              >
                                {isSaving ? <Loader2 className="size-3.5 animate-spin" /> : <FileCheck2 className="size-3.5" />}
                                <span>Save Incident Review</span>
                              </Button>
                            </div>

                            {feedbackMsg && feedbackMsg.id === alert.id && (
                              <p
                                className={cn(
                                  "mt-2 text-xs",
                                  feedbackMsg.err ? "text-danger" : "text-safe"
                                )}
                              >
                                {feedbackMsg.msg}
                              </p>
                            )}
                          </div>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </motion.div>
              );
            })}
          </div>
        )}
      </Panel>
    </div>
  );
}
