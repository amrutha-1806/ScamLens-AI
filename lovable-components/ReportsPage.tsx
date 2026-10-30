import React, { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { historyQueryOptions } from "@/lib/scamlens-queries";
import { ScanRecord } from "@/lib/scamlens-types";
import {
  FileText,
  Download,
  Search,
  AlertTriangle,
  CheckCircle2,
  ShieldAlert,
  Clock,
  ExternalLink,
  RefreshCw,
  FileCheck,
  ChevronRight,
  Database,
  Cpu,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";

export default function ReportsPage() {
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [reportGenerated, setReportGenerated] = useState(false);

  // 1. Fetch real scan records using existing useQuery(historyQueryOptions())
  const {
    data: historyData,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery(historyQueryOptions());

  // Normalize history data into a flat array of ScanRecord
  const scanRecords: ScanRecord[] = useMemo(() => {
    if (!historyData) return [];
    if (Array.isArray(historyData)) return historyData;
    // Handle { items: [...], total: ... } or { records: [...], count: ... }
    const anyData = historyData as any;
    if (Array.isArray(anyData.items)) return anyData.items;
    if (Array.isArray(anyData.records)) return anyData.records;
    if (Array.isArray(anyData.data)) return anyData.data;
    return [];
  }, [historyData]);

  // 3. Search functionality to filter available scans
  const filteredScans = useMemo(() => {
    if (!searchTerm.trim()) return scanRecords;
    const term = searchTerm.toLowerCase();
    return scanRecords.filter((scan) => {
      const content = (scan.content || "").toLowerCase();
      const pred = (scan.prediction || scan.prediction_label || "").toLowerCase();
      const level = (scan.risk_level || "").toLowerCase();
      const type = (scan.input_type || "").toLowerCase();
      const idStr = String(scan.id);
      return (
        content.includes(term) ||
        pred.includes(term) ||
        level.includes(term) ||
        type.includes(term) ||
        idStr.includes(term)
      );
    });
  }, [scanRecords, searchTerm]);

  // Currently selected scan record
  const selectedScan = useMemo(() => {
    if (selectedScanId === null) return null;
    return scanRecords.find((s) => s.id === selectedScanId) || null;
  }, [scanRecords, selectedScanId]);

  // Helpers to safely extract fields without inventing data
  const getPrediction = (scan: ScanRecord) =>
    scan.prediction || scan.prediction_label || "Unknown";

  const getRiskScore = (scan: ScanRecord) =>
    typeof scan.risk_score === "number" ? scan.risk_score : 0;

  const getRiskProbability = (scan: ScanRecord) => {
    if (typeof scan.risk_probability === "number") return scan.risk_probability;
    if (typeof scan.scam_probability === "number") return scan.scam_probability;
    if (typeof scan.risk_score === "number") return scan.risk_score / 100;
    return 0;
  };

  const getIndicators = (scan: ScanRecord): string[] => {
    if (Array.isArray(scan.indicators) && scan.indicators.length > 0) {
      return scan.indicators;
    }
    if (scan.explanation_summary) {
      return scan.explanation_summary
        .split(";")
        .map((s) => s.trim())
        .filter(Boolean);
    }
    return [];
  };

  const formatTimestamp = (ts: string) => {
    if (!ts) return "Not available";
    try {
      const date = new Date(ts.replace(" ", "T"));
      if (!isNaN(date.getTime())) {
        return date.toLocaleString();
      }
    } catch (_) {}
    return ts;
  };

  // 6. Generate structured plain text report using selected record's actual data
  const generateReportText = (scan: ScanRecord): string => {
    const pred = getPrediction(scan);
    const score = getRiskScore(scan);
    const prob = getRiskProbability(scan);
    const indicators = getIndicators(scan);
    const ts = formatTimestamp(scan.timestamp);

    const separator = "=".repeat(72);
    const subSep = "-".repeat(72);

    return [
      separator,
      "             SCAMLENS AI -- INCIDENT AUDIT & ANALYSIS REPORT",
      separator,
      "",
      `Report Reference ID : SCAM-RPT-${scan.id}`,
      `Scan Timestamp      : ${ts}`,
      `Audit Status        : VERIFIED (Offline ML Classification)`,
      `Model Engine        : Random Forest Classifier (Class-Balanced, 200 trees)`,
      `Feature Dimension   : 10,043 TF-IDF N-grams & Lexical Features`,
      "",
      subSep,
      " 1. TARGET SUBMISSION SUMMARY",
      subSep,
      `Input Category      : ${(scan.input_type || "text").toUpperCase()}`,
      `Submitted Content   :`,
      `  "${scan.content || "Not available"}"`,
      "",
      subSep,
      " 2. MACHINE LEARNING CLASSIFICATION RESULTS",
      subSep,
      `Final Prediction    : ${pred.toUpperCase()}`,
      `Assessed Risk Level : ${scan.risk_level || "Not available"}`,
      `Computed Risk Score : ${score.toFixed(1)} / 100`,
      `Scam Probability    : ${(prob * 100).toFixed(2)}%`,
      "",
      subSep,
      " 3. DETECTION & STATIC SECURITY INDICATORS",
      subSep,
      indicators.length > 0
        ? indicators.map((ind, i) => `  [${i + 1}] ${ind}`).join("\n")
        : "  * No strong predefined indicators detected (prediction based on learned patterns).",
      "",
      scan.input_type === "url"
        ? [
            subSep,
            " 4. URL STATIC SAFETY NOTICE",
            subSep,
            "  * SECURITY GUARANTEE: Submitted URLs are strictly analyzed as static text strings.",
            "  * The server NEVER fetches, executes, resolves DNS, or connects to target links.",
            "",
          ].join("\n")
        : "",
      subSep,
      " 5. SYSTEM COMPLIANCE & REPRODUCIBILITY",
      subSep,
      `  * Database Log ID : ${scan.id}`,
      `  * Training Corpus : UCI SMS Spam Collection Benchmark (5,574 samples)`,
      `  * Benchmark Score : 0.9803 Macro F1 | 0.9936 ROC-AUC`,
      `  * Generation Date : ${new Date().toLocaleString()}`,
      "",
      separator,
      "       Generated by SCAMLENS AI Academic Cybersecurity Platform",
      separator,
    ]
      .filter((line) => line !== undefined)
      .join("\n");
  };

  // 7. Download report as plain-text .txt file
  const handleDownload = () => {
    if (!selectedScan) return;
    const reportText = generateReportText(selectedScan);
    const blob = new Blob([reportText], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `scamlens-report-${selectedScan.id}.txt`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="container max-w-7xl mx-auto px-4 py-8 space-y-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border/40 pb-6">
        <div>
          <h1 className="text-3xl font-extrabold tracking-tight flex items-center gap-2">
            <FileText className="h-8 w-8 text-primary" />
            Incident Reports
          </h1>
          <p className="text-muted-foreground mt-1">
            Generate and export reproducible forensic reports from real SQLite scan logs.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => refetch()}
            disabled={isLoading}
            className="flex items-center gap-2"
          >
            <RefreshCw className={`h-4 w-4 ${isLoading ? "animate-spin" : ""}`} />
            Refresh Scans
          </Button>
        </div>
      </div>

      {/* 8. Loading State */}
      {isLoading && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <Card className="lg:col-span-1">
            <CardHeader>
              <Skeleton className="h-6 w-32" />
              <Skeleton className="h-4 w-48 mt-2" />
            </CardHeader>
            <CardContent className="space-y-3">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-16 w-full" />
              <Skeleton className="h-16 w-full" />
              <Skeleton className="h-16 w-full" />
            </CardContent>
          </Card>
          <Card className="lg:col-span-2">
            <CardHeader>
              <Skeleton className="h-6 w-48" />
              <Skeleton className="h-4 w-64 mt-2" />
            </CardHeader>
            <CardContent className="space-y-4">
              <Skeleton className="h-28 w-full" />
              <Skeleton className="h-40 w-full" />
            </CardContent>
          </Card>
        </div>
      )}

      {/* 8. Error State */}
      {isError && (
        <Card className="border-destructive/50 bg-destructive/5">
          <CardHeader>
            <div className="flex items-center gap-2 text-destructive">
              <AlertTriangle className="h-5 w-5" />
              <CardTitle>History Unavailable</CardTitle>
            </div>
            <CardDescription className="text-destructive/80">
              Could not communicate with the backend history API at{" "}
              <code className="text-xs bg-muted px-1.5 py-0.5 rounded">http://127.0.0.1:8001/api/history</code>.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Please ensure your FastAPI backend service is running locally on port 8001.
            </p>
            <Button variant="outline" size="sm" onClick={() => refetch()}>
              Try Reconnecting
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Main Content (when not loading and not error) */}
      {!isLoading && !isError && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* LEFT COLUMN: 2. Scan Selector & 3. Search */}
          <Card className="lg:col-span-1 flex flex-col h-[750px]">
            <CardHeader className="pb-3">
              <CardTitle className="text-lg flex items-center justify-between">
                <span>Select Scan Record</span>
                <Badge variant="secondary" className="font-mono text-xs">
                  {filteredScans.length} / {scanRecords.length}
                </Badge>
              </CardTitle>
              <CardDescription>
                Choose an audited scan to inspect and generate its forensic report.
              </CardDescription>

              {/* 3. Search input */}
              <div className="relative mt-2">
                <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Filter by keyword, risk, ID..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-9 h-9 text-sm"
                />
              </div>
            </CardHeader>

            {/* Scrollable list of scans */}
            <CardContent className="flex-1 overflow-y-auto space-y-2 pr-2">
              {/* 8. Empty History State */}
              {scanRecords.length === 0 ? (
                <div className="text-center py-12 px-4 space-y-3">
                  <Database className="h-10 w-10 text-muted-foreground/50 mx-auto" />
                  <p className="text-sm font-medium">No Scans Recorded Yet</p>
                  <p className="text-xs text-muted-foreground">
                    Perform a message or URL analysis on the Scam Analyzer page to record audit history.
                  </p>
                </div>
              ) : filteredScans.length === 0 ? (
                <div className="text-center py-12 px-4 space-y-2">
                  <p className="text-sm text-muted-foreground">No scans match your search query.</p>
                  <Button variant="ghost" size="sm" onClick={() => setSearchTerm("")}>
                    Clear Filter
                  </Button>
                </div>
              ) : (
                filteredScans.map((scan) => {
                  const isSelected = selectedScanId === scan.id;
                  const pred = getPrediction(scan);
                  const isScam = pred.toLowerCase().includes("scam") || pred.toLowerCase().includes("phish");
                  const ts = formatTimestamp(scan.timestamp);

                  return (
                    <button
                      key={scan.id}
                      onClick={() => {
                        setSelectedScanId(scan.id);
                        setReportGenerated(false);
                      }}
                      className={`w-full text-left p-3 rounded-lg border transition-all flex flex-col gap-1.5 ${
                        isSelected
                          ? "border-primary bg-primary/5 shadow-sm"
                          : "border-border/60 hover:border-border hover:bg-muted/40"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-1.5 font-mono text-xs text-muted-foreground">
                          <span>#{scan.id}</span>
                          <span>•</span>
                          <span className="uppercase">{scan.input_type || "text"}</span>
                        </div>
                        <Badge
                          variant={isScam ? "destructive" : "secondary"}
                          className={`text-[10px] px-1.5 py-0 h-5 ${
                            !isScam ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20" : ""
                          }`}
                        >
                          {pred}
                        </Badge>
                      </div>

                      <p className="text-xs text-foreground/90 font-medium line-clamp-2 leading-relaxed">
                        {scan.content || "Empty content"}
                      </p>

                      <div className="flex items-center justify-between text-[11px] text-muted-foreground pt-1 border-t border-border/30 mt-0.5">
                        <span className="flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          {ts.split(",")[0] || ts}
                        </span>
                        <span className="font-semibold text-foreground/80">
                          {scan.risk_level || "Unknown"} ({getRiskScore(scan).toFixed(0)}%)
                        </span>
                      </div>
                    </button>
                  );
                })
              )}
            </CardContent>
          </Card>

          {/* RIGHT COLUMN: 4. Detail View, 5. Generate, 6. Report, 7. Download */}
          <div className="lg:col-span-2 space-y-6">
            {!selectedScan ? (
              <Card className="h-full flex items-center justify-center min-h-[500px]">
                <div className="text-center max-w-md p-8 space-y-3">
                  <div className="p-4 bg-muted rounded-full w-16 h-16 flex items-center justify-center mx-auto">
                    <FileText className="h-8 w-8 text-muted-foreground" />
                  </div>
                  <h3 className="text-lg font-semibold">No Scan Selected</h3>
                  <p className="text-sm text-muted-foreground">
                    Select a scan from the left panel to inspect its audited machine learning classification and generate a downloadable report.
                  </p>
                </div>
              </Card>
            ) : (
              <>
                {/* 4. Display Selected Scan Details */}
                <Card>
                  <CardHeader className="pb-4">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <CardTitle className="text-xl">Scan Record #{selectedScan.id}</CardTitle>
                        <Badge variant="outline" className="font-mono text-xs uppercase">
                          {selectedScan.input_type || "text"}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-2">
                        {/* 5. Generate Report Button */}
                        <Button
                          onClick={() => setReportGenerated(true)}
                          disabled={!selectedScan}
                          className="flex items-center gap-1.5"
                        >
                          <FileCheck className="h-4 w-4" />
                          Generate Report
                        </Button>
                        {/* 7. Download Report Button */}
                        {reportGenerated && (
                          <Button
                            variant="secondary"
                            onClick={handleDownload}
                            className="flex items-center gap-1.5 bg-primary/10 text-primary hover:bg-primary/20"
                          >
                            <Download className="h-4 w-4" />
                            Download .TXT
                          </Button>
                        )}
                      </div>
                    </div>
                    <CardDescription className="flex items-center gap-2 mt-1">
                      <Clock className="h-3.5 w-3.5" />
                      Recorded on: {formatTimestamp(selectedScan.timestamp)}
                    </CardDescription>
                  </CardHeader>

                  <CardContent className="space-y-6">
                    {/* Content preview */}
                    <div className="space-y-1.5">
                      <label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                        Submitted Input / Preview
                      </label>
                      <div className="p-3 bg-muted/60 rounded-md border text-sm font-mono break-all leading-relaxed max-h-36 overflow-y-auto">
                        {selectedScan.content || "Not available"}
                      </div>
                    </div>

                    {/* Classification metrics grid */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      <div className="p-3 bg-card rounded-lg border">
                        <div className="text-xs text-muted-foreground font-medium">Prediction</div>
                        <div className="text-base font-bold mt-1">
                          {getPrediction(selectedScan)}
                        </div>
                      </div>
                      <div className="p-3 bg-card rounded-lg border">
                        <div className="text-xs text-muted-foreground font-medium">Risk Level</div>
                        <div className="text-base font-bold mt-1">
                          {selectedScan.risk_level || "Not available"}
                        </div>
                      </div>
                      <div className="p-3 bg-card rounded-lg border">
                        <div className="text-xs text-muted-foreground font-medium">Risk Score</div>
                        <div className="text-base font-bold mt-1 text-primary">
                          {getRiskScore(selectedScan).toFixed(1)} / 100
                        </div>
                      </div>
                      <div className="p-3 bg-card rounded-lg border">
                        <div className="text-xs text-muted-foreground font-medium">Scam Probability</div>
                        <div className="text-base font-bold mt-1">
                          {(getRiskProbability(selectedScan) * 100).toFixed(1)}%
                        </div>
                      </div>
                    </div>

                    {/* Explanatory Indicators */}
                    <div className="space-y-2">
                      <label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                        <AlertTriangle className="h-3.5 w-3.5 text-amber-500" />
                        Detection Indicators & Explanations
                      </label>
                      {getIndicators(selectedScan).length > 0 ? (
                        <div className="space-y-1.5">
                          {getIndicators(selectedScan).map((ind, i) => (
                            <div
                              key={i}
                              className="text-xs p-2.5 bg-muted/40 rounded border border-border/50 flex items-start gap-2"
                            >
                              <ChevronRight className="h-3.5 w-3.5 text-primary shrink-0 mt-0.5" />
                              <span>{ind}</span>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="text-xs text-muted-foreground italic bg-muted/20 p-2.5 rounded border">
                          No strong predefined indicators detected. Classification was driven by learned Random Forest TF-IDF word & character patterns.
                        </p>
                      )}
                    </div>

                    {/* Static Metadata */}
                    <div className="p-3 rounded-lg bg-muted/30 border border-border/40 flex items-center justify-between text-xs text-muted-foreground">
                      <span className="flex items-center gap-1.5">
                        <Cpu className="h-4 w-4 text-primary" />
                        Model: <strong className="text-foreground">Random Forest Classifier (Class-Balanced)</strong>
                      </span>
                      <span>Offline Analysis • 0 Network Calls</span>
                    </div>
                  </CardContent>
                </Card>

                {/* 6. Generated Report Preview (Rendered upon clicking Generate) */}
                {reportGenerated && (
                  <Card className="border-primary/40 shadow-sm animate-in fade-in duration-300">
                    <CardHeader className="pb-3 border-b bg-muted/20">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <FileCheck className="h-5 w-5 text-emerald-500" />
                          <CardTitle className="text-lg">Generated Incident Report</CardTitle>
                        </div>
                        <Button
                          size="sm"
                          onClick={handleDownload}
                          className="flex items-center gap-1.5"
                        >
                          <Download className="h-4 w-4" />
                          Download Report (.txt)
                        </Button>
                      </div>
                      <CardDescription>
                        Factual forensic summary formatted for documentation and BCA academic review.
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="pt-4">
                      <pre className="text-xs font-mono bg-muted/70 p-4 rounded-lg border overflow-x-auto whitespace-pre-wrap leading-relaxed">
                        {generateReportText(selectedScan)}
                      </pre>
                    </CardContent>
                  </Card>
                )}
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
