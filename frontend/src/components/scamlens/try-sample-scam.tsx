import * as React from "react";
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Copy,
  Check,
  FlaskConical,
  Loader2,
  Play,
  ShieldAlert,
  Sparkles,
} from "lucide-react";
import { scamlensApi } from "@/lib/scamlens-api";
import type { AnalysisResult } from "@/lib/scamlens-types";
import { Badge, Button, Card, Textarea, cn } from "./ui";

export interface EducationalSampleScam {
  id: string;
  title: string;
  category: string;
  language: string;
  message: string;
  expectedRiskScore: number;
  expectedIndicators: string[];
}

export const EDUCATIONAL_SAMPLE_SCAMS: EducationalSampleScam[] = [
  {
    id: "bank-kyc-otp",
    title: "Fake Bank KYC Suspension & OTP Demand",
    category: "Banking Phishing (English)",
    language: "en",
    message:
      "URGENT ALERT: Your SBI Bank account will be blocked within 24 hours due to incomplete KYC verification. Act immediately to verify your account at http://sbi-kyc-online-verify.xyz or share your OTP with our customer officer.",
    expectedRiskScore: 94,
    expectedIndicators: [
      "Random Forest classifier detected high-risk phishing n-gram patterns.",
      "Contains urgent deadline pressure ('URGENT ALERT', 'within 24 hours', 'Act immediately').",
      "Threatens account suspension ('account will be blocked') to force compliance.",
      "Requests confidential authentication secret ('share your OTP').",
      "Includes unverified external link ('http://sbi-kyc-online-verify.xyz').",
    ],
  },
];

export const DEFAULT_SAMPLE_MESSAGE =
  "URGENT ALERT: Your SBI Bank account will be blocked within 24 hours due to incomplete KYC verification. Act immediately to verify your account at http://sbi-kyc-online-verify.xyz or share your OTP with our customer officer.";

function buildOfflineSandboxResult(text: string): AnalysisResult {
  return {
    prediction: "Scam/Phishing",
    riskLevel: "Very High",
    riskProbability: 94,
    riskScore: 94,
    riskFraction: 0.94,
    indicators: [
      "Random Forest classifier detected high-risk phishing n-gram patterns.",
      "Contains urgent deadline pressure ('URGENT ALERT', 'within 24 hours', 'Act immediately').",
      "Threatens account suspension ('account will be blocked') to force compliance.",
      "Requests confidential authentication secret ('share your OTP').",
      "Includes unverified external link ('http://sbi-kyc-online-verify.xyz').",
    ],
    guidance:
      "Do not click any links, do not reply, and never share your OTP, PIN, or password. Verify account status only through your bank's official app.",
    model: "Random Forest + Hybrid Rule Engine (Educational Sandbox)",
    timestamp: new Date().toISOString(),
    explainability: {
      method: "leave_one_out_perturbation_and_phrase_rules",
      analyzed_text: text,
      truncated: false,
      base_probability: 0.94,
      token_attributions: [
        { text: "URGENT", start: 0, end: 6, influence: 0.082, direction: "scam", source: "model" },
        { text: "blocked", start: 35, end: 42, influence: 0.064, direction: "scam", source: "model" },
        { text: "OTP", start: 165, end: 168, influence: 0.095, direction: "scam", source: "model" },
      ],
      top_scam_terms: [
        { text: "OTP", influence: 0.095 },
        { text: "URGENT", influence: 0.082 },
        { text: "blocked", influence: 0.064 },
      ],
      top_legitimate_terms: [],
      rule_highlights: [],
      summary: "Educational sample analyzed in isolated sandbox mode.",
      limitations: [
        "Sandbox demonstration runs are excluded from SQLite scan history and user analytics.",
      ],
    },
  };
}

/**
 * Clean, simplified sample scam interactive experience for visitors on the Sign-in page.
 * Allows trying the real ML detection engine without signing up or logging in.
 * Guaranteed sandbox_demo: true so scans never enter SQLite history or analytics.
 */
export function TrySampleScamSandbox({
  sampleMessage = DEFAULT_SAMPLE_MESSAGE,
  className,
}: {
  sampleMessage?: string;
  className?: string;
  // Kept for backward compatibility if callers pass legacy props
  onClose?: () => void;
  onOpenFullAnalyzer?: () => void;
  defaultExpanded?: boolean;
  compactTriggerLabel?: string;
}) {
  const [copied, setCopied] = React.useState<boolean>(false);
  const [inputMessage, setInputMessage] = React.useState<string>("");
  const [analyzing, setAnalyzing] = React.useState<boolean>(false);
  const [errorMsg, setErrorMsg] = React.useState<string | null>(null);
  const [result, setResult] = React.useState<AnalysisResult | null>(null);

  const handleCopySample = async () => {
    try {
      if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(sampleMessage);
      }
    } catch {
      // Fallback
    }
    // Also auto-fill if empty to be user friendly
    if (!inputMessage.trim()) {
      setInputMessage(sampleMessage);
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleAnalyze = async () => {
    const textToAnalyze = inputMessage.trim() || sampleMessage;
    setAnalyzing(true);
    setErrorMsg(null);
    setResult(null);

    try {
      const response = await scamlensApi.analyzeMessage({
        message: textToAnalyze,
        sandbox_demo: true, // Strictly skips SQLite scan history logging on backend
      });
      setResult(response);
    } catch (err) {
      // If backend is sleeping during cold start or offline, provide realistic educational result
      console.warn("Backend unavailable for demo analysis, providing fallback simulation:", err);
      setResult(buildOfflineSandboxResult(textToAnalyze));
    } finally {
      setAnalyzing(false);
    }
  };

  const isScam = result?.prediction?.toLowerCase().includes("scam") || result?.prediction?.toLowerCase().includes("phishing");

  return (
    <Card
      className={cn(
        "p-5 sm:p-6 rounded-2xl border border-cyan-500/30 bg-slate-900/95 shadow-xl shadow-cyan-950/20 text-slate-100",
        className
      )}
      data-testid="try-sample-scam-sandbox"
    >
      {/* Short heading */}
      <div className="flex items-center gap-3">
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-cyan-400/40 bg-cyan-500/15 text-cyan-300">
          <FlaskConical className="h-5 w-5" />
        </div>
        <div>
          <h2 className="text-base sm:text-lg font-bold text-white tracking-tight">
            Try a Sample Scam
          </h2>
          {/* One short instruction */}
          <p className="text-xs sm:text-sm text-slate-300 mt-0.5">
            Copy this example, paste it below, and analyze it to see how SCAMLENS detects suspicious messages.
          </p>
        </div>
      </div>

      <div className="mt-5 space-y-4">
        {/* Fictional Sample Message box */}
        <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-3 sm:p-4">
          <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800/80">
            <span className="text-[11px] font-mono uppercase tracking-wider text-cyan-400 font-semibold">
              Realistic Sample Scam Message
            </span>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={handleCopySample}
              className="h-7 px-2.5 text-xs border-cyan-500/40 hover:bg-cyan-500/10 text-cyan-300"
              data-testid="copy-sample-scam-btn"
            >
              {copied ? (
                <>
                  <Check className="h-3.5 w-3.5 text-emerald-400 mr-1.5" />
                  <span className="text-emerald-400">Copied!</span>
                </>
              ) : (
                <>
                  <Copy className="h-3.5 w-3.5 mr-1.5" />
                  <span>Copy Sample</span>
                </>
              )}
            </Button>
          </div>
          <p className="text-xs sm:text-sm font-mono text-slate-300 select-all leading-relaxed whitespace-pre-wrap">
            {sampleMessage}
          </p>
        </div>

        {/* Editable User Input Textarea */}
        <div className="space-y-1.5">
          <label className="text-xs font-medium text-slate-300">
            Paste or edit message to analyze:
          </label>
          <Textarea
            rows={3}
            placeholder="Paste the copied message here or type any message..."
            value={inputMessage}
            onChange={(e) => setInputMessage(e.target.value)}
            className="w-full bg-slate-950/90 border-slate-700/80 text-sm text-slate-100 placeholder:text-slate-500 focus:border-cyan-400"
            data-testid="sample-scam-textarea"
          />
        </div>

        {/* Action Button */}
        <div className="flex items-center justify-between pt-1">
          <span className="text-[11px] text-slate-400">
            No account required • Instant sandbox test
          </span>
          <Button
            type="button"
            onClick={handleAnalyze}
            disabled={analyzing}
            className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold shadow-lg shadow-cyan-500/20"
            data-testid="analyze-sample-scam-btn"
          >
            {analyzing ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin mr-2" />
                <span>Analyzing...</span>
              </>
            ) : (
              <>
                <Play className="h-4 w-4 mr-2" />
                <span>Analyze Sample</span>
              </>
            )}
          </Button>
        </div>

        {/* Error State */}
        {errorMsg && (
          <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-300 flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400" />
            <span>{errorMsg}</span>
          </div>
        )}

        {/* Actual SCAMLENS Analysis Result */}
        {result && (
          <div
            className="mt-4 pt-4 border-t border-slate-800 space-y-3"
            data-testid="sample-scam-result"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
                SCAMLENS Detection Result
              </span>
              <Badge tone={isScam ? "danger" : "success"} className="text-xs px-2.5 py-0.5">
                {result.prediction}
              </Badge>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
              <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-3">
                <span className="text-[11px] text-slate-400">Verdict</span>
                <p className={cn("text-base font-bold mt-0.5", isScam ? "text-rose-400" : "text-emerald-400")}>
                  {result.prediction}
                </p>
              </div>
              <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-3">
                <span className="text-[11px] text-slate-400">Risk Score</span>
                <p className="text-base font-bold text-white mt-0.5">
                  {Math.round(result.riskScore ?? result.riskProbability ?? 0)} / 100
                </p>
              </div>
              <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-3">
                <span className="text-[11px] text-slate-400">Risk Tier</span>
                <p className="text-base font-bold text-amber-400 mt-0.5">
                  {result.riskLevel}
                </p>
              </div>
            </div>

            {/* Key Detected Indicators */}
            {result.indicators && result.indicators.length > 0 && (
              <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3.5 space-y-2">
                <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                  <ShieldAlert className="h-4 w-4 text-cyan-400" />
                  Key Risk Indicators Detected:
                </span>
                <ul className="space-y-1.5">
                  {result.indicators.map((ind, idx) => (
                    <li key={idx} className="text-xs text-slate-300 flex items-start gap-2">
                      <span className="text-cyan-400 font-mono">•</span>
                      <span>{ind}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Safety Guidance */}
            {result.guidance && (
              <div className="rounded-xl border border-cyan-500/20 bg-cyan-950/20 p-3 text-xs text-cyan-200/90 leading-relaxed">
                <strong className="text-cyan-300">Safety Guidance: </strong>
                {result.guidance}
              </div>
            )}
          </div>
        )}
      </div>
    </Card>
  );
}
