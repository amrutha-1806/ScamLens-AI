import * as React from "react";
import {
  Activity,
  AlertTriangle,
  BrainCircuit,
  CheckCircle2,
  Gauge,
  HelpCircle,
  Info,
  Sparkles,
} from "lucide-react";
import type { AnalysisResult, RuleHighlight, SupportedLanguage, TokenAttribution } from "@/lib/scamlens-types";
import { Badge, Card, cn } from "./ui";

interface PhraseRulePattern {
  regex: RegExp;
  categoryLabel: string;
  explanation: string;
}

const CLIENT_PHRASE_PATTERNS: PhraseRulePattern[] = [
  {
    regex: /\b(act\s+immediately|urgent\s+action\s+required|immediately\s+verify|within\s+24\s+hours)\b/gi,
    categoryLabel: "Urgency & Pressure Phrase",
    explanation: "Creates artificial time pressure so you act before verifying the sender.",
  },
  {
    regex: /\b(verify\s+your\s+account|update\s+your\s+kyc|complete\s+your\s+kyc|confirm\s+your\s+identity)\b/gi,
    categoryLabel: "Account Verification Lure",
    explanation: "Directs you to hand over login or KYC details under the guise of account verification.",
  },
  {
    regex: /\b((?:your\s+)?account\s+(?:will\s+be|has\s+been)\s+(?:blocked|suspended|frozen|closed|deactivated))\b/gi,
    categoryLabel: "Account Suspension Threat",
    explanation: "Uses fear of losing access to your bank or service account to force quick compliance.",
  },
  {
    regex: /\b(share\s+(?:your\s+)?otp|send\s+(?:your\s+)?otp|enter\s+(?:your\s+)?(?:otp|upi\s+pin|password|cvv))\b/gi,
    categoryLabel: "OTP / Credential Harvesting",
    explanation: "Requests a confidential one-time password or PIN that authorizes account takeover or money transfers.",
  },
  {
    regex: /\b(claim\s+your\s+(?:reward|prize|bonus|cashback)|you\s+have\s+won)\b/gi,
    categoryLabel: "Reward / Prize Lure",
    explanation: "Promises an unexpected reward, lottery, or cashback to entice you into clicking a link or paying a fee.",
  },
  {
    regex: /\b(urgent\s+payment\s+required|pay\s+immediately|avoid\s+disconnection|processing\s+fee)\b/gi,
    categoryLabel: "Coercive Payment Demand",
    explanation: "Demands an immediate fee or bill payment under threat of service disconnection or penalty.",
  },
  {
    regex: /(आपका\s+खाता\s+बंद|तुरंत\s+सत्यापित\s+करें|ओटीपी\s+साझा\s+करें|केवाईसी\s+अपडेट|इनाम\s+जीतें|बिजली\s+कनेक्शन\s+काट)/g,
    categoryLabel: "Hindi Scam Phrase (हिंदी चेतावनी)",
    explanation: "Matches a high-risk Hindi phishing phrase demanding urgent KYC, OTP sharing, or threatening account closure.",
  },
  {
    regex: /\b(aapka\s+(?:account|khata)\s+band|turant\s+verify|otp\s+share\s+karein|kyc\s+update\s+karein|bijli\s+connection\s+kat)\b/gi,
    categoryLabel: "Hinglish Scam Phrase",
    explanation: "Matches a Romanized Hindi (Hinglish) social-engineering phrase used in banking and utility scams.",
  },
  {
    regex: /(ನಿಮ್ಮ\s+ಖಾತೆ\s+ಬ್ಲಾಕ್|ತಕ್ಷಣ\s+ಪರಿಶೀಲಿಸಿ|ಒಟಿಪಿ\s+ಹಂಚಿಕೊಳ್ಳಿ|ಕೆವೈಸಿ\s+ಅಪ್ಡೇಟ್|ಬಹುಮಾನ\s+ಗೆದ್ದಿದ್ದೀರಿ)/g,
    categoryLabel: "Kannada Scam Phrase (ಕನ್ನಡ ಎಚ್ಚರಿಕೆ)",
    explanation: "Matches a high-risk Kannada phishing phrase threatening account suspension or requesting OTP/KYC details.",
  },
];

const ONE_SENTENCE_CATEGORY_EXPLANATIONS: Record<string, string> = {
  "Urgency & Pressure Phrase": "Creates artificial time pressure so you act before verifying the sender.",
  "Urgency / Pressure": "Uses urgent countdown language to rush you into making a mistake.",
  "Account Verification Lure": "Asks you to verify or update account details, a common tactic to capture login credentials.",
  "Account Threat": "Threatens account suspension or closure to trigger panic and immediate compliance.",
  "Account Suspension Threat": "Uses fear of losing access to your bank or service account to force quick compliance.",
  "Credential Request": "Asks for sensitive authentication secrets (OTP, PIN, CVV, or password) that legitimate institutions never request.",
  "OTP / Credential Harvesting": "Requests a confidential one-time password or PIN that authorizes account takeover or money transfers.",
  "Financial / Prize Lure": "Dangles free money, lottery winnings, or cashback rewards to trick you into paying fees or sharing bank details.",
  "Reward / Prize Lure": "Promises an unexpected reward, lottery, or cashback to entice you into clicking a link or paying a fee.",
  "Coercive Payment Demand": "Demands an immediate fee or bill payment under threat of service disconnection or penalty.",
  "Embedded Link": "Contains a web link or short URL that may lead to a spoofed credential-harvesting website.",
  "Hindi Scam Phrase": "Matches a known Hindi (Devanagari) social-engineering phrase targeting banking or utility users.",
  "Hinglish Scam Phrase": "Matches a known Hinglish phrase frequently used in SMS and WhatsApp fraud campaigns.",
  "Kannada Scam Phrase": "Matches a known Kannada social-engineering phrase targeting banking or KYC verification.",
};

export function explainIndicatorInOneSentence(indicator: string): string {
  const lower = indicator.toLowerCase();
  if (lower.includes("otp") || lower.includes("pin") || lower.includes("password") || lower.includes("credential")) {
    return "Legitimate banks and services never ask you to share your OTP, UPI PIN, or password via message.";
  }
  if (lower.includes("urgent") || lower.includes("immediately") || lower.includes("pressure") || lower.includes("24 hours")) {
    return "Scammers manufacture urgency so you react emotionally before checking official channels.";
  }
  if (lower.includes("blocked") || lower.includes("suspended") || lower.includes("kyc") || lower.includes("deactivated") || lower.includes("खाता बंद") || lower.includes("ಬ್ಲಾಕ್")) {
    return "Threatening sudden account or KYC suspension is a classic banking phishing tactic.";
  }
  if (lower.includes("prize") || lower.includes("reward") || lower.includes("won") || lower.includes("lottery") || lower.includes("cashback")) {
    return "Unsolicited prize or cashback notifications are designed to lure victims into advance-fee or phishing traps.";
  }
  if (lower.includes("url") || lower.includes("link") || lower.includes("http") || lower.includes("domain") || lower.includes("shortener")) {
    return "Suspicious or shortened links often hide lookalike websites built to steal your login or payment credentials.";
  }
  if (lower.includes("random forest") || lower.includes("classifier") || lower.includes("probability")) {
    return "The statistical n-gram vocabulary of this message closely resembles confirmed spam/phishing messages in our training corpus.";
  }
  return "This pattern frequently appears in social-engineering messages designed to deceive recipients.";
}

interface HighlightSpan {
  start: number;
  end: number;
  text: string;
  label: string;
  explanation: string;
  source: "model" | "rule";
  influence?: number;
}

function buildCombinedHighlightSpans(
  text: string,
  tokenAttributions: TokenAttribution[],
  ruleHighlights: RuleHighlight[]
): HighlightSpan[] {
  const spans: HighlightSpan[] = [];

  // 1. Add client-side multi-word phrase patterns first (longest phrases win)
  for (const pattern of CLIENT_PHRASE_PATTERNS) {
    pattern.regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.regex.exec(text)) !== null) {
      const start = match.index;
      const end = start + match[0].length;
      if (!spans.some((s) => !(end <= s.start || start >= s.end))) {
        spans.push({
          start,
          end,
          text: match[0],
          label: pattern.categoryLabel,
          explanation: pattern.explanation,
          source: "rule",
        });
      }
    }
  }

  // 2. Add backend rule highlights that don't overlap
  for (const rh of ruleHighlights) {
    if (rh.start >= 0 && rh.end <= text.length && rh.end > rh.start) {
      if (!spans.some((s) => !(rh.end <= s.start || rh.start >= s.end))) {
        const explanation =
          ONE_SENTENCE_CATEGORY_EXPLANATIONS[rh.category_label] ??
          explainIndicatorInOneSentence(rh.category_label);
        spans.push({
          start: rh.start,
          end: rh.end,
          text: text.slice(rh.start, rh.end),
          label: rh.category_label,
          explanation,
          source: "rule",
        });
      }
    }
  }

  // 3. Add positive-influence ML token attributions that don't overlap
  for (const tok of tokenAttributions) {
    if (tok.direction === "scam" && tok.influence > 0.005 && tok.start >= 0 && tok.end <= text.length) {
      if (!spans.some((s) => !(tok.end <= s.start || tok.start >= s.end))) {
        spans.push({
          start: tok.start,
          end: tok.end,
          text: text.slice(tok.start, tok.end),
          label: `ML Token Attribution (+${(tok.influence * 100).toFixed(1)}%)`,
          explanation: `Removing "${tok.text}" reduces the Random Forest scam score by ${(tok.influence * 100).toFixed(1)} percentage points.`,
          source: "model",
          influence: tok.influence,
        });
      }
    }
  }

  spans.sort((a, b) => a.start - b.start);
  return spans;
}

export function ExplainableRiskScoreCard({
  result,
  analyzedText,
  selectedLanguage = "en",
}: {
  result: AnalysisResult;
  analyzedText?: string | undefined;
  selectedLanguage?: SupportedLanguage | undefined;
}) {
  const score = Math.max(0, Math.min(100, Math.round(result.riskScore ?? result.riskProbability ?? 0)));
  const textToHighlight = analyzedText || result.explainability?.analyzed_text || "";
  const tokenAttributions = result.explainability?.token_attributions ?? [];
  const ruleHighlights = result.explainability?.rule_highlights ?? [];

  const highlightSpans = React.useMemo(
    () => (textToHighlight ? buildCombinedHighlightSpans(textToHighlight, tokenAttributions, ruleHighlights) : []),
    [textToHighlight, tokenAttributions, ruleHighlights]
  );

  const modelEvidenceItems = React.useMemo(
    () => tokenAttributions.filter((t) => t.direction === "scam" && t.influence > 0.004).slice(0, 6),
    [tokenAttributions]
  );

  const ruleWarningItems = React.useMemo(() => {
    const seen = new Set<string>();
    const list: Array<{ phrase: string; category: string; sentence: string }> = [];
    for (const sp of highlightSpans) {
      if (sp.source === "rule") {
        const key = `${sp.text.toLowerCase()}__${sp.label}`;
        if (!seen.has(key)) {
          seen.add(key);
          list.push({
            phrase: sp.text,
            category: sp.label,
            sentence: sp.explanation,
          });
        }
      }
    }
    return list;
  }, [highlightSpans]);

  const meterTone =
    score >= 90
      ? { color: "bg-rose-500", text: "text-rose-400", border: "border-rose-500/40", label: "Very High Risk (90–100)" }
      : score >= 70
        ? { color: "bg-orange-500", text: "text-orange-400", border: "border-orange-500/40", label: "High Risk (70–89)" }
        : score >= 40
          ? { color: "bg-amber-400", text: "text-amber-300", border: "border-amber-500/40", label: "Suspicious (40–69)" }
          : { color: "bg-emerald-500", text: "text-emerald-400", border: "border-emerald-500/40", label: "Low Risk (0–39)" };

  // Build segments for inline message highlighting
  const renderedSegments = React.useMemo(() => {
    if (!textToHighlight) return [];
    const out: Array<{ text: string; span?: HighlightSpan }> = [];
    let cursor = 0;
    for (const sp of highlightSpans) {
      if (sp.start > cursor) {
        out.push({ text: textToHighlight.slice(cursor, sp.start) });
      }
      out.push({ text: textToHighlight.slice(sp.start, sp.end), span: sp });
      cursor = sp.end;
    }
    if (cursor < textToHighlight.length) {
      out.push({ text: textToHighlight.slice(cursor) });
    }
    return out;
  }, [textToHighlight, highlightSpans]);

  return (
    <Card className="p-5 space-y-5 border-slate-800/90 bg-slate-900/75" data-testid="explainable-risk-score-card">
      {/* Top Header & 0-100 Visual Risk Meter */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <Gauge className="h-5 w-5 text-cyan-400" />
            <h3 className="text-base font-bold text-white">Explainable Risk Score & Evidence Breakdown</h3>
            <Badge tone={score >= 70 ? "danger" : score >= 40 ? "warning" : "success"}>
              {score} / 100 ({result.riskLevel})
            </Badge>
          </div>
          <p className="text-xs text-slate-400">
            Transparent 0–100 risk index separating Random Forest ML token attributions from deterministic rule-based phrase warnings.
          </p>
        </div>

        {/* Visual Segmented Risk Meter */}
        <div className="w-full lg:w-80 space-y-1.5" data-testid="visual-risk-meter">
          <div className="flex items-center justify-between text-xs">
            <span className="font-mono text-slate-400">RISK METER (0–100)</span>
            <span className={cn("font-mono font-bold", meterTone.text)}>{score} / 100</span>
          </div>
          <div className="relative h-3 w-full overflow-hidden rounded-full bg-slate-950 border border-slate-800 p-0.5">
            <div
              className={cn("h-full rounded-full transition-all duration-500", meterTone.color)}
              style={{ width: `${Math.max(4, score)}%` }}
            />
          </div>
          <div className="grid grid-cols-4 text-[10px] font-mono text-slate-500">
            <span>0–39 Low</span>
            <span className="text-center">40–69 Susp.</span>
            <span className="text-center">70–89 High</span>
            <span className="text-right">90+ Very High</span>
          </div>
        </div>
      </div>

      {/* How the Score is Calculated (Methodology Box) */}
      <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-3.5 text-xs text-slate-300 space-y-1.5">
        <div className="flex items-center gap-1.5 font-semibold text-cyan-300">
          <Info className="h-4 w-4 shrink-0" />
          <span>How this 0–100 Risk Score is Calculated</span>
        </div>
        <p className="leading-relaxed text-slate-400">
          For text messages, the base score is derived from the <strong className="text-slate-200">Random Forest ensemble tree-vote proportion</strong> (across 10,043 TF-IDF word/character n-gram and statistical features), combined with <strong className="text-slate-200">deterministic rule-based phrase detectors</strong> for high-risk OTP, KYC, urgent payment, and regional (Hindi/Hinglish/Kannada) patterns.{" "}
          <span className="text-slate-300 font-medium">
            Note: This 0–100 score is an uncalibrated risk index, not a calibrated statistical probability of verified financial fraud.
          </span>
        </p>
      </div>

      {/* Highlighted Message Inspection */}
      {textToHighlight && (
        <div className="space-y-2.5" data-testid="highlighted-message-container">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
              In-Message Phrase & Token Highlighting
            </span>
            <div className="flex flex-wrap items-center gap-3 text-[11px]">
              <span className="inline-flex items-center gap-1.5 text-amber-300">
                <span className="h-2.5 w-2.5 rounded-sm bg-amber-500/30 border border-amber-400/60" />
                Rule-Based Phrase Warning
              </span>
              <span className="inline-flex items-center gap-1.5 text-rose-300">
                <span className="h-2.5 w-2.5 rounded-sm bg-rose-500/30 border border-rose-400/60" />
                ML Model Token Evidence
              </span>
            </div>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-950/90 p-4 text-sm leading-7 text-slate-200 font-sans whitespace-pre-wrap break-words">
            {renderedSegments.map((seg, idx) => {
              if (!seg.span) {
                return <React.Fragment key={idx}>{seg.text}</React.Fragment>;
              }
              const isRule = seg.span.source === "rule";
              return (
                <mark
                  key={idx}
                  title={`${seg.span.label}: ${seg.span.explanation}`}
                  data-testid={isRule ? "highlight-rule-phrase" : "highlight-model-token"}
                  className={cn(
                    "rounded px-1.5 py-0.5 font-medium mx-0.5 border transition-colors cursor-help",
                    isRule
                      ? "bg-amber-500/20 border-amber-400/50 text-amber-200"
                      : "bg-rose-500/20 border-rose-400/50 text-rose-200"
                  )}
                >
                  {seg.text}
                </mark>
              );
            })}
          </div>
        </div>
      )}

      {/* Side-by-Side Comparison: Actual Model Evidence vs Rule-Based Warnings */}
      <div className="grid gap-4 md:grid-cols-2">
        {/* Column 1: Actual ML Model Evidence */}
        <div
          className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 space-y-3"
          data-testid="model-evidence-panel"
        >
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <BrainCircuit className="h-4 w-4 text-rose-400" />
              <h4 className="text-xs font-bold uppercase tracking-wider text-white">
                1. Actual ML Model Evidence
              </h4>
            </div>
            <Badge tone="danger">Random Forest</Badge>
          </div>
          <p className="text-[11px] text-slate-400">
            Measured by leave-one-out perturbation on the trained English Random Forest classifier:
          </p>

          {modelEvidenceItems.length > 0 ? (
            <ul className="space-y-2">
              {modelEvidenceItems.map((item, idx) => (
                <li
                  key={idx}
                  className="rounded-lg border border-rose-500/20 bg-rose-950/15 px-3 py-2 text-xs space-y-0.5"
                >
                  <div className="flex items-center justify-between font-semibold text-rose-200">
                    <span>Token: &ldquo;{item.text}&rdquo;</span>
                    <span className="font-mono text-[11px] text-rose-300">
                      +{(item.influence * 100).toFixed(1)}% tree vote impact
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-300">
                    Removing &ldquo;{item.text}&rdquo; lowers the classifier&apos;s scam tree-vote proportion by{" "}
                    {(item.influence * 100).toFixed(1)}%.
                  </p>
                </li>
              ))}
            </ul>
          ) : (
            <div className="rounded-lg border border-slate-800/80 bg-slate-900/50 p-3 text-xs text-slate-400 flex items-start gap-2">
              <CheckCircle2 className="h-4 w-4 text-slate-500 shrink-0 mt-0.5" />
              <span>
                {selectedLanguage !== "en"
                  ? "No single English ML token dominated the tree-vote shift; primary detection relied on regional/structural rules."
                  : "No single English token caused a large individual tree-vote shift in the Random Forest model."}
              </span>
            </div>
          )}
        </div>

        {/* Column 2: Rule-Based Warnings & Phrase Triggers */}
        <div
          className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 space-y-3"
          data-testid="rule-warnings-panel"
        >
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-400" />
              <h4 className="text-xs font-bold uppercase tracking-wider text-white">
                2. Rule-Based Phrase & Pattern Warnings
              </h4>
            </div>
            <Badge tone="warning">Deterministic Rules</Badge>
          </div>
          <p className="text-[11px] text-slate-400">
            Explicit social-engineering phrases and structural indicators explained in one sentence:
          </p>

          {ruleWarningItems.length > 0 || result.indicators.length > 0 ? (
            <ul className="space-y-2">
              {ruleWarningItems.slice(0, 4).map((rw, idx) => (
                <li
                  key={`rw-${idx}`}
                  className="rounded-lg border border-amber-500/25 bg-amber-950/15 px-3 py-2 text-xs space-y-0.5"
                >
                  <div className="flex items-center justify-between gap-2 font-semibold text-amber-200">
                    <span>&ldquo;{rw.phrase}&rdquo;</span>
                    <span className="text-[10px] font-mono uppercase text-amber-300/90">{rw.category}</span>
                  </div>
                  <p className="text-[11px] text-slate-300">{rw.sentence}</p>
                </li>
              ))}
              {result.indicators.slice(0, 4).map((ind, idx) => (
                <li
                  key={`ind-${idx}`}
                  className="rounded-lg border border-slate-800 bg-slate-900/70 px-3 py-2 text-xs space-y-0.5"
                >
                  <div className="font-semibold text-slate-200 flex items-center gap-1.5">
                    <Sparkles className="h-3 w-3 text-cyan-400 shrink-0" />
                    <span>{ind}</span>
                  </div>
                  <p className="text-[11px] text-slate-400">{explainIndicatorInOneSentence(ind)}</p>
                </li>
              ))}
            </ul>
          ) : (
            <div className="rounded-lg border border-slate-800/80 bg-slate-900/50 p-3 text-xs text-slate-400 flex items-start gap-2">
              <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
              <span>No high-risk rule-based scam phrases were triggered in this text.</span>
            </div>
          )}
        </div>
      </div>
    </Card>
  );
}
