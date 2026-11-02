import { useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  BrainCircuit,
  Info,
  Sparkles,
  AlertTriangle,
  CheckCircle2,
  Globe2,
  HelpCircle,
  TrendingUp,
  TrendingDown,
  Layers,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useScamlensPreferences } from "@/lib/scamlens-preferences";
import type { ExplainabilityData, LanguageData, RuleHighlight, TokenAttribution } from "@/lib/scamlens-types";

interface ExplainabilityProps {
  explainability?: ExplainabilityData | null;
  languageInfo?: LanguageData | null;
}

interface SpanItem {
  text: string;
  start: number;
  end: number;
  attr?: TokenAttribution;
  rule?: RuleHighlight;
}

export function InteractiveHighlightedText({
  text,
  attributions,
  rules,
}: {
  text: string;
  attributions: TokenAttribution[];
  rules: RuleHighlight[];
}) {
  const [selected, setSelected] = useState<SpanItem | null>(null);

  // Merge spans from attributions and rules
  const spans: SpanItem[] = [];
  const boundaries = new Set<number>([0, text.length]);

  for (const a of attributions) {
    if (a.start >= 0 && a.end <= text.length && a.start < a.end) {
      boundaries.add(a.start);
      boundaries.add(a.end);
    }
  }

  for (const r of rules) {
    if (r.start >= 0 && r.end <= text.length && r.start < r.end) {
      boundaries.add(r.start);
      boundaries.add(r.end);
    }
  }

  const sortedPoints = Array.from(boundaries).sort((a, b) => a - b);

  for (let i = 0; i < sortedPoints.length - 1; i++) {
    const s = sortedPoints[i];
    const e = sortedPoints[i + 1];
    const spanText = text.slice(s, e);
    if (!spanText) continue;

    // Find attribution covering this span
    const attr = attributions.find((a) => a.start <= s && a.end >= e && a.direction !== "neutral");
    // Find rule covering this span
    const rule = rules.find((r) => r.start <= s && r.end >= e);

    spans.push({ text: spanText, start: s, end: e, attr, rule });
  }

  return (
    <div className="space-y-3">
      <div className="relative rounded-lg border border-border bg-card p-4 font-sans text-sm leading-relaxed text-foreground shadow-2xs dark:bg-slate-950/70">
        <div className="flex flex-wrap items-center gap-1.5 leading-7">
          {spans.map((span, idx) => {
            const hasScamAttr = span.attr && span.attr.direction === "scam";
            const hasLegitAttr = span.attr && span.attr.direction === "legitimate";
            const hasRule = Boolean(span.rule);
            const isClickable = hasScamAttr || hasLegitAttr || hasRule;
            const isSelected = selected?.start === span.start && selected?.end === span.end;

            if (!isClickable) {
              return <span key={idx}>{span.text}</span>;
            }

            return (
              <button
                key={idx}
                type="button"
                onClick={() => setSelected(isSelected ? null : span)}
                className={cn(
                  "relative inline-flex items-center rounded px-1.5 py-0.5 text-xs font-semibold transition-all duration-150 focus:outline-none focus:ring-2 focus:ring-primary/50",
                  hasScamAttr &&
                    "border border-danger/40 bg-danger/15 text-danger hover:bg-danger/25 dark:border-rose-500/40 dark:bg-rose-950/40 dark:text-rose-300",
                  hasLegitAttr &&
                    "border border-safe/40 bg-safe/15 text-safe hover:bg-safe/25 dark:border-emerald-500/40 dark:bg-emerald-950/40 dark:text-emerald-300",
                  !hasScamAttr &&
                    !hasLegitAttr &&
                    hasRule &&
                    "border border-warning/40 bg-warning/15 text-warning hover:bg-warning/25 dark:border-amber-500/40 dark:bg-amber-950/40 dark:text-amber-300",
                  isSelected && "ring-2 ring-primary ring-offset-1 shadow-sm"
                )}
                title={
                  hasScamAttr
                    ? `Word increased scam probability by ${(span.attr!.influence * 100).toFixed(1)}%`
                    : hasLegitAttr
                      ? `Word shifted verdict towards Legitimate by ${Math.abs(span.attr!.influence * 100).toFixed(1)}%`
                      : span.rule?.category_label ?? "Keyword indicator"
                }
              >
                <span>{span.text}</span>
                {hasScamAttr && (
                  <span className="ml-1 font-mono text-[9px] font-bold opacity-85">
                    +{(span.attr!.influence * 100).toFixed(0)}%
                  </span>
                )}
                {hasLegitAttr && (
                  <span className="ml-1 font-mono text-[9px] font-bold opacity-85">
                    {(span.attr!.influence * 100).toFixed(0)}%
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* Selected Token Inspector Card */}
      <AnimatePresence>
        {selected && (
          <motion.div
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -4 }}
            className="flex items-start gap-3 rounded-lg border border-primary/30 bg-primary/5 p-3.5 text-xs text-foreground dark:border-cyan-500/30 dark:bg-cyan-950/20"
          >
            <div className="grid size-7 shrink-0 place-items-center rounded bg-primary/20 text-primary dark:bg-cyan-500/20 dark:text-cyan-400">
              <Sparkles className="size-4" />
            </div>
            <div className="min-w-0 flex-1 space-y-1">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-semibold text-foreground">
                  Inspected Token: <strong className="font-mono text-primary dark:text-cyan-300">"{selected.text}"</strong>
                </span>
                <button
                  type="button"
                  onClick={() => setSelected(null)}
                  className="text-[11px] text-muted-foreground hover:text-foreground"
                >
                  Dismiss
                </button>
              </div>

              {selected.attr && (
                <div className="flex flex-wrap items-center gap-2 pt-0.5">
                  <span
                    className={cn(
                      "inline-flex items-center gap-1 rounded px-2 py-0.5 font-mono text-[10px] font-bold",
                      selected.attr.direction === "scam"
                        ? "bg-danger/20 text-danger dark:text-rose-300"
                        : "bg-safe/20 text-safe dark:text-emerald-300"
                    )}
                  >
                    {selected.attr.direction === "scam" ? (
                      <TrendingUp className="size-3" />
                    ) : (
                      <TrendingDown className="size-3" />
                    )}
                    Impact: {(selected.attr.influence * 100).toFixed(2)}%
                  </span>
                  <span className="text-[11px] text-muted-foreground">
                    {selected.attr.direction === "scam"
                      ? "Removing this word lowers the model's scam probability."
                      : "Removing this word increases the model's scam probability."}
                  </span>
                </div>
              )}

              {selected.rule && (
                <p className="text-[11px] text-muted-foreground">
                  <strong className="text-foreground">Category:</strong> {selected.rule.category_label} (Deterministic
                  heuristic rule)
                </p>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

export function ExplainabilityCard({ explainability }: { explainability: ExplainabilityData }) {
  const { shouldReduceMotion } = useScamlensPreferences();

  return (
    <motion.div
      initial={shouldReduceMotion ? false : { opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: shouldReduceMotion ? 0 : 0.25 }}
      className="space-y-4 rounded-xl border border-primary/25 bg-card p-4 shadow-panel sm:p-5 dark:border-cyan-500/25 dark:bg-slate-950/70"
    >
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border pb-3.5 dark:border-slate-800">
        <div className="flex items-center gap-2.5">
          <div className="grid size-9 place-items-center rounded-lg bg-primary/10 text-primary dark:bg-cyan-500/10 dark:text-cyan-400">
            <BrainCircuit className="size-5" />
          </div>
          <div>
            <h4 className="text-sm font-bold text-foreground">Explainable AI (Perturbation Attribution)</h4>
            <p className="text-[11px] text-muted-foreground">
              Token-level leave-one-word-out impact on the trained Random Forest classifier.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1 rounded-full border border-primary/25 bg-primary/5 px-2.5 py-0.5 text-[10px] font-semibold text-primary dark:border-cyan-500/30 dark:text-cyan-300">
            <Layers className="size-3" />
            Zero Guesswork
          </span>
        </div>
      </div>

      {/* Model explanation summary paragraph */}
      {explainability.summary && (
        <div className="rounded-lg border border-border bg-secondary/30 p-3.5 text-xs leading-relaxed text-foreground dark:bg-slate-900/60">
          <p className="font-medium">{explainability.summary}</p>
        </div>
      )}

      {/* Interactive Token-Level Highlighter */}
      <div>
        <div className="mb-2 flex items-center justify-between">
          <span className="text-xs font-semibold text-foreground">Interactive Word Attribution Inspector</span>
          <span className="text-[10px] text-muted-foreground">Click highlighted words for individual weight</span>
        </div>

        <InteractiveHighlightedText
          text={explainability.analyzed_text}
          attributions={explainability.token_attributions}
          rules={explainability.rule_highlights}
        />
      </div>

      {/* Legend & Breakdown Columns */}
      <div className="grid gap-3 pt-1 sm:grid-cols-2">
        {/* Words pushing towards Scam */}
        <div className="rounded-lg border border-danger/30 bg-danger/5 p-3 dark:border-rose-900/40 dark:bg-rose-950/20">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-danger dark:text-rose-300">
            <TrendingUp className="size-4" />
            <span>Top Scam Indicators (Pushed Score Up)</span>
          </div>
          {explainability.top_scam_terms.length ? (
            <div className="mt-2.5 flex flex-wrap gap-1.5">
              {explainability.top_scam_terms.map((t) => (
                <span
                  key={t.text}
                  className="inline-flex items-center gap-1 rounded border border-danger/40 bg-danger/10 px-2 py-0.5 font-mono text-xs font-bold text-danger dark:border-rose-500/40 dark:text-rose-300"
                >
                  {t.text}
                  <span className="text-[10px] opacity-80">+{(t.influence * 100).toFixed(1)}%</span>
                </span>
              ))}
            </div>
          ) : (
            <p className="mt-2 text-xs text-muted-foreground">No single word raised the scam probability by &gt; 0.5%.</p>
          )}
        </div>

        {/* Words pushing towards Legitimate */}
        <div className="rounded-lg border border-safe/30 bg-safe/5 p-3 dark:border-emerald-900/40 dark:bg-emerald-950/20">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-safe dark:text-emerald-300">
            <TrendingDown className="size-4" />
            <span>Top Legitimate Terms (Lowered Risk)</span>
          </div>
          {explainability.top_legitimate_terms.length ? (
            <div className="mt-2.5 flex flex-wrap gap-1.5">
              {explainability.top_legitimate_terms.map((t) => (
                <span
                  key={t.text}
                  className="inline-flex items-center gap-1 rounded border border-safe/40 bg-safe/10 px-2 py-0.5 font-mono text-xs font-bold text-safe dark:border-emerald-500/40 dark:text-emerald-300"
                >
                  {t.text}
                  <span className="text-[10px] opacity-80">{(t.influence * 100).toFixed(1)}%</span>
                </span>
              ))}
            </div>
          ) : (
            <p className="mt-2 text-xs text-muted-foreground">No single word strongly pulled the score towards legitimate.</p>
          )}
        </div>
      </div>

      {/* Scientific Transparency & Limitations */}
      <div className="rounded-lg border border-border bg-secondary/20 p-3 text-[11px] leading-relaxed text-muted-foreground dark:bg-slate-900/40">
        <div className="flex items-center gap-1.5 font-semibold text-foreground">
          <Info className="size-3.5 text-primary" />
          <span>Scientific Methodology &amp; Boundaries</span>
        </div>
        <ul className="mt-1.5 list-inside list-disc space-y-1">
          {explainability.limitations.map((lim, idx) => (
            <li key={idx}>{lim}</li>
          ))}
        </ul>
      </div>
    </motion.div>
  );
}

export function LanguageTransparencyCard({ languageInfo }: { languageInfo: LanguageData }) {
  const { shouldReduceMotion } = useScamlensPreferences();
  const script = languageInfo.script_info;
  const isIndic = script.has_indic_script;
  const hasRegional = languageInfo.regional_signals.total_regional_signals > 0;

  return (
    <motion.div
      initial={shouldReduceMotion ? false : { opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: shouldReduceMotion ? 0 : 0.25 }}
      className="space-y-3.5 rounded-xl border border-border bg-card p-4 shadow-panel sm:p-5 dark:bg-slate-950/70"
    >
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border pb-3 dark:border-slate-800">
        <div className="flex items-center gap-2">
          <Globe2 className="size-4 text-primary" />
          <h4 className="text-xs font-bold uppercase tracking-wider text-foreground">
            Multilingual Script &amp; Regional Analysis
          </h4>
        </div>
        <span className="rounded-full border border-border bg-secondary px-2.5 py-0.5 font-mono text-[10px] font-semibold text-foreground">
          Script: {script.primary_script}
        </span>
      </div>

      {/* Script details */}
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="font-semibold text-foreground">Detected Scripts:</span>
        {script.scripts_detected.length ? (
          script.scripts_detected.map((s) => (
            <span
              key={s}
              className="rounded border border-border bg-secondary px-2 py-0.5 font-medium text-foreground"
            >
              {s}
            </span>
          ))
        ) : (
          <span className="text-muted-foreground">Standard text</span>
        )}
      </div>

      {/* Regional Transliterated Patterns (Hinglish / Kanglish) */}
      {hasRegional && (
        <div className="rounded-lg border border-warning/35 bg-warning/5 p-3 dark:border-amber-900/40 dark:bg-amber-950/20">
          <p className="flex items-center gap-1.5 text-xs font-semibold text-warning dark:text-amber-300">
            <AlertTriangle className="size-3.5" />
            Detected Transliterated Scam Signals ({languageInfo.regional_signals.total_regional_signals})
          </p>
          <div className="mt-2 space-y-1.5">
            {languageInfo.regional_signals.hinglish_signals.map((h, i) => (
              <div key={`h-${i}`} className="flex items-center justify-between text-[11px]">
                <span className="font-mono font-bold text-foreground">"{h.matched_text}"</span>
                <span className="text-muted-foreground">{h.description} (Hinglish)</span>
              </div>
            ))}
            {languageInfo.regional_signals.kanglish_signals.map((k, i) => (
              <div key={`k-${i}`} className="flex items-center justify-between text-[11px]">
                <span className="font-mono font-bold text-foreground">"{k.matched_text}"</span>
                <span className="text-muted-foreground">{k.description} (Kanglish)</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Model Scope Transparency Notice (Strict Honesty Guarantee) */}
      {isIndic && (
        <div className="rounded-lg border border-primary/30 bg-primary/5 p-3 text-xs leading-relaxed text-foreground dark:border-cyan-500/30 dark:bg-cyan-950/20">
          <div className="flex items-center gap-1.5 font-semibold text-primary dark:text-cyan-300">
            <Info className="size-3.5" />
            <span>ML Scope Transparency: Native Indic Script Detected</span>
          </div>
          <p className="mt-1 text-[11px] leading-relaxed text-muted-foreground dark:text-slate-300">
            The core machine learning Random Forest classifier was trained on the English UCI SMS Spam Collection
            (5,574 samples). While this message contains native {script.indic_script_name || "Indic"} script, SCAMLENS AI
            evaluates it using structural markers, phone numbers, URL presence, and financial keywords without claiming
            native Indic NLP model training.
          </p>
        </div>
      )}
    </motion.div>
  );
}
