import { useEffect, useState, useCallback } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  AlertTriangle,
  ArrowRight,
  BatteryFull,
  BrainCircuit,
  CheckCircle2,
  Cpu,
  LockKeyhole,
  MessageSquareWarning,
  Play,
  Radar,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Signal,
  Sparkles,
  Wifi,
} from "lucide-react";
import { Link } from "@tanstack/react-router";
import { Button } from "@/components/ui/button";
import { useScamlensPreferences } from "@/lib/scamlens-preferences";
import { cn } from "@/lib/utils";

/**
 * Phases of the cinematic demonstration:
 * 0: Phone enters & normal conversation visible
 * 1: Notification banner slides down ("New SMS • Unknown Sender")
 * 2: Suspicious message bubble appears with typing/reveal effect
 * 3: Cyan laser scanning beam sweeps across phone screen; brackets highlight key phrases
 * 4: Particle data stream travels to AI Engine; 4 ML stages progress with futuristic radar
 * 5: Threat Detected alert reveals, risk gauge animates, safety recommendation appears
 */
type DemoPhase = 0 | 1 | 2 | 3 | 4 | 5;

const AI_STAGES = [
  { id: "extract", label: "Extracting text features...", detail: "TF-IDF word & char n-grams (10,043 dims)" },
  { id: "language", label: "Examining suspicious language...", detail: "Urgency, reward & call-to-action triggers" },
  { id: "url", label: "Analysing URL patterns...", detail: "Static lexical check: suspicious-example.com" },
  { id: "classify", label: "Running machine-learning classification...", detail: "Class-balanced Random Forest ensemble" },
] as const;

const THREAT_INDICATORS = [
  "Urgent reward claim (₹50,000 prize lure)",
  "Suspicious URL (unverified external domain)",
  "Request designed to encourage immediate action",
] as const;

export function HeroThreatScene({
  compact = false,
  embedded = false,
}: {
  compact?: boolean;
  embedded?: boolean;
}) {
  const { shouldReduceMotion: prefersReducedMotion } = useScamlensPreferences();
  const [phase, setPhase] = useState<DemoPhase>(prefersReducedMotion ? 5 : 0);
  const [activeStageIndex, setActiveStageIndex] = useState<number>(prefersReducedMotion ? 3 : -1);
  const [runId, setRunId] = useState<number>(0);
  const [autoLoop, setAutoLoop] = useState<boolean>(true);

  const replayScan = useCallback(() => {
    setRunId((prev) => prev + 1);
    if (prefersReducedMotion) {
      setPhase(5);
      setActiveStageIndex(3);
    } else {
      setPhase(0);
      setActiveStageIndex(-1);
    }
  }, [prefersReducedMotion]);

  useEffect(() => {
    if (prefersReducedMotion) {
      setPhase(5);
      setActiveStageIndex(3);
      return;
    }

    const timers: ReturnType<typeof setTimeout>[] = [];

    // Phase 0 -> 1: Notification arrives
    timers.push(setTimeout(() => setPhase(1), 700));

    // Phase 1 -> 2: Suspicious message bubble appears in chat
    timers.push(setTimeout(() => setPhase(2), 1900));

    // Phase 2 -> 3: Glowing cyan scanning beam sweeps phone & brackets lock onto phrases
    timers.push(setTimeout(() => setPhase(3), 3200));

    // Phase 3 -> 4: Particle trail activates & AI analysis stages progress
    timers.push(
      setTimeout(() => {
        setPhase(4);
        setActiveStageIndex(0);
      }, 4800)
    );
    timers.push(setTimeout(() => setActiveStageIndex(1), 5650));
    timers.push(setTimeout(() => setActiveStageIndex(2), 6500));
    timers.push(setTimeout(() => setActiveStageIndex(3), 7350));

    // Phase 4 -> 5: Threat Detected alert & illustrative risk gauge
    timers.push(setTimeout(() => setPhase(5), 8300));

    // Auto-loop after pause
    if (autoLoop) {
      timers.push(
        setTimeout(() => {
          setRunId((prev) => prev + 1);
          setPhase(0);
          setActiveStageIndex(-1);
        }, 15500)
      );
    }

    return () => {
      timers.forEach(clearTimeout);
    };
  }, [runId, prefersReducedMotion, autoLoop]);

  const isScanningPhone = phase === 3 || phase === 4;
  const isAnalyzing = phase >= 4;
  const isThreatDetected = phase === 5;
  const highlightMarkers = phase >= 3;

  // Illustrative demo risk percentage (explicitly labeled as visual demonstration)
  const demoRiskValue = isThreatDetected ? 94 : isAnalyzing ? 62 : 0;
  const gaugeCircumference = 2 * Math.PI * 34;
  const gaugeStrokeOffset = gaugeCircumference - (demoRiskValue / 100) * gaugeCircumference;

  return (
    <section
      aria-label="Interactive AI scam detection visual demonstration"
      className={cn(
        "relative overflow-hidden",
        embedded
          ? "flex h-full w-full flex-col justify-between"
          : cn(
              "rounded-2xl border border-cyan-500/25 bg-[#060B16] shadow-[0_25px_70px_-15px_rgba(0,0,0,0.85)]",
              compact ? "p-3.5 sm:p-4 lg:p-5" : "p-5 sm:p-7 lg:p-8"
            )
      )}
    >
      {/* Subtle cybersecurity grid & atmospheric lighting (only when standalone) */}
      {!embedded && (
        <>
          <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(to_right,rgba(56,189,248,0.05)_1px,transparent_1px),linear-gradient(to_bottom,rgba(56,189,248,0.05)_1px,transparent_1px)] bg-[size:28px_28px]" />
          <div className="pointer-events-none absolute -left-24 -top-24 size-80 rounded-full bg-cyan-500/10 blur-3xl" />
          <div
            className={cn(
              "pointer-events-none absolute -bottom-24 -right-24 size-80 rounded-full blur-3xl transition-colors duration-1000",
              isThreatDetected ? "bg-red-500/15" : "bg-teal-500/10"
            )}
          />
        </>
      )}

      {/* Top header bar + Visual Demonstration badge + Replay Controls */}
      <div
        className={cn(
          "relative z-10 flex flex-wrap items-center justify-between gap-3 border-b border-slate-800/80",
          compact ? "pb-2.5" : "pb-5"
        )}
      >
        <div className="space-y-0.5">
          <div className="inline-flex items-center gap-1.5 rounded-full border border-cyan-400/30 bg-cyan-500/10 px-2.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-cyan-300">
            <Sparkles className="size-3 text-cyan-400" />
            Interactive Visual Demonstration • Simulated Scenario
          </div>
          <h2 className={cn("font-bold tracking-tight text-slate-100", compact ? "text-base sm:text-lg" : "text-lg sm:text-xl")}>
            See How SCAMLENS AI Intercepts Mobile Phishing in Real Time
          </h2>
          {!compact && (
            <p className="max-w-2xl text-xs text-slate-400 sm:text-sm">
              Watch a simulated suspicious SMS arrive, undergo static NLP &amp; URL inspection, and trigger an explainable threat alert before the user clicks.
            </p>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={replayScan}
            className="h-7 border-cyan-500/35 bg-slate-900/90 px-2.5 text-xs text-cyan-200 hover:bg-cyan-950/60 hover:text-cyan-100"
          >
            <RotateCcw className="size-3" />
            Replay Scan
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={() => setAutoLoop((v) => !v)}
            className="h-7 px-2 text-xs text-slate-400 hover:text-slate-200"
          >
            <Play className={cn("size-3", autoLoop ? "text-cyan-400" : "text-slate-500")} />
            {autoLoop ? "Auto-Loop: On" : "Paused"}
          </Button>
          {!compact && (
            <Button asChild size="sm" className="bg-cyan-500 text-slate-950 hover:bg-cyan-400">
              <Link to="/message-analyzer">
                Open Live Scanner
                <ArrowRight className="size-3.5" />
              </Link>
            </Button>
          )}
        </div>
      </div>

      {/* Process pipeline stage bar: PHONE MESSAGE -> AI ANALYSIS -> THREAT DETECTED */}
      <div
        className={cn(
          "relative z-10 grid grid-cols-3 items-center gap-2 rounded-xl border border-slate-800/80 bg-slate-950/65 px-3 backdrop-blur-sm",
          compact ? "my-2.5 py-2" : "my-5 py-3 sm:px-5"
        )}
      >
        {/* Step 1: PHONE MESSAGE */}
        <div className="flex items-center gap-2">
          <div
            className={cn(
              "grid shrink-0 place-items-center rounded-lg border text-xs font-bold transition-all duration-500",
              compact ? "size-7" : "size-8",
              phase >= 1
                ? "border-cyan-400/60 bg-cyan-500/20 text-cyan-300 shadow-[0_0_15px_rgba(34,211,238,0.25)]"
                : "border-slate-800 bg-slate-900 text-slate-500"
            )}
          >
            <MessageSquareWarning className="size-3.5" />
          </div>
          <div className="min-w-0">
            <p className="truncate text-[9px] font-semibold uppercase tracking-wider text-slate-400">Stage 01</p>
            <p className={cn("truncate text-[11px] font-semibold", phase >= 1 ? "text-slate-100" : "text-slate-500")}>
              PHONE MESSAGE
            </p>
          </div>
        </div>

        {/* Step 2: AI ANALYSIS */}
        <div className="relative flex items-center gap-2 pl-2 sm:pl-3">
          <div className="hidden sm:block absolute -left-5 top-1/2 h-0.5 w-5 -translate-y-1/2 overflow-hidden rounded-full bg-slate-800">
            <motion.div
              className="h-full bg-gradient-to-r from-cyan-400 to-teal-300"
              initial={{ width: "0%" }}
              animate={{ width: phase >= 3 ? "100%" : "0%" }}
              transition={{ duration: 0.6 }}
            />
          </div>
          <div
            className={cn(
              "grid shrink-0 place-items-center rounded-lg border text-xs font-bold transition-all duration-500",
              compact ? "size-7" : "size-8",
              phase >= 3
                ? "border-teal-400/60 bg-teal-500/20 text-teal-300 shadow-[0_0_15px_rgba(45,212,191,0.25)]"
                : "border-slate-800 bg-slate-900 text-slate-500"
            )}
          >
            <BrainCircuit className="size-3.5" />
          </div>
          <div className="min-w-0">
            <p className="truncate text-[9px] font-semibold uppercase tracking-wider text-slate-400">Stage 02</p>
            <p className={cn("truncate text-[11px] font-semibold", phase >= 3 ? "text-teal-200" : "text-slate-500")}>
              AI ANALYSIS
            </p>
          </div>
        </div>

        {/* Step 3: THREAT DETECTED */}
        <div className="relative flex items-center gap-2 pl-2 sm:pl-3">
          <div className="hidden sm:block absolute -left-5 top-1/2 h-0.5 w-5 -translate-y-1/2 overflow-hidden rounded-full bg-slate-800">
            <motion.div
              className="h-full bg-gradient-to-r from-teal-400 to-red-500"
              initial={{ width: "0%" }}
              animate={{ width: isThreatDetected ? "100%" : "0%" }}
              transition={{ duration: 0.6 }}
            />
          </div>
          <div
            className={cn(
              "grid shrink-0 place-items-center rounded-lg border text-xs font-bold transition-all duration-500",
              compact ? "size-7" : "size-8",
              isThreatDetected
                ? "border-red-500/70 bg-red-500/20 text-red-400 shadow-[0_0_18px_rgba(239,68,68,0.35)]"
                : "border-slate-800 bg-slate-900 text-slate-500"
            )}
          >
            <ShieldAlert className="size-3.5" />
          </div>
          <div className="min-w-0">
            <p className="truncate text-[9px] font-semibold uppercase tracking-wider text-slate-400">Stage 03</p>
            <p className={cn("truncate text-[11px] font-semibold", isThreatDetected ? "text-red-300" : "text-slate-500")}>
              THREAT DETECTED
            </p>
          </div>
        </div>
      </div>

      {/* Main Interactive Scene: Left = Smartphone, Center = Particle Bridge, Right = AI Engine + Threat Alert */}
      <div
        className={cn(
          "relative z-10 grid items-center",
          compact
            ? "gap-3.5 md:grid-cols-[260px_1fr] xl:grid-cols-[268px_32px_1fr]"
            : "gap-6 lg:grid-cols-[330px_56px_1fr]"
        )}
      >
        {/* 1. ANIMATED SMARTPHONE */}
        <motion.div
          key={`phone-${runId}`}
          initial={prefersReducedMotion ? false : { opacity: 0, y: 10, scale: 0.98 }}
          animate={
            prefersReducedMotion
              ? { opacity: 1, y: 0, scale: 1 }
              : {
                  opacity: 1,
                  y: [0, -3, 0],
                  scale: 1,
                }
          }
          transition={{
            opacity: { duration: 0.45 },
            scale: { duration: 0.45 },
            y: { duration: 5.5, repeat: Infinity, ease: "easeInOut" },
          }}
          className={cn("mx-auto w-full", compact ? "max-w-[268px]" : "max-w-[320px]")}
        >
          {/* Outer Titanium/Glass Bezel */}
          <div
            className={cn(
              "relative rounded-[2.1rem] border-[3px] bg-gradient-to-b from-slate-800 via-slate-900 to-slate-950 p-2 shadow-[0_20px_50px_rgba(0,0,0,0.85),inset_0_1px_1px_rgba(255,255,255,0.2)] transition-colors duration-700",
              isThreatDetected
                ? "border-red-500/60 shadow-[0_20px_55px_rgba(239,68,68,0.22)]"
                : isScanningPhone
                  ? "border-cyan-400/65 shadow-[0_20px_55px_rgba(34,211,238,0.22)]"
                  : "border-slate-700/80"
            )}
          >
            {/* Side hardware buttons */}
            <div className="-left-[5px] top-20 absolute h-8 w-[3px] rounded-l bg-slate-700" />
            <div className="-left-[5px] top-32 absolute h-8 w-[3px] rounded-l bg-slate-700" />
            <div className="-right-[5px] top-24 absolute h-10 w-[3px] rounded-r bg-slate-700" />

            {/* Inner Dark Glass Screen */}
            <div
              className={cn(
                "relative flex flex-col overflow-hidden rounded-[1.7rem] border border-slate-800/90 bg-[#070D19]",
                compact ? "h-[378px]" : "h-[470px]"
              )}
            >
              {/* Subtle screen glass reflection */}
              <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(135deg,rgba(255,255,255,0.05)_0%,transparent_42%,transparent_100%)]" />

              {/* Dynamic Island & Status Bar */}
              <div className="relative z-20 flex items-center justify-between px-4 pt-2.5 pb-1.5 text-[10px] font-semibold text-slate-300">
                <span>9:41</span>
                <div className="h-3.5 w-16 rounded-full bg-black/90 ring-1 ring-slate-800/80 flex items-center justify-end pr-2">
                  <span
                    className={cn(
                      "size-1.5 rounded-full transition-colors",
                      isScanningPhone ? "bg-cyan-400 animate-ping" : isThreatDetected ? "bg-red-500" : "bg-emerald-500/70"
                    )}
                  />
                </div>
                <div className="flex items-center gap-1 text-slate-300">
                  <Signal className="size-2.5" />
                  <Wifi className="size-2.5" />
                  <BatteryFull className="size-3" />
                </div>
              </div>

              {/* App Header */}
              <div className="relative z-10 flex items-center justify-between border-b border-slate-800/80 bg-slate-900/60 px-3.5 py-2 backdrop-blur-sm">
                <div className="flex items-center gap-2">
                  <div className="grid size-6 place-items-center rounded-full bg-slate-800 text-[10px] font-bold text-cyan-300">
                    SMS
                  </div>
                  <div>
                    <p className="text-[11px] font-semibold text-slate-100">Messages</p>
                    <p className="text-[9px] text-slate-400">SCAMLENS Shield Active</p>
                  </div>
                </div>
                <span className="inline-flex items-center gap-1 rounded-full border border-cyan-500/30 bg-cyan-500/10 px-1.5 py-0.5 text-[9px] font-medium text-cyan-300">
                  <ShieldCheck className="size-2.5" /> Protected
                </span>
              </div>

              {/* Incoming Notification Toast */}
              <AnimatePresence>
                {phase >= 1 && (
                  <motion.div
                    initial={prefersReducedMotion ? false : { opacity: 0, y: -20, scale: 0.95 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    exit={{ opacity: 0, y: -12 }}
                    transition={{ duration: 0.35 }}
                    className="relative z-20 mx-2.5 mt-2 rounded-lg border border-amber-500/40 bg-slate-900/95 p-2 shadow-lg backdrop-blur-md"
                  >
                    <div className="flex items-center justify-between text-[9px]">
                      <span className="font-semibold text-amber-300 flex items-center gap-1">
                        <MessageSquareWarning className="size-2.5" /> New SMS • +91-98XXX-XX412
                      </span>
                      <span className="text-slate-400">now</span>
                    </div>
                    <p className="mt-0.5 truncate text-[10px] text-slate-300">
                      Congratulations! You&apos;ve won a ₹50,000 reward...
                    </p>
                  </motion.div>
                )}
              </AnimatePresence>

              {/* Conversation Area */}
              <div className="relative z-10 flex-1 space-y-2 overflow-hidden px-3 py-2">
                {/* Earlier safe message for realism */}
                <div className="max-w-[85%] rounded-xl rounded-tl-sm border border-slate-800 bg-slate-900/75 px-2.5 py-1.5 text-[10px] text-slate-300">
                  <p>Hi! Team meeting is confirmed for 3:00 PM in Room B.</p>
                  <span className="mt-0.5 block text-[8px] text-emerald-400/90">✓ Verified Legitimate • 9:38 AM</span>
                </div>

                {/* Suspicious incoming message */}
                <AnimatePresence>
                  {phase >= 2 && (
                    <motion.div
                      initial={prefersReducedMotion ? false : { opacity: 0, y: 14, scale: 0.96 }}
                      animate={{ opacity: 1, y: 0, scale: 1 }}
                      transition={{ duration: 0.4 }}
                      className={cn(
                        "relative rounded-xl rounded-tl-sm border p-2.5 text-xs leading-relaxed transition-all duration-500",
                        isThreatDetected
                          ? "border-red-500/75 bg-red-950/35 text-slate-100 shadow-[0_0_25px_rgba(239,68,68,0.2)]"
                          : highlightMarkers
                            ? "border-cyan-400/65 bg-cyan-950/25 text-slate-100 shadow-[0_0_20px_rgba(34,211,238,0.15)]"
                            : "border-slate-700 bg-slate-900/90 text-slate-200"
                      )}
                    >
                      <div className="mb-1 flex items-center justify-between text-[9px]">
                        <span className="font-mono font-semibold text-amber-300">Unknown Sender</span>
                        <span
                          className={cn(
                            "rounded px-1.5 py-0.5 font-mono text-[8px] font-bold uppercase",
                            isThreatDetected
                              ? "bg-red-500/20 text-red-300 border border-red-500/40"
                              : highlightMarkers
                                ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40"
                                : "bg-slate-800 text-slate-400"
                          )}
                        >
                          {isThreatDetected ? "Phishing Flagged" : highlightMarkers ? "AI Inspecting" : "Unverified"}
                        </span>
                      </div>

                      {/* Fictional message with animated brackets/markers on key phrases */}
                      <p className="text-[11px] leading-4 text-slate-100">
                        &ldquo;Congratulations! You&apos;ve{" "}
                        <span
                          className={cn(
                            "inline-block rounded px-1 transition-all duration-300",
                            isThreatDetected
                              ? "bg-red-500/25 text-red-200 ring-1 ring-red-400/70 font-medium"
                              : highlightMarkers
                                ? "bg-cyan-500/20 text-cyan-200 ring-1 ring-cyan-400/70 font-medium"
                                : ""
                          )}
                        >
                          {highlightMarkers && <span className="mr-0.5 font-mono text-[9px] opacity-80">[</span>}
                          won a ₹50,000 reward!
                          {highlightMarkers && <span className="ml-0.5 font-mono text-[9px] opacity-80">]</span>}
                        </span>{" "}
                        <span
                          className={cn(
                            "inline-block rounded px-1 transition-all duration-300",
                            isThreatDetected
                              ? "bg-amber-500/25 text-amber-200 ring-1 ring-amber-400/70 font-medium"
                              : highlightMarkers
                                ? "bg-cyan-500/20 text-cyan-200 ring-1 ring-cyan-400/70 font-medium"
                                : ""
                          )}
                        >
                          {highlightMarkers && <span className="mr-0.5 font-mono text-[9px] opacity-80">[</span>}
                          Claim your prize now:
                          {highlightMarkers && <span className="ml-0.5 font-mono text-[9px] opacity-80">]</span>}
                        </span>{" "}
                        <span
                          className={cn(
                            "mt-0.5 inline-block break-all rounded px-1 py-0.5 font-mono text-[10px] underline transition-all duration-300",
                            isThreatDetected
                              ? "bg-red-500/30 text-red-200 ring-1 ring-red-400"
                              : highlightMarkers
                                ? "bg-cyan-500/25 text-cyan-200 ring-1 ring-cyan-400"
                                : "text-sky-400"
                          )}
                        >
                          {highlightMarkers && <span className="mr-0.5 text-[9px] no-underline">[</span>}
                          suspicious-example.com
                          {highlightMarkers && <span className="ml-0.5 text-[9px] no-underline">]</span>}
                        </span>
                        &rdquo;
                      </p>

                      {/* Detection marker tags underneath bubble */}
                      <AnimatePresence>
                        {highlightMarkers && (
                          <motion.div
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: "auto" }}
                            className="mt-1.5 flex flex-wrap gap-1 border-t border-slate-800/90 pt-1.5"
                          >
                            <span className="rounded bg-amber-500/15 px-1 py-0.5 font-mono text-[8px] text-amber-300 border border-amber-500/30">
                              REWARD_LURE
                            </span>
                            <span className="rounded bg-cyan-500/15 px-1 py-0.5 font-mono text-[8px] text-cyan-300 border border-cyan-500/30">
                              URGENCY_CTA
                            </span>
                            <span className="rounded bg-red-500/15 px-1 py-0.5 font-mono text-[8px] text-red-300 border border-red-500/30">
                              SUSPICIOUS_URL
                            </span>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </motion.div>
                  )}
                </AnimatePresence>

                {/* In-phone Threat Shield Overlay at Phase 5 */}
                <AnimatePresence>
                  {isThreatDetected && (
                    <motion.div
                      initial={prefersReducedMotion ? false : { opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="rounded-lg border border-red-500/50 bg-gradient-to-r from-red-950/90 via-red-900/40 to-slate-900/90 p-2 shadow-lg"
                    >
                      <div className="flex items-center gap-2">
                        <ShieldAlert className="size-3.5 shrink-0 text-red-400" />
                        <div className="min-w-0">
                          <p className="text-[10px] font-bold text-red-200">Link Blocked by SCAMLENS Guard</p>
                          <p className="text-[9px] text-red-300/90">Do not tap suspicious-example.com</p>
                        </div>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>

              {/* Glowing Cyan Laser Scanning Beam across phone screen */}
              <AnimatePresence>
                {isScanningPhone && !prefersReducedMotion && (
                  <motion.div
                    initial={{ top: "10%", opacity: 0 }}
                    animate={{ top: ["12%", "88%", "12%"], opacity: [0.9, 1, 0.9] }}
                    exit={{ opacity: 0 }}
                    transition={{ duration: 2.2, repeat: Infinity, ease: "linear" }}
                    className="pointer-events-none absolute inset-x-0 z-30 h-10"
                  >
                    <div className="h-[2px] w-full bg-gradient-to-r from-transparent via-cyan-300 to-transparent shadow-[0_0_16px_3px_rgba(34,211,238,0.85)]" />
                    <div className="h-8 w-full bg-gradient-to-b from-cyan-400/25 to-transparent" />
                  </motion.div>
                )}
              </AnimatePresence>

              {/* Phone Footer Bar */}
              <div className="relative z-20 border-t border-slate-800/80 bg-slate-950/90 px-3 py-1.5 text-center">
                <p className="text-[9px] text-slate-400">Fictional message for visual demonstration</p>
                <div className="mx-auto mt-1 h-1 w-20 rounded-full bg-slate-700" />
              </div>
            </div>
          </div>
        </motion.div>

        {/* 2. PARTICLE DATA STREAM BRIDGE (Phone -> AI Panel) */}
        <div className="hidden items-center justify-center xl:flex xl:flex-col">
          <div className="relative flex h-40 w-9 items-center justify-center">
            <div className="h-full w-[2px] bg-slate-800" />
            {phase >= 3 && !prefersReducedMotion && (
              <motion.div
                className={cn(
                  "absolute h-6 w-2 rounded-full shadow-[0_0_12px_rgba(34,211,238,0.9)]",
                  isThreatDetected ? "bg-red-400" : "bg-cyan-400"
                )}
                animate={{
                  y: [-50, 50],
                  opacity: [0.2, 1, 0.2],
                }}
                transition={{ duration: 1.1, repeat: Infinity, ease: "linear" }}
              />
            )}
            <div
              className={cn(
                "relative z-10 grid size-8 place-items-center rounded-full border transition-colors duration-500",
                isThreatDetected
                  ? "border-red-500/60 bg-red-950 text-red-300 shadow-[0_0_15px_rgba(239,68,68,0.4)]"
                  : phase >= 3
                    ? "border-cyan-400/60 bg-cyan-950 text-cyan-300 shadow-[0_0_15px_rgba(34,211,238,0.4)]"
                    : "border-slate-800 bg-slate-900 text-slate-500"
              )}
            >
              <Cpu className="size-3.5" />
            </div>
          </div>
        </div>

        {/* 3. AI SCANNING ENGINE & THREAT DETECTED ALERT PANEL */}
        <div className={cn("min-w-0", compact ? "space-y-3" : "space-y-4")}>
          {/* Top Card: AI Analysis Stages + Futuristic Radar */}
          <div className={cn("rounded-xl border border-slate-800/90 bg-slate-900/75 backdrop-blur-md", compact ? "p-3.5" : "p-4 sm:p-5")}>
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2.5">
              <div className="flex items-center gap-2">
                <div
                  className={cn(
                    "grid size-8 shrink-0 place-items-center rounded-lg border",
                    isAnalyzing
                      ? "border-cyan-400/40 bg-cyan-500/15 text-cyan-300"
                      : "border-slate-800 bg-slate-950 text-slate-400"
                  )}
                >
                  <Radar className={cn("size-4", phase === 4 && !prefersReducedMotion && "animate-spin")} />
                </div>
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <h3 className="text-xs font-semibold text-slate-100 sm:text-sm">SCAMLENS AI Inspection Telemetry</h3>
                    <span className="rounded border border-slate-700 bg-slate-800/90 px-1.5 py-0.5 font-mono text-[9px] text-slate-300">
                      DEMO SIMULATION
                    </span>
                  </div>
                  <p className="truncate text-[11px] text-slate-400">
                    4-stage static feature extraction &amp; Random Forest pipeline
                  </p>
                </div>
              </div>

              {/* Status pill */}
              <span
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] font-medium",
                  isThreatDetected
                    ? "border-red-500/40 bg-red-500/15 text-red-300"
                    : phase >= 3
                      ? "border-cyan-400/40 bg-cyan-500/15 text-cyan-300"
                      : "border-slate-700 bg-slate-800 text-slate-400"
                )}
              >
                <span
                  className={cn(
                    "size-1.5 rounded-full",
                    isThreatDetected
                      ? "bg-red-400"
                      : phase >= 3
                        ? "bg-cyan-400 animate-ping"
                        : "bg-slate-500"
                  )}
                />
                {isThreatDetected
                  ? "Threat Identified"
                  : phase >= 3
                    ? "Scanning..."
                    : "Standby"}
              </span>
            </div>

            {/* 4 Analysis Stages */}
            <div className={cn("mt-3 grid gap-2 sm:grid-cols-2")}>
              {AI_STAGES.map((stage, idx) => {
                const isDone = activeStageIndex > idx || isThreatDetected;
                const isCurrent = phase === 4 && activeStageIndex === idx;
                return (
                  <div
                    key={stage.id}
                    className={cn(
                      "rounded-lg border p-2.5 transition-all duration-300",
                      isDone
                        ? "border-teal-500/35 bg-teal-950/20"
                        : isCurrent
                          ? "border-cyan-400/60 bg-cyan-950/30 shadow-[0_0_15px_rgba(34,211,238,0.12)]"
                          : "border-slate-800/80 bg-slate-950/50 opacity-65"
                    )}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-[9px] font-semibold uppercase tracking-wider text-cyan-400">
                        Step 0{idx + 1}
                      </span>
                      {isDone ? (
                        <CheckCircle2 className="size-3.5 text-teal-400" />
                      ) : isCurrent ? (
                        <span className="size-2 rounded-full bg-cyan-400 animate-ping" />
                      ) : (
                        <span className="size-2 rounded-full bg-slate-700" />
                      )}
                    </div>
                    <p className="mt-0.5 text-[11px] font-medium text-slate-100">{stage.label}</p>
                    <p className="mt-0.5 truncate text-[10px] text-slate-400">{stage.detail}</p>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Bottom Card: THREAT DETECTED Alert + Illustrative Risk Gauge + Indicators */}
          <div
            className={cn(
              "rounded-xl border transition-all duration-500",
              compact ? "p-3.5" : "p-4 sm:p-5",
              isThreatDetected
                ? "border-red-500/60 bg-gradient-to-br from-red-950/45 via-slate-900/90 to-slate-950/95 shadow-[0_0_35px_rgba(239,68,68,0.16)]"
                : "border-slate-800/80 bg-slate-900/50"
            )}
          >
            {isThreatDetected ? (
              <motion.div
                initial={prefersReducedMotion ? false : { opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.4 }}
                className="grid gap-3.5 md:grid-cols-[118px_1fr] md:items-center"
              >
                {/* Animated Risk Gauge Ring (Clearly Labeled Illustrative Demo Value) */}
                <div className="flex flex-col items-center justify-center rounded-xl border border-red-500/30 bg-slate-950/80 p-2.5 text-center">
                  <div className="relative grid size-20 place-items-center">
                    <svg className="size-20 -rotate-90 transform" viewBox="0 0 84 84">
                      <circle
                        cx="42"
                        cy="42"
                        r="34"
                        stroke="currentColor"
                        strokeWidth="6"
                        fill="transparent"
                        className="text-slate-800"
                      />
                      <motion.circle
                        cx="42"
                        cy="42"
                        r="34"
                        stroke="currentColor"
                        strokeWidth="6"
                        strokeLinecap="round"
                        fill="transparent"
                        className="text-red-500"
                        initial={{ strokeDashoffset: gaugeCircumference }}
                        animate={{ strokeDashoffset: gaugeStrokeOffset }}
                        transition={{ duration: 0.9, ease: "easeOut" }}
                        style={{ strokeDasharray: gaugeCircumference }}
                      />
                    </svg>
                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                      <span className="font-mono text-lg font-bold text-red-400">{demoRiskValue}%</span>
                      <span className="text-[8px] font-semibold uppercase tracking-wider text-red-300">
                        Very High
                      </span>
                    </div>
                  </div>
                  <span className="mt-1 rounded bg-slate-900 px-1.5 py-0.5 text-[8px] font-medium text-slate-400">
                    Illustrative Demo Score
                  </span>
                </div>

                {/* Alert Banner, Example Indicators & Safety Recommendation */}
                <div className="min-w-0 space-y-2.5">
                  <div className="flex flex-wrap items-center justify-between gap-1.5">
                    <div className="flex items-center gap-1.5">
                      <span className="relative flex size-5 items-center justify-center rounded-full bg-red-500/20 text-red-400">
                        <AlertTriangle className="size-3.5" />
                      </span>
                      <h4 className="text-xs font-bold tracking-wide text-red-300 sm:text-sm">
                        SCAM / PHISHING RISK DETECTED
                      </h4>
                    </div>
                    <span className="rounded border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 text-[9px] font-medium text-amber-300">
                      Visual Demo Only
                    </span>
                  </div>

                  {/* Example Indicators */}
                  <div className="grid gap-1.5 sm:grid-cols-3">
                    {THREAT_INDICATORS.map((indicator) => (
                      <div
                        key={indicator}
                        className="flex items-start gap-1.5 rounded-md border border-red-500/25 bg-slate-950/70 p-1.5 text-[10px] leading-snug text-slate-200"
                      >
                        <ShieldAlert className="mt-0.5 size-3 shrink-0 text-red-400" />
                        <span>{indicator}</span>
                      </div>
                    ))}
                  </div>

                  {/* Safety Recommendation */}
                  <div className="flex flex-wrap items-center justify-between gap-1.5 rounded-lg border border-amber-500/30 bg-amber-500/10 px-2.5 py-1.5 text-[11px] text-amber-200">
                    <span className="flex items-center gap-1.5 font-medium">
                      <LockKeyhole className="size-3.5 shrink-0 text-amber-300" />
                      Do not click suspicious links or share personal information.
                    </span>
                  </div>
                </div>
              </motion.div>
            ) : (
              <div className="flex min-h-[126px] flex-col items-center justify-center text-center">
                <div className="flex items-center gap-2 text-xs font-medium text-cyan-300">
                  <Radar className="size-4 animate-spin text-cyan-400" />
                  <span>
                    {phase < 2
                      ? "Waiting for incoming message on smartphone..."
                      : phase === 2
                        ? "Suspicious SMS detected — initializing optical & lexical scan..."
                        : "Evaluating message tokens, urgency cues, and URL risk signals..."}
                  </span>
                </div>
                <p className="mt-1 text-[11px] text-slate-400">
                  The threat verdict and safety guidance will appear automatically when the scan completes.
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
