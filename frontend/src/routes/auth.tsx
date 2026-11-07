import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useState, type FormEvent } from "react";
import { AnimatePresence, motion } from "motion/react";
import {
  AlertTriangle,
  ArrowRight,
  BatteryFull,
  BrainCircuit,
  CheckCircle2,
  Eye,
  EyeOff,
  KeyRound,
  Loader2,
  LockKeyhole,
  Mail,
  Shield,
  ShieldCheck,
  Signal,
  Sparkles,
  UserPlus,
  Wifi,
} from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ThemeSwitcher } from "@/components/scamlens/primitives";
import { ScamLensIcon } from "@/components/scamlens/logo";
import { CyberRobot, robotGuardian, useRobotGuardian, type RobotMood } from "@/components/scamlens/cyber-robot";
import { formatAuthError } from "@/lib/auth-error-helper";
import { useScamlensPreferences } from "@/lib/scamlens-preferences";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/auth")({
  head: () => ({
    meta: [
      { title: "Welcome to SCAMLENS AI — Sign In" },
      {
        name: "description",
        content:
          "Your Digital Safety Starts Here. Sign in to access intelligent scam and phishing detection with SCAMLENS AI.",
      },
      { property: "og:title", content: "Welcome to SCAMLENS AI — Sign In" },
      {
        property: "og:description",
        content:
          "See the risk before you click. Sign in to access intelligent scam and phishing detection.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: AuthPage,
});

type Mode = "signin" | "signup" | "forgot";
const emailOk = (v: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v.trim());

const AMBIENT_NODES = [
  { id: "n1", x: "14%", y: "22%", size: "size-2", delay: 0 },
  { id: "n2", x: "23%", y: "68%", size: "size-1.5", delay: 1.1 },
  { id: "n3", x: "84%", y: "26%", size: "size-2", delay: 0.6 },
  { id: "n4", x: "78%", y: "74%", size: "size-1.5", delay: 1.7 },
  { id: "n5", x: "18%", y: "46%", size: "size-1.5", delay: 2.2 },
  { id: "n6", x: "82%", y: "52%", size: "size-2", delay: 0.9 },
] as const;

const SECURITY_INFO_ITEMS = [
  {
    icon: BrainCircuit,
    title: "AI-Powered Detection",
    description: "identifies suspicious message and URL patterns.",
    accent:
      "text-sky-700 bg-sky-500/12 border-sky-500/30 dark:text-cyan-300 dark:bg-cyan-500/15 dark:border-cyan-400/30",
  },
  {
    icon: Shield,
    title: "Privacy-Focused",
    description: "analyzes submitted content through the configured SCAMLENS system.",
    accent:
      "text-blue-700 bg-blue-500/12 border-blue-500/30 dark:text-sky-300 dark:bg-sky-500/15 dark:border-sky-400/30",
  },
  {
    icon: LockKeyhole,
    title: "Secure Access",
    description: "protected access to your workspace.",
    accent:
      "text-teal-700 bg-teal-500/12 border-teal-500/30 dark:text-teal-300 dark:bg-teal-500/15 dark:border-teal-400/30",
  },
] as const;

function AuthPage() {
  const navigate = useNavigate();
  const { shouldReduceMotion, updatePreferences } = useScamlensPreferences();
  const [mode, setMode] = useState<Mode>("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [focusedField, setFocusedField] = useState<"email" | "password" | null>(null);
  const [cursorPos, setCursorPos] = useState<{ x: number; y: number } | null>(null);
  const [isInsideSignInArea, setIsInsideSignInArea] = useState(false);

  useEffect(() => {
    supabase.auth.getUser().then(({ data }) => {
      if (data.user) navigate({ to: "/", replace: true });
    });
  }, [navigate]);

  const switchMode = (m: Mode) => {
    setMode(m);
    setError(null);
    setInfo(null);
  };

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setInfo(null);
    if (!emailOk(email)) return setError("Enter a valid email address.");
    if (mode !== "forgot" && password.length < (mode === "signup" ? 8 : 1)) {
      return setError(
        mode === "signup"
          ? "Password must be at least 8 characters."
          : "Enter your password."
      );
    }
    setBusy(true);
    try {
      if (mode === "signin") {
        const { error } = await supabase.auth.signInWithPassword({
          email: email.trim(),
          password,
        });
        if (error) throw error;
        robotGuardian.greet("Welcome back! Ready to inspect suspicious links and messages.");
        navigate({ to: "/", replace: true });
      } else if (mode === "signup") {
        const { data, error } = await supabase.auth.signUp({
          email: email.trim(),
          password,
          options: { emailRedirectTo: window.location.origin },
        });
        if (error) throw error;
        if (data.session) {
          robotGuardian.greet("Welcome to SCAMLENS AI! Your security guardian is active.");
          navigate({ to: "/", replace: true });
        } else {
          setInfo(
            "Account created! Please check your email to confirm your address before signing in."
          );
          setMode("signin");
          setPassword("");
        }
      } else {
        const { error } = await supabase.auth.resetPasswordForEmail(
          email.trim(),
          {
            redirectTo: `${window.location.origin}/reset-password`,
          }
        );
        if (error) throw error;
        setInfo(
          "If an account exists for that email, a password reset link has been sent."
        );
      }
    } catch (err) {
      setError(formatAuthError(err, mode));
    } finally {
      setBusy(false);
    }
  }

  const guardianState = useRobotGuardian();
  const authRobotMood: RobotMood = busy
    ? "scanning"
    : error
      ? "invalid"
      : info
        ? "greeting"
        : guardianState.mood;

  const descriptionText =
    mode === "signin"
      ? "Sign in to access intelligent scam and phishing detection."
      : mode === "signup"
        ? "Create your account to access intelligent scam and phishing detection."
        : "Enter your registered email to receive a password recovery link.";

  return (
    <div className="relative flex min-h-screen w-full flex-col items-center justify-center overflow-x-hidden bg-gradient-to-br from-slate-100 via-sky-50 to-indigo-100 px-3 py-4 text-foreground sm:px-6 dark:bg-none dark:bg-[#040812]">
      {/* =================================================================== */}
      {/* 1. CYBERSECURITY ATMOSPHERE (Grid, Red/Cyan Glows, Network Lines)   */}
      {/* =================================================================== */}
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        {/* Fine technical grid pattern */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,rgba(14,165,233,0.07)_1px,transparent_1px),linear-gradient(to_bottom,rgba(14,165,233,0.07)_1px,transparent_1px)] bg-[size:36px_36px] dark:bg-[linear-gradient(to_right,rgba(56,189,248,0.045)_1px,transparent_1px),linear-gradient(to_bottom,rgba(56,189,248,0.045)_1px,transparent_1px)]" />

        {/* Radial vignette to keep focus on the center smartphone */}
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,transparent_30%,rgba(148,163,184,0.18)_100%)] dark:bg-[radial-gradient(circle_at_center,transparent_20%,rgba(2,5,12,0.85)_100%)]" />

        {/* Subtle cyan and crimson/red ambient lighting behind the phone */}
        <div className="absolute left-1/2 top-1/2 h-[540px] w-[540px] -translate-x-1/2 -translate-y-1/2 rounded-full bg-cyan-500/12 blur-[130px]" />
        <div className="absolute left-[28%] top-[24%] h-[320px] w-[320px] -translate-x-1/2 -translate-y-1/2 rounded-full bg-red-500/8 blur-[120px]" />
        <div className="absolute left-[72%] top-[74%] h-[340px] w-[340px] -translate-x-1/2 -translate-y-1/2 rounded-full bg-sky-500/10 blur-[125px]" />

        {/* Decorative SVG network lines on desktop */}
        <svg
          className="hidden h-full w-full opacity-35 lg:block"
          viewBox="0 0 1440 900"
          fill="none"
          preserveAspectRatio="xMidYMid slice"
          aria-hidden="true"
        >
          <defs>
            <linearGradient id="cyberLineLeft" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="rgba(34,211,238,0)" />
              <stop offset="55%" stopColor="rgba(34,211,238,0.38)" />
              <stop offset="100%" stopColor="rgba(34,211,238,0)" />
            </linearGradient>
            <linearGradient id="cyberLineRight" x1="100%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stopColor="rgba(239,68,68,0)" />
              <stop offset="50%" stopColor="rgba(56,189,248,0.35)" />
              <stop offset="100%" stopColor="rgba(34,211,238,0)" />
            </linearGradient>
          </defs>
          {/* Left network geometry */}
          <path
            d="M90 190 L280 270 L360 440 L230 630 L80 710"
            stroke="url(#cyberLineLeft)"
            strokeWidth="1.2"
            strokeDasharray="4 6"
          />
          <path
            d="M190 120 L340 260 L480 260"
            stroke="url(#cyberLineLeft)"
            strokeWidth="1"
          />
          <path
            d="M140 520 L320 520 L450 610"
            stroke="url(#cyberLineLeft)"
            strokeWidth="1"
          />
          {/* Right network geometry */}
          <path
            d="M1350 200 L1160 280 L1080 450 L1210 640 L1360 720"
            stroke="url(#cyberLineRight)"
            strokeWidth="1.2"
            strokeDasharray="4 6"
          />
          <path
            d="M1250 140 L1100 270 L960 270"
            stroke="url(#cyberLineRight)"
            strokeWidth="1"
          />
          <path
            d="M1300 530 L1120 530 L990 620"
            stroke="url(#cyberLineRight)"
            strokeWidth="1"
          />
        </svg>

        {/* Subtle glowing network particles */}
        {AMBIENT_NODES.map((node) => (
          <motion.span
            key={node.id}
            style={{ left: node.x, top: node.y }}
            animate={
              shouldReduceMotion
                ? { opacity: 0.45 }
                : { opacity: [0.25, 0.75, 0.25], scale: [1, 1.25, 1] }
            }
            transition={{
              duration: 4.2,
              repeat: Infinity,
              delay: node.delay,
              ease: "easeInOut",
            }}
            className={cn(
              "hidden rounded-full bg-cyan-400 shadow-[0_0_12px_rgba(34,211,238,0.85)] lg:block",
              node.size
            )}
          />
        ))}

        {/* Left Floating Decorative Shield Motif (Desktop) */}
        <motion.div
          animate={shouldReduceMotion ? { y: 0 } : { y: [-5, 5, -5] }}
          transition={{ duration: 6, repeat: Infinity, ease: "easeInOut" }}
          className="hidden items-center gap-2.5 rounded-xl border border-sky-300/60 bg-white/80 px-3.5 py-2.5 shadow-[0_8px_30px_rgba(14,165,233,0.14)] backdrop-blur-md lg:flex dark:border-cyan-500/20 dark:bg-slate-950/70 dark:shadow-[0_0_30px_rgba(34,211,238,0.1)]"
          style={{ position: "absolute", left: "9%", top: "32%" }}
        >
          <span className="grid size-8 place-items-center rounded-lg border border-sky-400/40 bg-sky-500/10 text-sky-700 dark:border-cyan-400/30 dark:bg-cyan-500/15 dark:text-cyan-300">
            <Shield className="size-4" />
          </span>
          <div>
            <p className="font-mono text-[10px] font-semibold uppercase tracking-wider text-sky-700 dark:text-cyan-300">
              AI Threat Shield
            </p>
            <p className="text-[11px] text-slate-600 dark:text-slate-400">Zero-Execution Guard</p>
          </div>
        </motion.div>

        {/* Right Floating Decorative Lock Motif (Desktop) */}
        <motion.div
          animate={shouldReduceMotion ? { y: 0 } : { y: [5, -5, 5] }}
          transition={{ duration: 6.5, repeat: Infinity, ease: "easeInOut" }}
          className="hidden items-center gap-2.5 rounded-xl border border-sky-300/60 bg-white/80 px-3.5 py-2.5 shadow-[0_8px_30px_rgba(14,165,233,0.14)] backdrop-blur-md lg:flex dark:border-cyan-500/20 dark:bg-slate-950/70 dark:shadow-[0_0_30px_rgba(34,211,238,0.1)]"
          style={{ position: "absolute", right: "9%", bottom: "28%" }}
        >
          <span className="grid size-8 place-items-center rounded-lg border border-teal-500/40 bg-teal-500/10 text-teal-700 dark:border-teal-400/30 dark:bg-teal-500/15 dark:text-teal-300">
            <LockKeyhole className="size-4" />
          </span>
          <div>
            <p className="font-mono text-[10px] font-semibold uppercase tracking-wider text-teal-700 dark:text-teal-300">
              Protected Access
            </p>
            <p className="text-[11px] text-slate-600 dark:text-slate-400">Workspace Security</p>
          </div>
        </motion.div>
      </div>

      {/* =================================================================== */}
      {/* 2. TOP AMBIENT STATUS PILL & MOTION PREFERENCE TOGGLE               */}
      {/* =================================================================== */}
      <div className="relative z-20 mb-2.5 flex w-full max-w-[424px] flex-wrap items-center justify-between gap-2 px-1">
        <div className="inline-flex items-center gap-2 rounded-full border border-sky-300/70 bg-white/85 px-3 py-1 text-[10px] font-semibold uppercase tracking-widest text-sky-700 shadow-[0_4px_18px_rgba(14,165,233,0.15)] backdrop-blur-md dark:border-cyan-500/30 dark:bg-slate-950/80 dark:text-cyan-300 dark:shadow-[0_0_20px_rgba(34,211,238,0.15)]">
          <span
            className={cn(
              "size-1.5 rounded-full bg-sky-500 dark:bg-cyan-400",
              !shouldReduceMotion && "animate-pulse"
            )}
          />
          SCAMLENS SECURITY ACTIVE
        </div>

        <div className="flex items-center gap-1.5">
          <ThemeSwitcher scopeId="auth-header" compactMobile />
          <button
            type="button"
            onClick={() =>
              updatePreferences({
                motionMode: shouldReduceMotion ? "full" : "reduced",
              })
            }
            className="inline-flex min-h-9 items-center gap-1.5 rounded-full border border-slate-300 bg-white/85 px-2.5 py-1 text-[10px] font-medium text-slate-700 transition-colors hover:border-sky-400 hover:text-slate-900 dark:border-slate-800 dark:bg-slate-950/80 dark:text-slate-300 dark:hover:border-cyan-500/40 dark:hover:text-slate-100"
            title="Toggle interface animation mode"
          >
            <Sparkles
              className={cn(
                "size-3",
                shouldReduceMotion ? "text-slate-500" : "text-sky-600 dark:text-cyan-400"
              )}
            />
            <span>Motion: {shouldReduceMotion ? "Reduced" : "Full"}</span>
          </button>
        </div>
      </div>

      {/* =================================================================== */}
      {/* 3. CENTERED REALISTIC SMARTPHONE CONTAINING THE LOGIN INTERFACE     */}
      {/* =================================================================== */}
      <motion.main
        initial={shouldReduceMotion ? false : { opacity: 0, y: 12, scale: 0.985 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: shouldReduceMotion ? 0 : 0.4, ease: "easeOut" }}
        onMouseMove={(e) => {
          setCursorPos({ x: e.clientX, y: e.clientY });
          setIsInsideSignInArea(true);
        }}
        onMouseLeave={() => {
          setCursorPos(null);
          setIsInsideSignInArea(false);
        }}
        className="relative z-10 w-full max-w-[424px]"
      >
        {/* Subtle Cyan Halo Glow Behind Smartphone Frame */}
        <div className="pointer-events-none absolute -inset-3 rounded-[3.2rem] bg-gradient-to-b from-sky-400/25 via-indigo-300/15 to-cyan-300/20 blur-xl dark:from-cyan-500/20 dark:via-sky-500/10 dark:to-red-500/10" />

        {/* Outer Titanium / Metallic Smartphone Bezel */}
        <div className="relative rounded-[2.85rem] border-[3px] border-sky-400/50 bg-gradient-to-b from-slate-700 via-slate-800 to-slate-900 p-2 shadow-[0_28px_70px_-14px_rgba(15,23,42,0.45),0_0_30px_rgba(14,165,233,0.18),inset_0_1px_1px_rgba(255,255,255,0.25)] sm:p-2.5 dark:border-cyan-400/40 dark:from-slate-800 dark:via-slate-900 dark:to-slate-950 dark:shadow-[0_28px_80px_-12px_rgba(0,0,0,0.92),0_0_40px_rgba(34,211,238,0.18),inset_0_1px_1px_rgba(255,255,255,0.22)]">
          {/* Physical Hardware Side Buttons */}
          <div
            aria-hidden="true"
            className="absolute -left-[5px] top-24 h-9 w-[3px] rounded-l bg-slate-700"
          />
          <div
            aria-hidden="true"
            className="absolute -left-[5px] top-36 h-12 w-[3px] rounded-l bg-slate-700"
          />
          <div
            aria-hidden="true"
            className="absolute -left-[5px] top-52 h-12 w-[3px] rounded-l bg-slate-700"
          />
          <div
            aria-hidden="true"
            className="absolute -right-[5px] top-32 h-16 w-[3px] rounded-r bg-slate-700"
          />

          {/* Inner Polished Smartphone Screen */}
          <div className="relative flex flex-col overflow-hidden rounded-[2.35rem] border border-slate-200 bg-gradient-to-b from-white via-sky-50/80 to-slate-100 dark:border-slate-800/90 dark:from-[#081226] dark:via-[#060C1A] dark:to-[#040812]">
            {/* Layered inner-screen lighting, fine micro-grid & glass reflection */}
            <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(to_right,rgba(14,165,233,0.05)_1px,transparent_1px),linear-gradient(to_bottom,rgba(14,165,233,0.05)_1px,transparent_1px)] bg-[size:22px_22px] dark:bg-[linear-gradient(to_right,rgba(56,189,248,0.03)_1px,transparent_1px),linear-gradient(to_bottom,rgba(56,189,248,0.03)_1px,transparent_1px)]" />
            <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(135deg,rgba(255,255,255,0.055)_0%,transparent_36%,rgba(14,165,233,0.03)_100%)]" />
            <div className="pointer-events-none absolute -top-16 left-1/2 h-44 w-72 -translate-x-1/2 rounded-full bg-sky-300/30 blur-2xl dark:bg-cyan-500/20" />
            <div className="pointer-events-none absolute -bottom-16 left-1/2 h-36 w-64 -translate-x-1/2 rounded-full bg-indigo-300/20 blur-2xl dark:bg-blue-600/15" />

            {/* Smartphone Status Bar & Dynamic Island */}
            <div className="relative z-20 flex items-center justify-between px-6 pt-3 pb-1.5 text-[11px] font-semibold tracking-tight text-slate-800 dark:text-slate-200">
              <span>9:41</span>
              <div
                aria-hidden="true"
                className="flex h-5 w-24 items-center justify-between rounded-full bg-black px-2.5 ring-1 ring-slate-800/90"
              >
                <span className="size-2 rounded-full bg-slate-900 ring-1 ring-slate-700" />
                <span className="size-1.5 rounded-full bg-cyan-400 shadow-[0_0_6px_rgba(34,211,238,0.9)]" />
              </div>
              <div className="flex items-center gap-1.5 text-slate-800 dark:text-slate-200">
                <Signal className="size-3" />
                <Wifi className="size-3" />
                <BatteryFull className="size-3.5" />
              </div>
            </div>

            {/* Inner Mobile App Surface */}
            <div className="relative z-10 flex flex-col px-4 pt-2 pb-4 sm:px-6 sm:pt-2.5 sm:pb-4">
              {/* ============================================================= */}
              {/* 1. ANIMATED WELCOME & BRANDING SECTION                        */}
              {/* ============================================================= */}
              <div className="flex flex-col items-center text-center">
                {/* Smooth Fade-in "AI-POWERED PROTECTION" Badge */}
                <motion.div
                  initial={shouldReduceMotion ? false : { opacity: 0, y: -6, scale: 0.96 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  transition={{ duration: shouldReduceMotion ? 0 : 0.32, ease: "easeOut" }}
                  className="inline-flex items-center gap-1.5 rounded-full border border-sky-400/45 bg-sky-500/10 px-2.5 py-0.5 text-[9px] font-bold uppercase tracking-[0.14em] text-sky-700 shadow-[0_0_16px_rgba(14,165,233,0.15)] dark:border-cyan-400/35 dark:bg-cyan-500/10 dark:text-cyan-300 dark:shadow-[0_0_16px_rgba(34,211,238,0.18)]"
                >
                  <motion.span
                    animate={
                      shouldReduceMotion
                        ? { rotate: 0, scale: 1 }
                        : { rotate: [0, 12, -12, 0], scale: [1, 1.12, 1] }
                    }
                    transition={{ duration: 4.5, repeat: Infinity, ease: "easeInOut" }}
                    className="inline-flex"
                  >
                    <Sparkles className="size-2.5 text-sky-600 dark:text-cyan-400" />
                  </motion.span>
                  AI-POWERED PROTECTION
                </motion.div>

                {/* AI Sentinel Robot Mascot (Entire head tracks cursor, eyes move independently, neck/body stable) */}
                <motion.div
                  initial={shouldReduceMotion ? false : { opacity: 0, scale: 0.88 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ duration: shouldReduceMotion ? 0 : 0.35, ease: "easeOut" }}
                  className="relative mt-2 flex justify-center"
                >
                  <CyberRobot
                    size={110}
                    mood={authRobotMood}
                    cursorPos={cursorPos}
                    isInsideSignInArea={isInsideSignInArea}
                    isPasswordFocused={focusedField === "password"}
                    showPassword={show}
                  />
                </motion.div>

                {/* Staggered Fade-and-Rise Welcome Heading & Tagline */}
                <motion.div
                  initial={shouldReduceMotion ? false : { opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{
                    duration: shouldReduceMotion ? 0 : 0.34,
                    delay: shouldReduceMotion ? 0 : 0.08,
                    ease: "easeOut",
                  }}
                  className="mt-2 flex flex-col items-center"
                >
                  <p className="font-mono text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">
                    Welcome to SCAMLENS AI
                  </p>
                  <h1 className="mt-0.5 bg-gradient-to-r from-slate-900 via-slate-800 to-sky-700 bg-clip-text text-lg font-extrabold tracking-tight text-transparent sm:text-xl dark:from-white dark:via-slate-100 dark:to-cyan-200">
                    Your Digital Safety Starts Here
                  </h1>
                  <p className="mt-0.5 text-xs font-semibold text-sky-700 dark:text-cyan-300">
                    See the risk before you click.
                  </p>
                  <AnimatePresence mode="wait" initial={false}>
                    <motion.p
                      key={mode}
                      initial={shouldReduceMotion ? false : { opacity: 0, y: 3 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={shouldReduceMotion ? { opacity: 1 } : { opacity: 0, y: -3 }}
                      transition={{ duration: shouldReduceMotion ? 0 : 0.18 }}
                      className="mt-1 max-w-[310px] text-[11px] leading-relaxed text-slate-600 dark:text-slate-400"
                    >
                      {descriptionText}
                    </motion.p>
                  </AnimatePresence>
                </motion.div>
              </div>

              {/* ============================================================= */}
              {/* 2. INTERACTIVE DARK-GLASS AUTHENTICATION FORM                 */}
              {/* ============================================================= */}
              <motion.div
                initial={shouldReduceMotion ? false : { opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{
                  duration: shouldReduceMotion ? 0 : 0.36,
                  delay: shouldReduceMotion ? 0 : 0.14,
                  ease: "easeOut",
                }}
                className="mt-3.5 rounded-2xl border border-slate-200 bg-white/85 p-3.5 shadow-[0_8px_24px_-12px_rgba(15,23,42,0.18)] backdrop-blur-md sm:p-4 dark:border-slate-800/90 dark:bg-slate-950/65 dark:shadow-[inset_0_1px_0_rgba(255,255,255,0.05)]"
              >
                {/* Animated Sliding Tab Indicator Bar */}
                <div className="mb-3 grid grid-cols-2 rounded-xl border border-slate-200 bg-slate-100/90 p-1 text-[11px] font-semibold dark:border-slate-800/90 dark:bg-[#050A14]/90">
                  {(
                    [
                      { id: "signin", label: "Sign In", active: mode === "signin" || mode === "forgot" },
                      { id: "signup", label: "Create Account", active: mode === "signup" },
                    ] as const
                  ).map((tab) => (
                    <button
                      key={tab.id}
                      type="button"
                      onClick={() => switchMode(tab.id)}
                      className={cn(
                        "relative min-h-9 rounded-lg py-1.5 transition-colors duration-200 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyan-400",
                        tab.active
                          ? "text-sky-800 dark:text-cyan-200"
                          : "text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200"
                      )}
                    >
                      {tab.active && (
                        <motion.span
                          layoutId="smartphone-auth-tab-pill"
                          transition={{
                            type: "spring",
                            stiffness: 380,
                            damping: 30,
                            duration: shouldReduceMotion ? 0 : 0.25,
                          }}
                          className="absolute inset-0 rounded-lg bg-white ring-1 ring-sky-400/50 shadow-sm dark:bg-transparent dark:bg-gradient-to-r dark:from-cyan-500/25 dark:to-blue-500/25 dark:ring-cyan-400/40 dark:shadow-[0_0_12px_rgba(34,211,238,0.18)]"
                        />
                      )}
                      <span className="relative z-10">{tab.label}</span>
                    </button>
                  ))}
                </div>

                <AnimatePresence mode="wait" initial={false}>
                  <motion.form
                    key={mode}
                    initial={shouldReduceMotion ? false : { opacity: 0, y: 6 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={shouldReduceMotion ? { opacity: 1 } : { opacity: 0, y: -6 }}
                    transition={{ duration: shouldReduceMotion ? 0 : 0.2, ease: "easeOut" }}
                    onSubmit={submit}
                    className="space-y-3"
                    noValidate
                  >
                    {/* Staggered Field 1: Email Dark-Glass Input */}
                    <motion.div
                      initial={shouldReduceMotion ? false : { opacity: 0, y: 6 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{
                        duration: shouldReduceMotion ? 0 : 0.24,
                        delay: shouldReduceMotion ? 0 : 0.03,
                      }}
                      className="space-y-1"
                    >
                      <Label
                        htmlFor="email"
                        className="text-[11px] font-semibold tracking-wide text-slate-700 dark:text-slate-200"
                      >
                        Email address
                      </Label>
                      <motion.div
                        animate={
                          focusedField === "email"
                            ? {
                                borderColor: "rgba(34, 211, 238, 0.82)",
                                boxShadow: "0 0 20px rgba(34, 211, 238, 0.2)",
                              }
                            : {
                                borderColor: "hsl(var(--border))",
                                boxShadow: "0 0 0px rgba(34, 211, 238, 0)",
                              }
                        }
                        transition={{ duration: shouldReduceMotion ? 0 : 0.2 }}
                        className="group relative flex items-center rounded-xl border border-slate-300 bg-white transition-colors hover:border-slate-400 dark:border-slate-800/95 dark:bg-[#070E1C]/90 dark:hover:border-slate-700"
                      >
                        <motion.span
                          animate={
                            focusedField === "email" && !shouldReduceMotion
                              ? { scale: 1.12 }
                              : { scale: 1 }
                          }
                          transition={{ duration: 0.18 }}
                          className={cn(
                            "pointer-events-none pl-3 transition-colors",
                            focusedField === "email" ? "text-sky-600 dark:text-cyan-300" : "text-slate-400"
                          )}
                        >
                          <Mail className="size-4" />
                        </motion.span>
                        <Input
                          id="email"
                          type="email"
                          placeholder="name@domain.com"
                          autoComplete="email"
                          value={email}
                          onFocus={() => setFocusedField("email")}
                          onBlur={() =>
                            setFocusedField((prev) => (prev === "email" ? null : prev))
                          }
                          onChange={(e) => setEmail(e.target.value)}
                          className="h-10 border-0 bg-transparent pl-2.5 pr-3 text-sm text-slate-900 placeholder:text-slate-400 focus-visible:ring-0 focus-visible:ring-offset-0 sm:h-9 dark:text-slate-100 dark:placeholder:text-slate-500"
                        />
                      </motion.div>
                    </motion.div>

                    {/* Staggered Field 2: Password Dark-Glass Input */}
                    {mode !== "forgot" && (
                      <motion.div
                        initial={shouldReduceMotion ? false : { opacity: 0, y: 6 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{
                          duration: shouldReduceMotion ? 0 : 0.24,
                          delay: shouldReduceMotion ? 0 : 0.09,
                        }}
                        className="space-y-1"
                      >
                        <div className="flex items-center justify-between">
                          <Label
                            htmlFor="password"
                            className="text-[11px] font-semibold tracking-wide text-slate-700 dark:text-slate-200"
                          >
                            Password
                          </Label>
                          {mode === "signin" && (
                            <motion.button
                              type="button"
                              whileHover={shouldReduceMotion ? { x: 0 } : { x: 1.5 }}
                              whileTap={shouldReduceMotion ? { scale: 1 } : { scale: 0.97 }}
                              className="rounded px-1 py-0.5 text-[11px] font-semibold text-sky-700 transition-colors hover:bg-sky-500/10 hover:text-sky-800 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyan-400 dark:text-cyan-300 dark:hover:bg-cyan-500/10 dark:hover:text-cyan-200"
                              onClick={() => switchMode("forgot")}
                            >
                              Forgot password?
                            </motion.button>
                          )}
                        </div>
                        <motion.div
                          animate={
                            focusedField === "password"
                              ? {
                                  borderColor: "rgba(34, 211, 238, 0.82)",
                                  boxShadow: "0 0 20px rgba(34, 211, 238, 0.2)",
                                }
                              : {
                                  borderColor: "hsl(var(--border))",
                                  boxShadow: "0 0 0px rgba(34, 211, 238, 0)",
                                }
                          }
                          transition={{ duration: shouldReduceMotion ? 0 : 0.2 }}
                          className="group relative flex items-center rounded-xl border border-slate-300 bg-white transition-colors hover:border-slate-400 dark:border-slate-800/95 dark:bg-[#070E1C]/90 dark:hover:border-slate-700"
                        >
                          <motion.span
                            animate={
                              focusedField === "password" && !shouldReduceMotion
                                ? { scale: 1.12, rotate: -6 }
                                : { scale: 1, rotate: 0 }
                            }
                            transition={{ duration: 0.18 }}
                            className={cn(
                              "pointer-events-none pl-3 transition-colors",
                              focusedField === "password" ? "text-sky-600 dark:text-cyan-300" : "text-slate-400"
                            )}
                          >
                            <KeyRound className="size-4" />
                          </motion.span>
                          <Input
                            id="password"
                            type={show ? "text" : "password"}
                            placeholder={
                              mode === "signup"
                                ? "Minimum 8 characters"
                                : "Enter your password"
                            }
                            autoComplete={
                              mode === "signup" ? "new-password" : "current-password"
                            }
                            value={password}
                            onFocus={() => setFocusedField("password")}
                            onBlur={() =>
                              setFocusedField((prev) => (prev === "password" ? null : prev))
                            }
                            onChange={(e) => setPassword(e.target.value)}
                            className="h-10 border-0 bg-transparent pl-2.5 pr-9 text-sm text-slate-900 placeholder:text-slate-400 focus-visible:ring-0 focus-visible:ring-offset-0 sm:h-9 dark:text-slate-100 dark:placeholder:text-slate-500"
                          />
                          <button
                            type="button"
                            aria-label={show ? "Hide password" : "Show password"}
                            onClick={() => setShow((prev) => !prev)}
                            className="absolute inset-y-0 right-1 my-auto grid size-8 place-items-center rounded-lg text-slate-500 transition-colors hover:bg-slate-100 hover:text-sky-700 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyan-400 dark:text-slate-400 dark:hover:bg-slate-800/80 dark:hover:text-cyan-200"
                          >
                            <AnimatePresence mode="wait" initial={false}>
                              <motion.span
                                key={show ? "eye-off" : "eye-on"}
                                initial={
                                  shouldReduceMotion
                                    ? false
                                    : { opacity: 0, rotate: -25, scale: 0.72 }
                                }
                                animate={{ opacity: 1, rotate: 0, scale: 1 }}
                                exit={
                                  shouldReduceMotion
                                    ? { opacity: 1 }
                                    : { opacity: 0, rotate: 25, scale: 0.72 }
                                }
                                transition={{ duration: shouldReduceMotion ? 0 : 0.15 }}
                                className="inline-flex"
                              >
                                {show ? (
                                  <EyeOff className="size-3.5" />
                                ) : (
                                  <Eye className="size-3.5" />
                                )}
                              </motion.span>
                            </AnimatePresence>
                          </button>
                        </motion.div>
                      </motion.div>
                    )}

                    {/* Animated Validation / Error & Info Alerts */}
                    <AnimatePresence initial={false}>
                      {error && (
                        <motion.div
                          key="auth-error-alert"
                          role="alert"
                          initial={shouldReduceMotion ? false : { opacity: 0, y: -6, scale: 0.98 }}
                          animate={{ opacity: 1, y: 0, scale: 1 }}
                          exit={shouldReduceMotion ? { opacity: 1 } : { opacity: 0, y: -4, scale: 0.98 }}
                          transition={{ duration: shouldReduceMotion ? 0 : 0.2 }}
                          className="flex items-start gap-2 rounded-xl border border-red-300 bg-red-50 px-3 py-2 text-[11px] leading-snug text-red-800 shadow-[0_0_16px_rgba(239,68,68,0.1)] dark:border-red-500/45 dark:bg-red-950/55 dark:text-red-200 dark:shadow-[0_0_16px_rgba(239,68,68,0.15)]"
                        >
                          <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-red-600 dark:text-red-400" />
                          <span>{error}</span>
                        </motion.div>
                      )}

                      {info && (
                        <motion.div
                          key="auth-info-alert"
                          role="status"
                          initial={shouldReduceMotion ? false : { opacity: 0, y: -6, scale: 0.98 }}
                          animate={{ opacity: 1, y: 0, scale: 1 }}
                          exit={shouldReduceMotion ? { opacity: 1 } : { opacity: 0, y: -4, scale: 0.98 }}
                          transition={{ duration: shouldReduceMotion ? 0 : 0.2 }}
                          className="flex items-start gap-2 rounded-xl border border-emerald-300 bg-emerald-50 px-3 py-2 text-[11px] leading-snug text-emerald-800 shadow-[0_0_16px_rgba(16,185,129,0.1)] dark:border-emerald-500/45 dark:bg-emerald-950/55 dark:text-emerald-200 dark:shadow-[0_0_16px_rgba(16,185,129,0.15)]"
                        >
                          <CheckCircle2 className="mt-0.5 size-3.5 shrink-0 text-emerald-600 dark:text-emerald-400" />
                          <span>{info}</span>
                        </motion.div>
                      )}
                    </AnimatePresence>

                    {/* 3. INTERACTIVE SIGN IN BUTTON WITH HOVER LIFT & PRESS FEEDBACK */}
                    <motion.div
                      whileHover={
                        shouldReduceMotion || busy ? { y: 0, scale: 1 } : { y: -1.5, scale: 1.01 }
                      }
                      whileTap={
                        shouldReduceMotion || busy ? { scale: 1 } : { scale: 0.985 }
                      }
                      transition={{ duration: 0.16 }}
                    >
                      <Button
                        type="submit"
                        disabled={busy}
                        className="group h-11 w-full rounded-xl bg-gradient-to-r from-cyan-400 via-sky-400 to-blue-500 text-xs font-bold tracking-wide text-slate-950 shadow-[0_8px_24px_-4px_rgba(34,211,238,0.45)] transition-all duration-200 hover:from-cyan-300 hover:via-sky-300 hover:to-blue-400 hover:shadow-[0_12px_30px_-2px_rgba(34,211,238,0.65)] sm:h-10 sm:text-sm"
                      >
                        {busy ? (
                          <Loader2 className="size-4 animate-spin text-slate-950" />
                        ) : (
                          <ShieldCheck className="size-4 text-slate-950 transition-transform duration-200 group-hover:scale-110" />
                        )}
                        <span>
                          {mode === "signin"
                            ? "Sign In"
                            : mode === "signup"
                              ? "Create Account"
                              : "Send Reset Link"}
                        </span>
                        {!busy && (
                          <ArrowRight className="size-3.5 text-slate-950/80 transition-transform duration-200 group-hover:translate-x-1" />
                        )}
                      </Button>
                    </motion.div>
                  </motion.form>
                </AnimatePresence>
              </motion.div>

              {/* ============================================================= */}
              {/* 4. REFINED VISUAL SEPARATOR ("YOUR SECURITY WORKSPACE")       */}
              {/* ============================================================= */}
              <motion.div
                initial={shouldReduceMotion ? false : { opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{
                  duration: shouldReduceMotion ? 0 : 0.3,
                  delay: shouldReduceMotion ? 0 : 0.22,
                }}
                className="my-3 flex items-center gap-2.5"
              >
                <div className="h-px flex-1 bg-gradient-to-r from-transparent via-slate-300 to-slate-300 dark:via-slate-700/80 dark:to-slate-800" />
                <span className="font-mono text-[9px] font-bold uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">
                  YOUR SECURITY WORKSPACE
                </span>
                <div className="h-px flex-1 bg-gradient-to-l from-transparent via-slate-300 to-slate-300 dark:via-slate-700/80 dark:to-slate-800" />
              </motion.div>

              {/* ============================================================= */}
              {/* 5. STAGGERED 3-ITEM SECURITY INFORMATION PANEL                */}
              {/* ============================================================= */}
              <div className="divide-y divide-slate-200 rounded-2xl border border-slate-200 bg-white/75 px-2.5 py-1 backdrop-blur-sm dark:divide-slate-800/80 dark:border-slate-800/90 dark:bg-slate-950/55">
                {SECURITY_INFO_ITEMS.map((item, idx) => {
                  const ItemIcon = item.icon;
                  return (
                    <motion.div
                      key={item.title}
                      initial={shouldReduceMotion ? false : { opacity: 0, x: -8 }}
                      animate={{ opacity: 1, x: 0 }}
                      whileHover={shouldReduceMotion ? { x: 0 } : { x: 3 }}
                      transition={{
                        duration: shouldReduceMotion ? 0 : 0.25,
                        delay: shouldReduceMotion ? 0 : 0.22 + idx * 0.06,
                        ease: "easeOut",
                      }}
                      className="group flex items-center gap-2.5 rounded-lg px-1 py-2 text-left transition-colors hover:bg-cyan-500/[0.04]"
                    >
                      <span
                        className={cn(
                          "grid size-6 shrink-0 place-items-center rounded-lg border transition-transform duration-200 group-hover:scale-110 group-hover:-rotate-6",
                          item.accent
                        )}
                      >
                        <ItemIcon className="size-3.5" />
                      </span>
                      <p className="min-w-0 text-[11px] leading-snug text-slate-600 dark:text-slate-300">
                        <strong className="font-semibold text-slate-900 transition-colors group-hover:text-sky-700 dark:text-slate-100 dark:group-hover:text-cyan-200">
                          {item.title}
                        </strong>{" "}
                        — {item.description}
                      </p>
                    </motion.div>
                  );
                })}
              </div>

              {/* ============================================================= */}
              {/* 6. INTERACTIVE MODE SWITCH FOOTER & SECURE AUTH BADGE         */}
              {/* ============================================================= */}
              <motion.div
                initial={shouldReduceMotion ? false : { opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{
                  duration: shouldReduceMotion ? 0 : 0.28,
                  delay: shouldReduceMotion ? 0 : 0.38,
                }}
                className="mt-3 flex flex-wrap items-center justify-between gap-2 rounded-xl border border-slate-200 bg-slate-50/80 px-3.5 py-2 text-xs dark:border-slate-800/80 dark:bg-slate-900/45"
              >
                {mode === "signin" ? (
                  <>
                    <span className="text-[11px] text-slate-600 dark:text-slate-400">
                      New to SCAMLENS AI?
                    </span>
                    <motion.button
                      type="button"
                      whileHover={shouldReduceMotion ? { scale: 1 } : { scale: 1.03, y: -1 }}
                      whileTap={shouldReduceMotion ? { scale: 1 } : { scale: 0.97 }}
                      onClick={() => switchMode("signup")}
                      className="inline-flex min-h-9 items-center gap-1 rounded-lg border border-sky-400/45 bg-sky-500/10 px-2.5 py-1 text-[11px] font-semibold text-sky-700 transition-colors hover:border-sky-500/60 hover:bg-sky-500/20 hover:text-sky-800 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyan-400 dark:border-cyan-400/35 dark:bg-cyan-500/10 dark:text-cyan-300 dark:hover:border-cyan-400/60 dark:hover:bg-cyan-500/20 dark:hover:text-cyan-200"
                    >
                      <UserPlus className="size-3" />
                      Create account
                    </motion.button>
                  </>
                ) : (
                  <>
                    <span className="text-[11px] text-slate-600 dark:text-slate-400">
                      Already registered?
                    </span>
                    <motion.button
                      type="button"
                      whileHover={shouldReduceMotion ? { scale: 1 } : { scale: 1.03, y: -1 }}
                      whileTap={shouldReduceMotion ? { scale: 1 } : { scale: 0.97 }}
                      onClick={() => switchMode("signin")}
                      className="inline-flex min-h-9 items-center gap-1 rounded-lg border border-sky-400/45 bg-sky-500/10 px-2.5 py-1 text-[11px] font-semibold text-sky-700 transition-colors hover:border-sky-500/60 hover:bg-sky-500/20 hover:text-sky-800 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyan-400 dark:border-cyan-400/35 dark:bg-cyan-500/10 dark:text-cyan-300 dark:hover:border-cyan-400/60 dark:hover:bg-cyan-500/20 dark:hover:text-cyan-200"
                    >
                      <ShieldCheck className="size-3" />
                      Sign In
                    </motion.button>
                  </>
                )}
              </motion.div>

              {/* Subtle Security Badge with Glowing Lock Icon + Home Indicator Bar */}
              <div className="mt-2.5 flex items-center justify-center">
                <span className="inline-flex items-center gap-1.5 rounded-full border border-sky-300/60 bg-white/85 px-2.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-sky-700 shadow-[0_0_12px_rgba(14,165,233,0.1)] dark:border-cyan-500/20 dark:bg-slate-950/80 dark:text-cyan-300/85 dark:shadow-[0_0_12px_rgba(34,211,238,0.12)]">
                  <LockKeyhole className="size-2.5 text-sky-600 drop-shadow-[0_0_6px_rgba(34,211,238,0.75)] dark:text-cyan-400" />
                  Secure Authentication
                </span>
              </div>

              <div
                aria-hidden="true"
                className="mx-auto mt-2.5 h-1 w-28 rounded-full bg-slate-300 dark:bg-slate-700/90"
              />
            </div>
          </div>
        </div>
      </motion.main>
    </div>
  );
}
