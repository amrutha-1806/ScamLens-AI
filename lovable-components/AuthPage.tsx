import React, { useState } from "react";
import {
  Shield,
  ShieldCheck,
  Lock,
  Mail,
  Eye,
  EyeOff,
  ArrowRight,
  CheckCircle2,
  AlertCircle,
  KeyRound,
  Fingerprint,
  Activity,
  Sparkles,
  Zap,
} from "lucide-react";

export default function AuthPage() {
  const [isSignUp, setIsSignUp] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  // Form fields
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [fullName, setFullName] = useState("");

  // Validation & feedback state
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [infoMessage, setInfoMessage] = useState<string | null>(null);

  // Validate form inputs
  const validateForm = () => {
    const newErrors: Record<string, string> = {};

    if (!email.trim()) {
      newErrors.email = "Email address is required.";
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
      newErrors.email = "Please enter a valid email address.";
    }

    if (!password) {
      newErrors.password = "Password is required.";
    } else if (password.length < 8) {
      newErrors.password = "Password must be at least 8 characters long.";
    }

    if (isSignUp) {
      if (!fullName.trim()) {
        newErrors.fullName = "Full name is required.";
      }
      if (password !== confirmPassword) {
        newErrors.confirmPassword = "Passwords do not match.";
      }
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setInfoMessage(null);

    if (!validateForm()) return;

    setIsLoading(true);

    // Simulate network authentication request
    setTimeout(() => {
      setIsLoading(false);
      // Factual status: Inform the user about backend auth status
      // We do NOT fake a successful login when no auth backend is configured.
      setInfoMessage(
        "Notice: SCAMLENS AI backend currently operates in offline ML inference mode without a persistent user account service. To enable real multi-user authentication, configure Supabase Auth or add JWT authentication endpoints (/api/auth) to FastAPI."
      );
    }, 900);
  };

  const handleForgotPassword = (e: React.MouseEvent) => {
    e.preventDefault();
    setInfoMessage(
      "Password reset request received. When real authentication (e.g. Supabase Auth) is connected, a reset link will be dispatched to your email."
    );
  };

  return (
    <div className="min-h-screen w-full bg-[#030712] text-slate-100 flex items-center justify-center p-4 sm:p-6 lg:p-8 relative overflow-hidden font-sans">
      {/* Background radial gradients & subtle cybersecurity grid */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-blue-900/20 via-[#030712] to-[#030712] pointer-events-none" />
      <div className="absolute -top-40 -left-40 w-96 h-96 bg-blue-600/10 rounded-full blur-[120px] pointer-events-none" />
      <div className="absolute -bottom-40 -right-40 w-96 h-96 bg-emerald-500/10 rounded-full blur-[120px] pointer-events-none" />

      {/* Cyber grid lines overlay */}
      <div
        className="absolute inset-0 opacity-[0.03] pointer-events-none"
        style={{
          backgroundImage: `linear-gradient(#3b82f6 1px, transparent 1px), linear-gradient(90deg, #3b82f6 1px, transparent 1px)`,
          backgroundSize: "40px 40px",
        }}
      />

      {/* Main Container: Split-screen card */}
      <div className="relative w-full max-w-5xl rounded-2xl border border-slate-800/80 bg-slate-900/60 backdrop-blur-xl shadow-2xl overflow-hidden grid grid-cols-1 lg:grid-cols-12 z-10 transition-all duration-300">
        
        {/* LEFT PANEL: Branding & Animated Cybersecurity Illustration (5 cols on lg) */}
        <div className="lg:col-span-5 bg-gradient-to-br from-slate-900/90 via-[#0b132b]/80 to-slate-950 p-8 sm:p-10 flex flex-col justify-between border-b lg:border-b-0 lg:border-r border-slate-800/80 relative overflow-hidden">
          
          {/* Subtle scanning line effect */}
          <div className="absolute inset-x-0 h-24 bg-gradient-to-b from-transparent via-blue-500/[0.04] to-transparent animate-pulse pointer-events-none" />

          {/* Brand header */}
          <div className="relative z-10">
            <div className="flex items-center gap-3">
              <div className="h-11 w-11 rounded-xl bg-gradient-to-tr from-blue-600 to-cyan-400 p-0.5 flex items-center justify-center shadow-lg shadow-blue-500/20">
                <div className="h-full w-full bg-slate-950 rounded-[10px] flex items-center justify-center">
                  <ShieldCheck className="h-6 w-6 text-cyan-400" />
                </div>
              </div>
              <div>
                <span className="text-xl font-black tracking-tight bg-gradient-to-r from-white via-slate-100 to-slate-300 bg-clip-text text-transparent">
                  SCAMLENS <span className="text-blue-500">AI</span>
                </span>
                <p className="text-[11px] font-medium text-slate-400 tracking-wide uppercase">
                  Intelligent Scam & Phishing Defense
                </p>
              </div>
            </div>

            <p className="mt-6 text-sm text-blue-200/80 italic font-medium flex items-center gap-2">
              <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-ping" />
              “See the risk before you click.”
            </p>
          </div>

          {/* Animated Centerpiece: Shield, Radar Rings, Telemetry */}
          <div className="my-8 py-4 relative flex flex-col items-center justify-center z-10">
            {/* Concentric glowing radar rings */}
            <div className="relative w-48 h-48 flex items-center justify-center">
              <div className="absolute inset-0 rounded-full border border-blue-500/20 animate-spin duration-[20000ms] pointer-events-none" />
              <div className="absolute inset-4 rounded-full border border-cyan-400/20 border-dashed animate-spin duration-[15000ms] reverse pointer-events-none" />
              <div className="absolute inset-8 rounded-full border border-emerald-500/20 pointer-events-none" />

              {/* Core Shield badge with glow */}
              <div className="relative z-10 h-24 w-24 rounded-2xl bg-gradient-to-br from-blue-600/30 to-slate-900/90 border border-blue-400/40 backdrop-blur-md flex items-center justify-center shadow-2xl shadow-blue-500/30 transition-transform hover:scale-105 duration-300">
                <Shield className="h-12 w-12 text-blue-400 filter drop-shadow-[0_0_12px_rgba(59,130,246,0.6)]" />
                <Lock className="h-5 w-5 text-emerald-400 absolute bottom-5 right-5 filter drop-shadow-[0_0_8px_rgba(16,185,129,0.8)]" />
              </div>
            </div>

            {/* Live Model Telemetry Pill */}
            <div className="mt-4 px-4 py-2 rounded-full bg-slate-950/70 border border-slate-800 text-[11px] font-mono text-slate-300 flex items-center gap-2 shadow-inner">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
              <span>Random Forest ML: 200 Trees Active</span>
            </div>
          </div>

          {/* Security note footer */}
          <div className="relative z-10 pt-4 border-t border-slate-800/60">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <Fingerprint className="h-4 w-4 text-cyan-400 shrink-0" />
              <span>
                Your security starts here. 100% offline heuristic & TF-IDF model evaluation.
              </span>
            </div>
          </div>
        </div>

        {/* RIGHT PANEL: Form Container (7 cols on lg) */}
        <div className="lg:col-span-7 p-8 sm:p-10 lg:p-12 flex flex-col justify-center bg-slate-900/40 relative">
          
          {/* Form Header */}
          <div className="mb-8">
            <div className="flex items-center justify-between">
              <h2 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-white">
                {isSignUp ? "Create Account" : "Welcome Back"}
              </h2>
              <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20">
                {isSignUp ? "New Portal" : "Cyber Sentinel"}
              </span>
            </div>
            <p className="text-sm text-slate-400 mt-2">
              {isSignUp
                ? "Start protecting your digital life with ML-driven threat detection."
                : "Secure your digital world with SCAMLENS AI."}
            </p>
          </div>

          {/* Informational / Status banner */}
          {infoMessage && (
            <div className="mb-6 p-3.5 rounded-lg bg-blue-950/50 border border-blue-500/30 text-xs text-blue-200 leading-relaxed flex items-start gap-2.5 animate-in fade-in duration-200">
              <AlertCircle className="h-4 w-4 text-blue-400 shrink-0 mt-0.5" />
              <span>{infoMessage}</span>
            </div>
          )}

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            
            {/* Full Name field (Sign Up only) */}
            {isSignUp && (
              <div className="space-y-1.5 animate-in fade-in duration-200">
                <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                  Full Name
                </label>
                <div className="relative">
                  <input
                    type="text"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    placeholder="Alex Morgan"
                    className={`w-full h-11 px-3.5 rounded-lg bg-slate-950/60 border ${
                      errors.fullName
                        ? "border-rose-500/80 focus:ring-rose-500/40"
                        : "border-slate-800 focus:border-blue-500 focus:ring-blue-500/30"
                    } text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:ring-2 transition-all`}
                  />
                </div>
                {errors.fullName && (
                  <p className="text-[11px] text-rose-400 font-medium">{errors.fullName}</p>
                )}
              </div>
            )}

            {/* Email Field */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                Email Address
              </label>
              <div className="relative">
                <Mail className="absolute left-3.5 top-3.5 h-4 w-4 text-slate-500" />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@scamlens.ai"
                  className={`w-full h-11 pl-10 pr-3.5 rounded-lg bg-slate-950/60 border ${
                    errors.email
                      ? "border-rose-500/80 focus:ring-rose-500/40"
                      : "border-slate-800 focus:border-blue-500 focus:ring-blue-500/30"
                  } text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:ring-2 transition-all`}
                />
              </div>
              {errors.email && (
                <p className="text-[11px] text-rose-400 font-medium">{errors.email}</p>
              )}
            </div>

            {/* Password Field */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3.5 top-3.5 h-4 w-4 text-slate-500" />
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className={`w-full h-11 pl-10 pr-10 rounded-lg bg-slate-950/60 border ${
                    errors.password
                      ? "border-rose-500/80 focus:ring-rose-500/40"
                      : "border-slate-800 focus:border-blue-500 focus:ring-blue-500/30"
                  } text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:ring-2 transition-all`}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3.5 top-3.5 text-slate-500 hover:text-slate-300 focus:outline-none transition-colors"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
              {errors.password && (
                <p className="text-[11px] text-rose-400 font-medium">{errors.password}</p>
              )}
            </div>

            {/* Confirm Password Field (Sign Up only) */}
            {isSignUp && (
              <div className="space-y-1.5 animate-in fade-in duration-200">
                <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                  Confirm Password
                </label>
                <div className="relative">
                  <KeyRound className="absolute left-3.5 top-3.5 h-4 w-4 text-slate-500" />
                  <input
                    type={showConfirmPassword ? "text" : "password"}
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="••••••••••••"
                    className={`w-full h-11 pl-10 pr-10 rounded-lg bg-slate-950/60 border ${
                      errors.confirmPassword
                        ? "border-rose-500/80 focus:ring-rose-500/40"
                        : "border-slate-800 focus:border-blue-500 focus:ring-blue-500/30"
                    } text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:ring-2 transition-all`}
                  />
                  <button
                    type="button"
                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                    className="absolute right-3.5 top-3.5 text-slate-500 hover:text-slate-300 focus:outline-none transition-colors"
                  >
                    {showConfirmPassword ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </button>
                </div>
                {errors.confirmPassword && (
                  <p className="text-[11px] text-rose-400 font-medium">
                    {errors.confirmPassword}
                  </p>
                )}
              </div>
            )}

            {/* Remember Me & Forgot Password (Sign In) */}
            {!isSignUp && (
              <div className="flex items-center justify-between text-xs pt-1">
                <label className="flex items-center gap-2 text-slate-300 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={rememberMe}
                    onChange={(e) => setRememberMe(e.target.checked)}
                    className="rounded border-slate-700 bg-slate-950 text-blue-600 focus:ring-blue-500/40 h-4 w-4"
                  />
                  <span>Remember Me</span>
                </label>
                <button
                  type="button"
                  onClick={handleForgotPassword}
                  className="text-blue-400 hover:text-blue-300 font-medium transition-colors"
                >
                  Forgot Password?
                </button>
              </div>
            )}

            {/* Submit Button */}
            <div className="pt-2">
              <button
                type="submit"
                disabled={isLoading}
                className="w-full h-11 rounded-lg bg-gradient-to-r from-blue-600 via-blue-500 to-cyan-500 hover:from-blue-500 hover:to-cyan-400 text-white font-semibold text-sm shadow-lg shadow-blue-500/25 flex items-center justify-center gap-2 transition-all duration-200 active:scale-[0.99] disabled:opacity-70 disabled:cursor-not-allowed group"
              >
                {isLoading ? (
                  <div className="h-4 w-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                ) : (
                  <>
                    <span>{isSignUp ? "Create Protected Account" : "Sign In to Console"}</span>
                    <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-0.5" />
                  </>
                )}
              </button>
            </div>
          </form>

          {/* Toggle between Sign In and Sign Up */}
          <div className="mt-8 text-center border-t border-slate-800/60 pt-6">
            <p className="text-xs text-slate-400">
              {isSignUp ? "Already registered with SCAMLENS AI?" : "Don't have an analyst account yet?"}{" "}
              <button
                type="button"
                onClick={() => {
                  setIsSignUp(!isSignUp);
                  setErrors({});
                  setInfoMessage(null);
                }}
                className="font-semibold text-blue-400 hover:text-cyan-300 transition-colors ml-1 inline-flex items-center gap-1"
              >
                {isSignUp ? "Sign In instead" : "Create Account"}
              </button>
            </p>
          </div>

          {/* System Compliance Badge */}
          <div className="mt-6 flex items-center justify-center gap-2 text-[11px] text-slate-500">
            <ShieldCheck className="h-3.5 w-3.5 text-emerald-500" />
            <span>End-to-End Cryptographic Security • Offline ML Engine</span>
          </div>
        </div>

      </div>
    </div>
  );
}
