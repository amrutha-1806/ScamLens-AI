import { useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  AlertTriangle,
  AtSign,
  CheckCircle2,
  ExternalLink,
  FileSearch,
  Globe2,
  Info,
  Link2,
  Loader2,
  LockKeyhole,
  Mail,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
  UserCheck,
  UserX,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { ApiNotice, Panel } from "./primitives";
import { ExplainabilityCard, LanguageTransparencyCard } from "./explainable-ai";
import { robotGuardian } from "./cyber-robot";
import { scamlensApi, ScamlensApiError } from "@/lib/scamlens-api";
import { useScamlensPreferences } from "@/lib/scamlens-preferences";
import { useQueryClient } from "@tanstack/react-query";
import type { AnalysisResult, EmailAnalysisRequest, SenderAnalysis } from "@/lib/scamlens-types";
import { cn } from "@/lib/utils";

const emailExamples = {
  "PayPal Impersonation Phishing": {
    sender: "PayPal Security Department <alert@verify-account-update.com>",
    subject: "Action Required: Suspicious Login Detected on Your Account",
    body: `Dear Customer,\n\nWe detected an unauthorized transaction of $499.00 on your PayPal account. If you did not authorize this payment, please secure your account immediately.\n\nClick the link below to verify your identity and cancel the transaction:\nhttp://192.168.1.100/paypal/login.php\n\nFailure to verify within 24 hours will result in permanent account suspension.\n\nSincerely,\nPayPal Account Protection Team`,
  },
  "Bank KYC Suspension Threat": {
    sender: "State Bank of India <notice@free-updates-kyc.org>",
    subject: "URGENT: Your NetBanking access is blocked due to incomplete KYC",
    body: `Dear SBI Customer,\n\nYour account #XXXX9821 has been blocked temporarily because your mandatory PAN-Aadhaar KYC is pending.\n\nPlease update your KYC immediately to resume banking services:\nhttps://bit.ly/3xY79aZ\n\nDo not share your OTP with anyone.\n\nSBI e-Banking Services`,
  },
  "Legitimate Work Schedule Email": {
    sender: "Sarah Jenkins <sjenkins@acmecorp.internal>",
    subject: "Sprint Planning Agenda for Thursday 10:00 AM",
    body: `Hi everyone,\n\nHere is our tentative agenda for Thursday's sprint planning session:\n1. Review sprint 14 metrics and backlog velocity.\n2. Finalize stories for the customer portal v2 milestone.\n3. Architecture discussion on database indexing.\n\nPlease review the ticket queue before our sync.\n\nBest regards,\nSarah Jenkins\nEngineering Team Lead`,
  },
} as const;

export function EmailAnalyzerSection({
  onResultUpdated,
}: {
  onResultUpdated?: (res: AnalysisResult | null) => void;
}) {
  const { shouldReduceMotion } = useScamlensPreferences();
  const [sender, setSender] = useState("");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [status, setStatus] = useState<"idle" | "loading" | "error" | "success">("idle");
  const [error, setError] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const queryClient = useQueryClient();

  async function handleScan() {
    if (!sender.trim() || sender.trim().length < 3) {
      const msg = "Please provide a valid sender email address or header.";
      setError(msg);
      setStatus("error");
      robotGuardian.notifyInvalid(msg, "email");
      return;
    }
    if (!body.trim() || body.trim().length < 3) {
      const msg = "Please provide the email body text (minimum 3 characters).";
      setError(msg);
      setStatus("error");
      robotGuardian.notifyInvalid(msg, "email");
      return;
    }

    setStatus("loading");
    setError("");
    setResult(null);
    robotGuardian.notifyScanning("Inspecting email headers, body, and embedded links...", "email");

    try {
      const response = await scamlensApi.analyzeEmail({
        sender: sender.trim(),
        subject: subject.trim(),
        body: body.trim(),
      });
      setResult(response);
      setStatus("success");
      robotGuardian.notifyAnalysisResult(response, "Email", "email");
      onResultUpdated?.(response);
      void queryClient.invalidateQueries({ queryKey: ["scamlens", "history"] });
    } catch (err) {
      const msg = err instanceof ScamlensApiError || err instanceof Error ? err.message : "Email analysis failed.";
      setError(msg);
      setStatus("error");
      setResult(null);
      robotGuardian.notifyInvalid(msg, "email");
      onResultUpdated?.(null);
    }
  }

  function handleClear() {
    setSender("");
    setSubject("");
    setBody("");
    setStatus("idle");
    setError("");
    setResult(null);
    robotGuardian.resetToIdle();
    onResultUpdated?.(null);
  }

  function loadSample(key: keyof typeof emailExamples) {
    const sample = emailExamples[key];
    setSender(sample.sender);
    setSubject(sample.subject);
    setBody(sample.body);
    setStatus("idle");
    setError("");
    setResult(null);
    robotGuardian.resetToIdle();
  }

  return (
    <div className="space-y-6">
      {/* Input panel */}
      <Panel
        title="Email Forensic Inspection Input"
        description="Analyze incoming email headers, sender display-name impersonation, urgency triggers, and embedded links without network execution."
        delay={0.04}
      >
        <div className="space-y-4">
          {/* Sender / From input */}
          <div>
            <div className="mb-1.5 flex items-center justify-between text-xs">
              <label htmlFor="email-sender" className="font-semibold text-foreground">
                Sender / From Header
              </label>
              <span className="text-muted-foreground">Format: "Name" &lt;user@domain.com&gt; or plain email</span>
            </div>
            <div className="relative">
              <AtSign className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                id="email-sender"
                value={sender}
                onChange={(e) => {
                  setSender(e.target.value);
                  setStatus("idle");
                }}
                placeholder='e.g. PayPal Support <service@security-update-fake.com>'
                className="pl-9 text-xs sm:text-sm"
              />
            </div>
          </div>

          {/* Subject input */}
          <div>
            <div className="mb-1.5 flex items-center justify-between text-xs">
              <label htmlFor="email-subject" className="font-semibold text-foreground">
                Subject Line (Optional)
              </label>
              <span className="text-muted-foreground">Checked for psychological urgency coercion</span>
            </div>
            <Input
              id="email-subject"
              value={subject}
              onChange={(e) => {
                setSubject(e.target.value);
                setStatus("idle");
              }}
              placeholder="e.g. URGENT: Unauthorized transaction detected on your account"
              className="text-xs sm:text-sm"
            />
          </div>

          {/* Body input */}
          <div>
            <div className="mb-1.5 flex items-center justify-between text-xs">
              <label htmlFor="email-body" className="font-semibold text-foreground">
                Email Body Text
              </label>
              <span className="font-mono text-muted-foreground">{body.length.toLocaleString()} / 50,000 chars</span>
            </div>
            <Textarea
              id="email-body"
              value={body}
              onChange={(e) => {
                setBody(e.target.value);
                setStatus("idle");
              }}
              placeholder="Paste email message text, greeting, instructions, and embedded links here..."
              className="min-h-48 resize-y text-xs leading-relaxed sm:text-sm"
            />
          </div>

          {/* Action buttons */}
          <div className="flex flex-wrap items-center gap-2.5 pt-1">
            <Button
              onClick={handleScan}
              disabled={status === "loading"}
              className="min-h-10 flex-1 transition-transform active:scale-97 sm:flex-initial"
            >
              {status === "loading" ? <Loader2 className="size-4 animate-spin" /> : <Mail className="size-4" />}
              {status === "loading" ? "Analyzing Email..." : "Analyze Email"}
            </Button>
            <Button
              variant="outline"
              disabled={!sender && !body && status === "idle"}
              onClick={handleClear}
              className="min-h-10 flex-1 transition-transform active:scale-97 sm:flex-initial"
            >
              <Trash2 className="size-4" /> Clear
            </Button>
          </div>

          {status === "error" && error && (
            <ApiNotice kind="error" message={error} />
          )}

          {/* Sample quick-loads */}
          <div className="border-t border-border pt-4">
            <p className="mb-2 text-xs font-semibold text-foreground">Load Sample Email for Static Testing</p>
            <div className="grid gap-2 sm:grid-cols-3">
              {(Object.keys(emailExamples) as Array<keyof typeof emailExamples>).map((k) => (
                <button
                  key={k}
                  type="button"
                  onClick={() => loadSample(k)}
                  className="rounded-lg border border-border bg-secondary/30 p-2.5 text-left text-xs transition-colors hover:border-primary/45 hover:bg-secondary/60"
                >
                  <p className="font-semibold text-foreground">{k}</p>
                  <p className="mt-0.5 truncate text-[11px] text-muted-foreground">{emailExamples[k].subject}</p>
                </button>
              ))}
            </div>
          </div>
        </div>
      </Panel>

      {/* Results view if result present */}
      <AnimatePresence>
        {result && (
          <motion.div
            initial={shouldReduceMotion ? false : { opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={shouldReduceMotion ? { opacity: 1 } : { opacity: 0 }}
            className="space-y-6"
          >
            {/* Sender Spoofing Analysis Card */}
            {result.senderAnalysis && <SenderAnalysisCard senderAnalysis={result.senderAnalysis} />}

            {/* Embedded URLs Card */}
            {result.embeddedUrls && result.embeddedUrls.length > 0 && (
              <Panel
                title={`Embedded Links Inspected (${result.embeddedUrls.length})`}
                description="Links extracted from email body and analyzed with static structural heuristics."
                delay={0.06}
              >
                <div className="space-y-2">
                  {result.embeddedUrls.map((link, idx) => (
                    <div
                      key={idx}
                      className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-border bg-secondary/25 p-3 text-xs"
                    >
                      <div className="flex items-center gap-2 truncate">
                        <Link2 className="size-4 shrink-0 text-primary" />
                        <span className="truncate font-mono font-medium text-foreground">{link}</span>
                      </div>
                      <span className="rounded border border-primary/25 bg-primary/10 px-2 py-0.5 text-[10px] font-semibold text-primary">
                        Statically Evaluated
                      </span>
                    </div>
                  ))}
                </div>
              </Panel>
            )}

            {/* Explainable AI Card */}
            {result.explainability && <ExplainabilityCard explainability={result.explainability} />}

            {/* Multilingual Card */}
            {result.languageInfo && <LanguageTransparencyCard languageInfo={result.languageInfo} />}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function SenderAnalysisCard({ senderAnalysis }: { senderAnalysis: SenderAnalysis }) {
  const isSpoofed = Boolean(senderAnalysis.spoofed_brand);
  const isFreeWebmail = senderAnalysis.is_free_webmail;

  return (
    <div className="space-y-3 rounded-xl border border-primary/25 bg-card p-4 shadow-panel sm:p-5 dark:border-cyan-500/25 dark:bg-slate-950/70">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border pb-3 dark:border-slate-800">
        <div className="flex items-center gap-2">
          <AtSign className="size-4 text-primary" />
          <h4 className="text-sm font-bold text-foreground">Sender &amp; Header Authentication Forensics</h4>
        </div>
        <span
          className={cn(
            "rounded-full border px-2.5 py-0.5 text-[10px] font-bold uppercase",
            isSpoofed
              ? "border-danger/40 bg-danger/10 text-danger"
              : isFreeWebmail
                ? "border-warning/40 bg-warning/10 text-warning"
                : "border-safe/40 bg-safe/10 text-safe"
          )}
        >
          {isSpoofed ? "Display Name Spoofing Detected" : isFreeWebmail ? "Public Webmail Sender" : "Standard Sender"}
        </span>
      </div>

      {/* Impersonation Alert Banner */}
      {isSpoofed && (
        <div className="flex items-start gap-2.5 rounded-lg border border-danger/40 bg-danger/10 p-3 text-xs text-danger dark:border-rose-900/40 dark:bg-rose-950/20 dark:text-rose-300">
          <UserX className="mt-0.5 size-4 shrink-0" />
          <div>
            <strong className="font-bold">Executive / Brand Impersonation Alert: </strong>
            The sender display name claims to represent <strong>{senderAnalysis.spoofed_brand}</strong>, but the actual
            transmitting email domain is <span className="font-mono font-bold">@{senderAnalysis.registrable_domain}</span>
            . Legitimate {senderAnalysis.spoofed_brand} notifications do not originate from this domain.
          </div>
        </div>
      )}

      {/* Sender breakdown table */}
      <div className="grid grid-cols-2 gap-2 text-xs sm:grid-cols-4">
        <div className="rounded border border-border bg-secondary/25 p-2.5">
          <span className="text-[10px] text-muted-foreground">Display Name</span>
          <p className="truncate font-semibold text-foreground">{senderAnalysis.display_name || "—"}</p>
        </div>
        <div className="rounded border border-border bg-secondary/25 p-2.5">
          <span className="text-[10px] text-muted-foreground">Email Address</span>
          <p className="truncate font-mono font-semibold text-foreground">{senderAnalysis.email_address || "—"}</p>
        </div>
        <div className="rounded border border-border bg-secondary/25 p-2.5">
          <span className="text-[10px] text-muted-foreground">Sender Domain</span>
          <p className="truncate font-mono font-semibold text-foreground">@{senderAnalysis.domain || "—"}</p>
        </div>
        <div className="rounded border border-border bg-secondary/25 p-2.5">
          <span className="text-[10px] text-muted-foreground">Provider Classification</span>
          <p className="font-semibold text-foreground">
            {senderAnalysis.is_free_webmail ? "Free Public Webmail" : "Custom / Corporate Domain"}
          </p>
        </div>
      </div>

      {/* Header findings list */}
      {senderAnalysis.header_findings.length > 0 && (
        <div className="space-y-1.5 pt-1">
          {senderAnalysis.header_findings.map((hf, i) => (
            <div
              key={i}
              className="flex items-start gap-2 rounded border border-border bg-secondary/15 p-2 text-xs text-foreground"
            >
              <AlertTriangle
                className={cn(
                  "mt-0.5 size-3.5 shrink-0",
                  hf.severity === "high" ? "text-danger" : "text-warning"
                )}
              />
              <div>
                <p className="font-semibold text-foreground">{hf.title}</p>
                <p className="text-[11px] text-muted-foreground">{hf.detail}</p>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
