import * as React from "react";
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  GraduationCap,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Target,
  Trophy,
  XCircle,
} from "lucide-react";
import { Badge, Button, Card, cn } from "./ui";

export interface SpotScamQuizItem {
  id: string;
  category: "Phishing" | "Fake Bank Message" | "Prize Scam" | "OTP Request" | "Payment / UPI Scam" | "Verified Communication";
  sender: string;
  channel: "SMS" | "Email" | "WhatsApp / UPI";
  message: string;
  correctChoice: "Legitimate" | "Suspicious";
  simpleExplanation: string;
  warningSigns: string[];
}

export const SPOT_THE_SCAM_ITEMS: SpotScamQuizItem[] = [
  {
    id: "quiz-bank-kyc",
    category: "Fake Bank Message",
    sender: "+91-98112-XX402 (Unknown Mobile)",
    channel: "SMS",
    message:
      "Dear Customer, your SBI Savings Account will be blocked today at 11:59 PM due to pending PAN-KYC update. Act immediately at http://sbi-kyc-portal-verify.example/login to keep your account active.",
    correctChoice: "Suspicious",
    simpleExplanation:
      "This is a classic fake bank KYC phishing message. Banks never send KYC update links from personal mobile numbers or threaten same-day account suspension over unencrypted HTTP links.",
    warningSigns: [
      "Sent from a regular 10-digit mobile number instead of an official bank header.",
      "Threatens immediate account blocking ('blocked today at 11:59 PM') to cause panic.",
      "Directs you to an unencrypted lookalike website ('http://sbi-kyc-portal-verify.example').",
    ],
  },
  {
    id: "quiz-otp-request",
    category: "OTP Request",
    sender: "Security-Support-Desk",
    channel: "WhatsApp / UPI",
    message:
      "Hello, I am calling from your bank's fraud prevention team. To cancel an unauthorized debit of Rs 18,500 on your card, please reply with the 6-digit OTP just sent to your phone.",
    correctChoice: "Suspicious",
    simpleExplanation:
      "Legitimate bank staff will NEVER ask you to share an OTP to 'cancel' or 'reverse' a transaction. Sharing the OTP actually authorizes the thief's transaction.",
    warningSigns: [
      "Asks you to share a confidential 6-digit OTP.",
      "Uses the false pretext of 'cancelling' an unauthorized debit.",
      "Contacts you via an unverified chat message.",
    ],
  },
  {
    id: "quiz-upi-qr-refund",
    category: "Payment / UPI Scam",
    sender: "Marketplace Buyer (+91-90041-XX819)",
    channel: "WhatsApp / UPI",
    message:
      "I have sent Rs 4,500 for the furniture listing via UPI QR code. Please scan the attached QR code and enter your UPI PIN to receive the Rs 4,500 payment into your bank account.",
    correctChoice: "Suspicious",
    simpleExplanation:
      "This is a UPI 'Scan to Receive' payment scam. You NEVER need to scan a QR code or enter your UPI PIN to receive money—entering your PIN always deducts money from your account.",
    warningSigns: [
      "Claims you must scan a QR code and enter your UPI PIN to receive money.",
      "Exploits confusion between UPI payment collection and receiving funds.",
    ],
  },
  {
    id: "quiz-legit-bank-alert",
    category: "Verified Communication",
    sender: "AD-HDFCBK (Official Bank Header)",
    channel: "SMS",
    message:
      "INR 340.00 debited from A/c XX4821 on 11-Nov via UPI Ref 431518992014. Not you? Call 18002586161 (official number on the back of your debit card).",
    correctChoice: "Legitimate",
    simpleExplanation:
      "This is a standard transactional notification. It contains no external login links, does not ask for your OTP or PIN, and directs you to verify using the official number printed on your card.",
    warningSigns: [
      "No external links or URL shorteners included.",
      "Does not request any OTP, PIN, or password.",
      "Advises calling the official number on the back of your physical bank card.",
    ],
  },
  {
    id: "quiz-prize-lottery",
    category: "Prize Scam",
    sender: "Mega-Lucky-Draw-Official",
    channel: "SMS",
    message:
      "CONGRATULATIONS! Your mobile number has won Rs 5,00,000 in the Festival Bumper Draw! Claim your reward now by paying Rs 999 processing charge at http://claim-festival-prize.example.",
    correctChoice: "Suspicious",
    simpleExplanation:
      "Real lotteries and rewards never ask winners to pay an advance 'processing charge' or 'release fee' to receive their prize.",
    warningSigns: [
      "Promises a large unsolicited cash prize ('won Rs 5,00,000').",
      "Demands an upfront processing fee ('paying Rs 999 processing charge').",
      "Uses an unverified external claim link.",
    ],
  },
  {
    id: "quiz-phishing-email",
    category: "Phishing",
    sender: "security-alert@paypa1-account-support.example",
    channel: "Email",
    message:
      "We noticed unusual activity on your account. Please sign in immediately at https://paypa1-account-support.example/verify to confirm your identity and prevent permanent suspension.",
    correctChoice: "Suspicious",
    simpleExplanation:
      "Look closely at the sender and link domain: it uses the digit '1' instead of the letter 'l' ('paypa1')—a character-substitution lookalike domain designed to steal your login password.",
    warningSigns: [
      "Lookalike character substitution in domain ('paypa1' with a '1' instead of 'paypal').",
      "Threatens permanent account suspension to rush you into logging in.",
    ],
  },
];

export function SpotTheScamInteractiveQuiz() {
  const [currentIndex, setCurrentIndex] = React.useState<number>(0);
  const [answers, setAnswers] = React.useState<Record<string, "Legitimate" | "Suspicious">>({});

  const totalQuestions = SPOT_THE_SCAM_ITEMS.length;
  const currentItem = SPOT_THE_SCAM_ITEMS[currentIndex] ?? SPOT_THE_SCAM_ITEMS[0]!;
  const selectedAnswer = answers[currentItem.id];
  const answeredCount = Object.keys(answers).length;

  const score = React.useMemo(() => {
    let correct = 0;
    for (const item of SPOT_THE_SCAM_ITEMS) {
      if (answers[item.id] && answers[item.id] === item.correctChoice) {
        correct += 1;
      }
    }
    return correct;
  }, [answers]);

  // Immediately records choice and reveals explanation upon clicking Legitimate or Suspicious
  const handleSelectChoice = (choice: "Legitimate" | "Suspicious") => {
    if (answers[currentItem.id]) return;
    setAnswers((prev) => ({ ...prev, [currentItem.id]: choice }));
  };

  const handleRestart = () => {
    setAnswers({});
    setCurrentIndex(0);
  };

  const isCorrect = selectedAnswer ? selectedAnswer === currentItem.correctChoice : false;
  const quizCompleted = answeredCount === totalQuestions;

  return (
    <Card
      className="p-5 space-y-5 border-cyan-500/35 bg-slate-900/90"
      data-testid="spot-the-scam-interactive-quiz"
    >
      {/* Header & Score / Progress Indicator */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div className="flex items-start gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-cyan-500/40 bg-cyan-500/15 text-cyan-300">
            <Target className="h-5 w-5" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-base font-bold text-white">Spot the Scam — Interactive Quiz</h2>
              <Badge tone="info">Fictional Training Scenarios</Badge>
              <Badge tone="neutral">Isolated from Scan History</Badge>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Choose <strong>Legitimate</strong> or <strong>Suspicious</strong> for each message to immediately reveal the answer and warning signs.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div
            className="rounded-xl border border-slate-800 bg-slate-950/80 px-3.5 py-2 text-xs font-mono"
            data-testid="spot-scam-quiz-score"
          >
            <span className="text-slate-400">Score: </span>
            <strong className="text-cyan-300 text-sm">
              {score} / {totalQuestions}
            </strong>
            <span className="text-slate-500 ml-2">
              (Question {currentIndex + 1} of {totalQuestions})
            </span>
          </div>

          <Button
            type="button"
            variant="secondary"
            size="sm"
            data-testid="spot-scam-restart-btn"
            onClick={handleRestart}
          >
            <RotateCcw className="h-3.5 w-3.5" />
            <span>Restart Quiz</span>
          </Button>
        </div>
      </div>

      {/* Progress Bar */}
      <div className="space-y-1">
        <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
          <span>
            PROGRESS: {answeredCount} / {totalQuestions} ANSWERED
          </span>
          <span>{Math.round((answeredCount / totalQuestions) * 100)}%</span>
        </div>
        <div className="h-2 w-full overflow-hidden rounded-full bg-slate-950 border border-slate-800">
          <div
            className="h-full bg-cyan-400 transition-all duration-300"
            style={{ width: `${(answeredCount / totalQuestions) * 100}%` }}
          />
        </div>
      </div>

      {/* Question Card */}
      <div className="grid gap-5 lg:grid-cols-12">
        <div className="lg:col-span-7 space-y-4">
          <div className="rounded-xl border border-slate-800 bg-slate-950/85 p-4 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/80 pb-2.5">
              <div className="flex items-center gap-2">
                <Badge tone="info">{currentItem.category}</Badge>
                <Badge tone="neutral">{currentItem.channel}</Badge>
              </div>
              <span className="text-xs font-mono text-slate-400">Sender: {currentItem.sender}</span>
            </div>

            <p
              className="rounded-lg border border-slate-800/90 bg-slate-900/80 p-4 text-sm leading-relaxed text-slate-100 font-sans"
              data-testid="spot-scam-question-message"
            >
              &ldquo;{currentItem.message}&rdquo;
            </p>

            {/* Immediate Selection Buttons: Legitimate vs Suspicious */}
            <div className="space-y-2 pt-1">
              <span className="text-xs font-mono uppercase tracking-wider text-slate-400 block">
                Is this message Legitimate or Suspicious? (Click to reveal answer immediately)
              </span>
              <div className="grid grid-cols-2 gap-3">
                <button
                  type="button"
                  data-testid="spot-scam-choice-legitimate"
                  disabled={Boolean(selectedAnswer)}
                  onClick={() => handleSelectChoice("Legitimate")}
                  className={cn(
                    "flex items-center justify-center gap-2 rounded-xl border p-3.5 text-sm font-bold transition-all",
                    selectedAnswer === "Legitimate"
                      ? currentItem.correctChoice === "Legitimate"
                        ? "border-emerald-400 bg-emerald-500/20 text-emerald-200"
                        : "border-rose-400 bg-rose-500/20 text-rose-200"
                      : "border-slate-800 bg-slate-900/80 text-slate-200 hover:border-emerald-500/50 hover:bg-emerald-500/10"
                  )}
                >
                  <ShieldCheck className="h-5 w-5 text-emerald-400" />
                  <span>Legitimate</span>
                </button>

                <button
                  type="button"
                  data-testid="spot-scam-choice-suspicious"
                  disabled={Boolean(selectedAnswer)}
                  onClick={() => handleSelectChoice("Suspicious")}
                  className={cn(
                    "flex items-center justify-center gap-2 rounded-xl border p-3.5 text-sm font-bold transition-all",
                    selectedAnswer === "Suspicious"
                      ? currentItem.correctChoice === "Suspicious"
                        ? "border-emerald-400 bg-emerald-500/20 text-emerald-200"
                        : "border-rose-400 bg-rose-500/20 text-rose-200"
                      : "border-slate-800 bg-slate-900/80 text-slate-200 hover:border-rose-500/50 hover:bg-rose-500/10"
                  )}
                >
                  <ShieldAlert className="h-5 w-5 text-rose-400" />
                  <span>Suspicious</span>
                </button>
              </div>
            </div>
          </div>

          {/* Question Navigation Pills */}
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-1.5">
              {SPOT_THE_SCAM_ITEMS.map((item, idx) => {
                const ans = answers[item.id];
                const active = idx === currentIndex;
                return (
                  <button
                    key={item.id}
                    type="button"
                    data-testid={`spot-scam-nav-${idx}`}
                    onClick={() => setCurrentIndex(idx)}
                    className={cn(
                      "h-8 w-8 rounded-lg border text-xs font-mono font-bold transition",
                      active
                        ? "border-cyan-400 bg-cyan-500/20 text-cyan-200"
                        : ans
                          ? ans === item.correctChoice
                            ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-300"
                            : "border-rose-500/40 bg-rose-500/15 text-rose-300"
                          : "border-slate-800 bg-slate-950 text-slate-400 hover:text-white"
                    )}
                  >
                    {idx + 1}
                  </button>
                );
              })}
            </div>

            {selectedAnswer && currentIndex + 1 < totalQuestions && (
              <Button
                type="button"
                size="sm"
                data-testid="spot-scam-next-btn"
                onClick={() => setCurrentIndex((prev) => Math.min(totalQuestions - 1, prev + 1))}
              >
                <span>Next Example ({currentIndex + 2}/{totalQuestions})</span>
                <ArrowRight className="h-3.5 w-3.5" />
              </Button>
            )}
          </div>
        </div>

        {/* Immediate Answer Reveal & Warning Signs Panel */}
        <div className="lg:col-span-5">
          {selectedAnswer ? (
            <div
              className={cn(
                "rounded-xl border p-4 space-y-3.5 h-full",
                isCorrect
                  ? "border-emerald-500/40 bg-emerald-950/20"
                  : "border-rose-500/40 bg-rose-950/20"
              )}
              data-testid="spot-scam-answer-reveal"
            >
              <div className="flex items-center gap-2.5">
                {isCorrect ? (
                  <CheckCircle2 className="h-6 w-6 text-emerald-400 shrink-0" />
                ) : (
                  <XCircle className="h-6 w-6 text-rose-400 shrink-0" />
                )}
                <div>
                  <h3 className="text-sm font-bold text-white">
                    {isCorrect ? "Spot On! Correct Answer" : "Not Quite — Review the Warning Signs"}
                  </h3>
                  <p className="text-xs text-slate-300">
                    Correct Verdict: <strong>{currentItem.correctChoice}</strong> • Your Choice:{" "}
                    <strong>{selectedAnswer}</strong>
                  </p>
                </div>
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-950/80 p-3 text-xs text-slate-200 leading-relaxed">
                <strong className="text-cyan-300 block mb-1">Plain-Language Explanation:</strong>
                {currentItem.simpleExplanation}
              </div>

              <div className="space-y-1.5">
                <span className="text-[11px] font-mono uppercase tracking-wider text-slate-300 block">
                  Key Indicators to Watch For:
                </span>
                <ul className="space-y-1.5">
                  {currentItem.warningSigns.map((sign, i) => (
                    <li
                      key={i}
                      className="flex items-start gap-2 rounded-lg border border-slate-800/80 bg-slate-900/70 px-3 py-2 text-xs text-slate-200"
                    >
                      <AlertTriangle className="h-3.5 w-3.5 text-amber-400 shrink-0 mt-0.5" />
                      <span>{sign}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {quizCompleted && (
                <div className="rounded-lg border border-cyan-500/40 bg-cyan-950/30 p-3 flex items-center justify-between">
                  <div className="flex items-center gap-2 text-xs text-cyan-200 font-semibold">
                    <Trophy className="h-4 w-4 text-amber-400" />
                    <span>
                      Quiz Complete! Final Score: {score} / {totalQuestions}
                    </span>
                  </div>
                  <Button type="button" size="sm" variant="secondary" onClick={handleRestart}>
                    <RotateCcw className="h-3 w-3" />
                    <span>Play Again</span>
                  </Button>
                </div>
              )}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-slate-800 bg-slate-950/50 p-6 text-center h-full min-h-[220px]">
              <GraduationCap className="h-8 w-8 text-cyan-400 mb-2" />
              <h3 className="text-sm font-semibold text-white">Choose Legitimate or Suspicious</h3>
              <p className="text-xs text-slate-400 mt-1 max-w-xs leading-relaxed">
                Select one of the two buttons on the left to immediately reveal the answer and plain-language warning signs.
              </p>
            </div>
          )}
        </div>
      </div>
    </Card>
  );
}
