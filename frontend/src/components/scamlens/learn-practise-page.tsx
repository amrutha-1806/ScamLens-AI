import { useEffect, useMemo, useState } from "react";
import { Link } from "@tanstack/react-router";
import { motion, AnimatePresence } from "motion/react";
import {
  AlertTriangle,
  ArrowRight,
  Award,
  BookOpen,
  CheckCircle2,
  ChevronRight,
  CreditCard,
  Gift,
  GraduationCap,
  HelpCircle,
  KeyRound,
  Link2,
  LockKeyhole,
  MailWarning,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Shuffle,
  Sparkles,
  Target,
  Trophy,
  UserCheck,
  XCircle,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { PageHeader, Panel } from "./primitives";
import { useScamlensPreferences } from "@/lib/scamlens-preferences";
import { cn } from "@/lib/utils";
import { QUIZ_QUESTION_BANK, type QuizScenario } from "./learn-practise-questions";
import { SpotTheScamInteractiveQuiz } from "./spot-the-scam-quiz";

// ============================================================================
// 1. EDUCATIONAL TOPICS ("LEARN" SECTION)
// ============================================================================
interface LearnTopic {
  id: string;
  title: string;
  category: string;
  icon: typeof ShieldAlert;
  summary: string;
  howItWorks: string;
  scamExample: {
    sender: string;
    channel: "SMS" | "Email" | "Chat";
    text: string;
    highlightedPhrases: { phrase: string; reason: string }[];
  };
  legitimateComparison: {
    sender: string;
    channel: "SMS" | "Email" | "Chat";
    text: string;
    whySafe: string;
  };
  warningSigns: string[];
  safetyTips: string[];
}

const LEARN_TOPICS: LearnTopic[] = [
  {
    id: "phishing-messages",
    title: "Phishing Messages",
    category: "Core Threat Vector",
    icon: MailWarning,
    summary:
      "Deceptive SMS ('smishing'), emails, and chat alerts engineered to trick recipients into surrendering credentials or clicking malicious links.",
    howItWorks:
      "Attackers disguise themselves as trusted organizations—banks, cloud providers, or courier companies—and manufacture a crisis (such as an unauthorized login or locked account) so you act before verifying.",
    scamExample: {
      sender: "+91-98100-XX491 (Unverified)",
      channel: "SMS",
      text: "ALERT: Unusual sign-in detected on your NetBanking profile. Verify your identity within 30 minutes at http://netbank-security-check.example/login or your account will be frozen.",
      highlightedPhrases: [
        { phrase: "within 30 minutes", reason: "Artificial countdown designed to cause panic and bypass critical thinking." },
        { phrase: "http://netbank-security-check.example/login", reason: "Unencrypted HTTP link using a look-alike domain instead of the official bank domain." },
        { phrase: "account will be frozen", reason: "Coercive threat of losing access to funds." },
      ],
    },
    legitimateComparison: {
      sender: "VM-HDFCBK (Official Header)",
      channel: "SMS",
      text: "You logged into NetBanking on 30-Oct at 14:20 IST. If this was not you, please call the official helpline on the back of your debit card.",
      whySafe: "Does not include an external login link or demand immediate credential entry; directs you to a known official channel.",
    },
    warningSigns: [
      "Generic greetings ('Dear Customer') paired with urgent security claims",
      "Links pointing to unfamiliar domains or raw IP addresses",
      "Threats of immediate account closure, fine, or suspension",
      "Sender number or email address does not match the official organization",
    ],
    safetyTips: [
      "Never click login links inside unexpected SMS or email alerts.",
      "Open your browser and navigate to the official bookmark or mobile app directly.",
      "Inspect the full domain name carefully before entering any username or password.",
    ],
  },
  {
    id: "fake-prizes-rewards",
    title: "Fake Prizes & Rewards",
    category: "Social Engineering Lure",
    icon: Gift,
    summary:
      "Fraudulent lottery wins, festival gift vouchers, or cashback rewards that require you to click a claim link or pay a 'processing fee'.",
    howItWorks:
      "Scammers exploit excitement and reciprocity by announcing you have won a high-value prize (cash, smartphone, or voucher). To claim it, you are asked to fill out sensitive banking details or pay a fake tax/delivery charge.",
    scamExample: {
      sender: "Promo-Winner-Desk",
      channel: "Chat",
      text: "Congratulations! Your mobile number won ₹50,000 in the Mega Festival Lucky Draw! Claim your instant reward now at http://festival-prize-claim.example/win before midnight!",
      highlightedPhrases: [
        { phrase: "won ₹50,000 in the Mega Festival Lucky Draw", reason: "Unsolicited high-value prize for a contest you never entered." },
        { phrase: "http://festival-prize-claim.example/win", reason: "External unverified claim portal designed to harvest banking or UPI details." },
        { phrase: "before midnight!", reason: "False scarcity pressuring you to click before verifying." },
      ],
    },
    legitimateComparison: {
      sender: "Campus Cultural Committee",
      channel: "Email",
      text: "Hi Aarav, thank you for participating in yesterday's coding hackathon. Certificates and prize distribution will take place in Auditorium B on Friday at 3 PM.",
      whySafe: "References a specific event you actually attended and requires no external link click, fee payment, or private data submission.",
    },
    warningSigns: [
      "Winning a lottery, raffle, or lucky draw you never entered",
      "Requests to pay a 'registration fee', 'GST tax', or 'customs charge' to release a prize",
      "Prompts asking for your UPI PIN or credit card CVV to *receive* money",
      "Exaggerated reward amounts with a 24-hour expiration timer",
    ],
    safetyTips: [
      "Remember that you never need to enter a UPI PIN or OTP to *receive* money.",
      "If a prize requires an upfront fee or tax transfer, it is 100% a scam.",
      "Ignore and delete unsolicited lucky-draw messages.",
    ],
  },
  {
    id: "impersonation-scams",
    title: "Impersonation Scams",
    category: "Identity Deception",
    icon: UserCheck,
    summary:
      "Attackers posing as bank officers, government agencies, tech support, college deans, or company executives to abuse authority.",
    howItWorks:
      "By mimicking an authority figure (police, tax department, IT admin, or CEO), scammers rely on compliance and fear. They often spoof display names or use look-alike email addresses to request urgent wire transfers, gift cards, or verification codes.",
    scamExample: {
      sender: "it-helpdesk-admin@campus-portal-support.example",
      channel: "Email",
      text: "From: Chief IT Security Officer. Mandatory password migration is underway. Reply to this email with your current password and 6-digit SMS code within 1 hour to keep your student portal active.",
      highlightedPhrases: [
        { phrase: "Chief IT Security Officer", reason: "Uses an authoritative title to intimidate the recipient into compliance." },
        { phrase: "Reply to this email with your current password and 6-digit SMS code", reason: "Legitimate IT administrators will NEVER ask for your password or OTP." },
        { phrase: "within 1 hour", reason: "High-pressure deadline to prevent you from checking with classmates or staff." },
      ],
    },
    legitimateComparison: {
      sender: "it-notice@university.edu",
      channel: "Email",
      text: "Scheduled maintenance will occur this Sunday from 2:00 AM to 4:00 AM. Portal services will be briefly offline. No action or password change is required from students.",
      whySafe: "Informational notice from an official domain that explicitly states no credentials or actions are needed.",
    },
    warningSigns: [
      "IT support, bank staff, or officials asking for your password, PIN, or OTP",
      "Display name says 'Official Support' but the actual email address is a free or unrelated domain",
      "Requests from a 'manager' or 'professor' asking you to urgently buy gift vouchers or send funds",
      "Demands for secrecy ('Do not discuss this verification with anyone')",
    ],
    safetyTips: [
      "No legitimate bank, government agency, or IT department will ever ask for your OTP or password.",
      "Verify unusual requests from professors, managers, or family members by calling them on a known phone number.",
      "Check the actual sender address header, not just the display name.",
    ],
  },
  {
    id: "suspicious-links",
    title: "Suspicious Links & URLs",
    category: "Lexical & Structural Signals",
    icon: Link2,
    summary:
      "Manipulated web addresses using typosquatting, raw IP addresses, excessive subdomains, or URL shorteners to hide malicious destinations.",
    howItWorks:
      "Attackers craft URLs that look convincing at a quick glance (e.g., placing a trusted brand name in a subdomain while the actual registered domain belongs to the attacker) or mask the destination behind a link shortener.",
    scamExample: {
      sender: "Delivery-Update",
      channel: "SMS",
      text: "Your package #IND4920 cannot be delivered due to an invalid PIN code. Update address at http://192.168.42.19/india-post-track/confirm-address.php",
      highlightedPhrases: [
        { phrase: "http://", reason: "Uses unencrypted HTTP protocol instead of HTTPS." },
        { phrase: "192.168.42.19", reason: "Uses a raw numeric IP address instead of a verified organization domain name." },
        { phrase: "/india-post-track/confirm-address.php", reason: "Places recognizable brand words in the URL path to deceive hasty readers." },
      ],
    },
    legitimateComparison: {
      sender: "Library-Desk",
      channel: "Email",
      text: "The Python documentation reference for our lab session is available at https://docs.python.org/3/library/urllib.parse.html",
      whySafe: "Uses HTTPS, points to the exact canonical domain (python.org), and contains no deceptive credential-harvesting paths.",
    },
    warningSigns: [
      "Numeric IP addresses (e.g., http://192.0.2.1/login) instead of domain names",
      "Brand names placed in subdomains (e.g., sbi.login.verify-account.example.com)",
      "Presence of the '@' symbol inside a URL (everything before '@' is ignored by browsers)",
      "Shortened links (bit.ly, tinyurl) in unsolicited financial or delivery messages",
    ],
    safetyTips: [
      "Read a URL from right to left up to the first single slash '/' to identify the true registered domain.",
      "Paste suspicious URLs into SCAMLENS AI's Static URL Analyzer to inspect their structure without visiting them.",
      "Avoid clicking shortened URLs from unknown senders.",
    ],
  },
  {
    id: "urgent-personal-info",
    title: "Urgent Requests for Personal Info",
    category: "Credential & KYC Harvesting",
    icon: KeyRound,
    summary:
      "High-pressure messages demanding PAN, Aadhaar, full card numbers, CVV, or One-Time Passwords (OTPs) under the guise of KYC verification.",
    howItWorks:
      "Fraudsters send alarming notices claiming your SIM card will be deactivated, your electricity will be cut off tonight, or your bank KYC has expired—requiring immediate submission of sensitive identity numbers.",
    scamExample: {
      sender: "+91-8800X-XX119",
      channel: "SMS",
      text: "Dear Consumer, your electricity connection will be disconnected tonight at 9:30 PM because your previous bill update failed. Call 98XXXXXX01 or submit KYC & OTP at http://power-bill-kyc.example",
      highlightedPhrases: [
        { phrase: "disconnected tonight at 9:30 PM", reason: "Extreme same-day utility cutoff threat to induce immediate fear." },
        { phrase: "Call 98XXXXXX01", reason: "Directs you to a personal mobile number instead of an official utility helpline." },
        { phrase: "submit KYC & OTP at http://power-bill-kyc.example", reason: "Attempts to steal identity documents and live banking OTPs." },
      ],
    },
    legitimateComparison: {
      sender: "BESCOM-INFO",
      channel: "SMS",
      text: "Your monthly electricity bill for Account ID 449102 is ₹840, due on 15-Nov. You may view your bill via the official utility app or customer portal.",
      whySafe: "Provides standard billing details with a normal due date and never threatens immediate same-night disconnection via a personal mobile number.",
    },
    warningSigns: [
      "Threats that electricity, SIM card, or bank accounts will be blocked 'tonight'",
      "Requests to share Aadhaar, PAN, CVV, or OTP over SMS, WhatsApp, or unverified web forms",
      "Instructions to install screen-sharing apps (AnyDesk, TeamViewer) for 'KYC assistance'",
      "Official notices sent from personal 10-digit mobile numbers",
    ],
    safetyTips: [
      "Never share your OTP, CVV, or UPI PIN with anyone—even if they claim to be from your bank or utility provider.",
      "Never install remote screen-sharing apps at the request of an unknown caller.",
      "Check bill status directly on your utility provider's official app.",
    ],
  },
  {
    id: "payment-advance-fee",
    title: "Payment & Advance-Fee Scams",
    category: "Financial Fraud",
    icon: CreditCard,
    summary:
      "Job offers, internship letters, customs clearance notices, or part-time task scams that demand an upfront security deposit or registration fee.",
    howItWorks:
      "Victims are promised a lucrative remote job, guaranteed internship, or high-return task payout, but must first pay a 'refundable security deposit', 'laptop shipping fee', or 'wallet recharge' before receiving their earnings.",
    scamExample: {
      sender: "HR-Recruiter-Global",
      channel: "Chat",
      text: "You are selected for our Work-From-Home Data Entry Internship (₹35,000/month). Pay ₹1,499 refundable laptop & ID registration fee via UPI to confirm your offer letter today: http://intern-onboarding-pay.example",
      highlightedPhrases: [
        { phrase: "₹35,000/month", reason: "Unusually high pay for an unverified, no-interview data entry role." },
        { phrase: "Pay ₹1,499 refundable laptop & ID registration fee", reason: "Classic advance-fee trap: demanding money upfront to secure employment." },
        { phrase: "http://intern-onboarding-pay.example", reason: "Suspicious payment link designed to collect irreversible transfers." },
      ],
    },
    legitimateComparison: {
      sender: "careers@tech-company.example.org",
      channel: "Email",
      text: "Hi Riya, your technical interview for the Summer Software Internship is scheduled for Tuesday at 11:00 AM. Note: Our company never charges candidates any fee at any stage of recruitment.",
      whySafe: "Follows a standard interview process and explicitly reminds candidates that legitimate employers do not charge recruitment fees.",
    },
    warningSigns: [
      "Job or internship offers that require payment for registration, training, or equipment",
      "Part-time 'like and subscribe' or 'prepaid task' groups promising daily payouts after you deposit money",
      "Fake customs or courier holds demanding an immediate transfer to release a parcel",
      "Requests to pay via irreversible methods before a service or contract is verified",
    ],
    safetyTips: [
      "Legitimate employers and internship programs pay you—they do not ask you to pay them to get hired.",
      "Be skeptical of job offers received via random WhatsApp or Telegram messages without a formal interview.",
      "Verify internship postings through your college placement cell or the company's official career page.",
    ],
  },
];

// ============================================================================
// 2. INTERACTIVE COMPARISON TABLE ("LEGITIMATE VS SCAM")
// ============================================================================
const LEGIT_VS_SCAM_ROWS = [
  {
    dimension: "Sender Identity",
    legitimate: "Verified official domain or registered service header (e.g., institutional .edu / official bank short-code).",
    scam: "Personal 10-digit mobile number, free webmail address, or look-alike domain (e.g., support-bank-kyc.example).",
  },
  {
    dimension: "Tone & Urgency",
    legitimate: "Calm, informative, and provides reasonable timelines for routine actions.",
    scam: "High-pressure panic ('Account blocked in 30 mins', 'Electricity cut tonight', 'Claim before midnight').",
  },
  {
    dimension: "Links & URLs",
    legitimate: "Uses HTTPS on the organization's primary domain, or advises you to open the official app yourself.",
    scam: "Uses plain HTTP, raw IP addresses (192.168.x.x), URL shorteners, or brand names hidden inside subdomains.",
  },
  {
    dimension: "Data Requested",
    legitimate: "Never asks for passwords, PINs, CVV, or One-Time Passwords (OTPs) via message or email.",
    scam: "Directly asks you to reply with or enter OTPs, UPI PINs, passwords, PAN/Aadhaar, or pay an advance fee.",
  },
] as const;

// ============================================================================
// 3. RANDOMIZED QUIZ ENGINE & PERSISTENCE HELPERS
// ============================================================================
const QUESTIONS_PER_ATTEMPT = 8;
const STORAGE_KEY = "scamlens_learn_practise_v1";

interface ScenarioAttempt {
  scenarioId: string;
  selectedClassification: "Legitimate" | "Suspicious";
  selectedTokenIds: string[];
  isClassificationCorrect: boolean;
  suspiciousFoundCount: number;
  totalSuspiciousTokens: number;
}

interface StoredQuizState {
  reviewedTopics?: string[];
  /** Ordered list of 8 scenario IDs selected for the active quiz attempt */
  activeQuestionIds?: string[];
  /** Current question index (0..7) within activeQuestionIds */
  currentIndex?: number;
  /** User's submitted answers for the active attempt */
  attempts?: Record<string, ScenarioAttempt>;
  /** Whether the active 8-question attempt has been finished */
  quizCompleted?: boolean;
  /** IDs of questions seen across recent attempts so new attempts prioritize unseen questions */
  seenHistoryIds?: string[];
  /** IDs from the immediately preceding attempt so we never repeat the exact same set back-to-back */
  lastAttemptIds?: string[];
  /** Number of quiz attempts started */
  attemptNumber?: number;
}

const QUESTION_MAP = new Map<string, QuizScenario>(
  QUIZ_QUESTION_BANK.map((q) => [q.id, q])
);

/**
 * Unbiased Fisher-Yates shuffle returning a new array.
 */
function shuffleArray<T>(items: readonly T[]): T[] {
  const copy = [...items];
  for (let i = copy.length - 1; i > 0; i -= 1) {
    const j = Math.floor(Math.random() * (i + 1));
    const temp = copy[i]!;
    copy[i] = copy[j]!;
    copy[j] = temp;
  }
  return copy;
}

/**
 * Selects `count` (8) unique, randomized question IDs from the 44-question bank.
 * - Prioritizes questions not yet seen in `seenHistoryIds` and not in `lastAttemptIds`.
 * - Ensures a balanced mix of Suspicious/Scam and Legitimate scenarios as well as varied difficulties.
 * - Automatically cycles the question pool once the user has seen almost all 44 scenarios.
 */
export function selectRandomizedAttemptQuestions(
  seenHistoryIds: string[] = [],
  lastAttemptIds: string[] = [],
  count: number = QUESTIONS_PER_ATTEMPT
): { selectedIds: string[]; updatedSeenHistoryIds: string[] } {
  const allIds = QUIZ_QUESTION_BANK.map((q) => q.id);
  const lastSet = new Set(lastAttemptIds);
  let seenSet = new Set(seenHistoryIds.filter((id) => QUESTION_MAP.has(id)));

  // Candidates not seen in the current cycle and not in the immediately preceding attempt
  let unseenPool = QUIZ_QUESTION_BANK.filter(
    (q) => !seenSet.has(q.id) && !lastSet.has(q.id)
  );

  // If fewer than `count` unseen questions remain, reset the cycle while still excluding `lastAttemptIds`
  if (unseenPool.length < count) {
    seenSet = new Set<string>();
    unseenPool = QUIZ_QUESTION_BANK.filter((q) => !lastSet.has(q.id));
  }

  // Separate unseen pool into Suspicious vs Legitimate so each 8-question attempt has a realistic mix
  // (e.g., 5 Suspicious + 3 Legitimate, shuffled in random order)
  const shuffledPool = shuffleArray(unseenPool);
  const suspiciousCandidates = shuffledPool.filter((q) => q.correctClassification === "Suspicious");
  const legitimateCandidates = shuffledPool.filter((q) => q.correctClassification === "Legitimate");

  const chosen: QuizScenario[] = [];
  const chosenIds = new Set<string>();

  const targetSuspicious = Math.min(5, suspiciousCandidates.length);
  const targetLegitimate = Math.min(count - targetSuspicious, legitimateCandidates.length);

  for (let i = 0; i < targetSuspicious; i += 1) {
    const item = suspiciousCandidates[i]!;
    chosen.push(item);
    chosenIds.add(item.id);
  }
  for (let i = 0; i < targetLegitimate; i += 1) {
    const item = legitimateCandidates[i]!;
    chosen.push(item);
    chosenIds.add(item.id);
  }

  // Top up from remaining unseenPool or full bank if needed
  const fallbackPool = shuffleArray(QUIZ_QUESTION_BANK.filter((q) => !chosenIds.has(q.id) && !lastSet.has(q.id)));
  for (const item of fallbackPool) {
    if (chosen.length >= count) break;
    chosen.push(item);
    chosenIds.add(item.id);
  }

  // Final fallback if bank was smaller than count
  if (chosen.length < count) {
    for (const id of shuffleArray(allIds)) {
      if (chosen.length >= count) break;
      if (!chosenIds.has(id)) {
        chosen.push(QUESTION_MAP.get(id)!);
        chosenIds.add(id);
      }
    }
  }

  // Shuffle the final 8 chosen scenarios so the order and first question are randomized every time
  let finalOrderedIds = shuffleArray(chosen).map((q) => q.id);

  // Ensure the very first question is never identical to the first question of the previous attempt
  if (
    finalOrderedIds.length > 1 &&
    lastAttemptIds.length > 0 &&
    finalOrderedIds[0] === lastAttemptIds[0]
  ) {
    const first = finalOrderedIds[0]!;
    finalOrderedIds[0] = finalOrderedIds[1]!;
    finalOrderedIds[1] = first;
  }

  const updatedSeen = Array.from(new Set([...Array.from(seenSet), ...finalOrderedIds]));
  return {
    selectedIds: finalOrderedIds,
    updatedSeenHistoryIds: updatedSeen,
  };
}

export function LearnPractisePage() {
  const { shouldReduceMotion } = useScamlensPreferences();
  const [activeTab, setActiveTab] = useState<"learn" | "practise">("learn");
  const [selectedTopicId, setSelectedTopicId] = useState<string>(LEARN_TOPICS[0]!.id);
  const [reviewedTopics, setReviewedTopics] = useState<string[]>([LEARN_TOPICS[0]!.id]);

  // Randomized Quiz Attempt State
  const [activeQuestionIds, setActiveQuestionIds] = useState<string[]>(() => {
    return selectRandomizedAttemptQuestions([], [], QUESTIONS_PER_ATTEMPT).selectedIds;
  });
  const [seenHistoryIds, setSeenHistoryIds] = useState<string[]>([]);
  const [lastAttemptIds, setLastAttemptIds] = useState<string[]>([]);
  const [attemptNumber, setAttemptNumber] = useState<number>(1);

  const [currentIndex, setCurrentIndex] = useState<number>(0);
  const [selectedTokens, setSelectedTokens] = useState<string[]>([]);
  const [selectedVerdict, setSelectedVerdict] = useState<"Legitimate" | "Suspicious" | null>(null);
  const [submitted, setSubmitted] = useState<boolean>(false);
  const [attempts, setAttempts] = useState<Record<string, ScenarioAttempt>>({});
  const [quizCompleted, setQuizCompleted] = useState<boolean>(false);
  const [validationMsg, setValidationMsg] = useState<string>("");
  const [hydrated, setHydrated] = useState<boolean>(false);

  // Hydrate state from localStorage (`scamlens_learn_practise_v1`)
  useEffect(() => {
    try {
      const raw = window.localStorage.getItem(STORAGE_KEY);
      if (!raw) {
        const initial = selectRandomizedAttemptQuestions([], [], QUESTIONS_PER_ATTEMPT);
        setActiveQuestionIds(initial.selectedIds);
        setSeenHistoryIds(initial.updatedSeenHistoryIds);
        setLastAttemptIds(initial.selectedIds);
        setHydrated(true);
        return;
      }

      const parsed = JSON.parse(raw) as StoredQuizState;

      if (Array.isArray(parsed.reviewedTopics) && parsed.reviewedTopics.length > 0) {
        setReviewedTopics(parsed.reviewedTopics);
      }

      const validStoredIds = Array.isArray(parsed.activeQuestionIds)
        ? parsed.activeQuestionIds.filter((id) => QUESTION_MAP.has(id))
        : [];
      const storedSeen = Array.isArray(parsed.seenHistoryIds)
        ? parsed.seenHistoryIds.filter((id) => QUESTION_MAP.has(id))
        : [];
      const storedLast = Array.isArray(parsed.lastAttemptIds)
        ? parsed.lastAttemptIds.filter((id) => QUESTION_MAP.has(id))
        : [];

      // If there is a valid in-progress attempt with 8 valid IDs and it was NOT already completed,
      // restore that in-progress attempt so page refresh doesn't lose mid-quiz answers.
      // Otherwise (legacy data without activeQuestionIds, or a previously completed attempt),
      // generate a fresh randomized 8-question attempt!
      if (validStoredIds.length === QUESTIONS_PER_ATTEMPT && !parsed.quizCompleted) {
        const restoredAttempts =
          parsed.attempts && typeof parsed.attempts === "object" ? parsed.attempts : {};
        const restoredIdx =
          typeof parsed.currentIndex === "number" &&
          parsed.currentIndex >= 0 &&
          parsed.currentIndex < validStoredIds.length
            ? parsed.currentIndex
            : 0;

        setActiveQuestionIds(validStoredIds);
        setSeenHistoryIds(storedSeen.length ? storedSeen : validStoredIds);
        setLastAttemptIds(storedLast.length ? storedLast : validStoredIds);
        setAttemptNumber(parsed.attemptNumber ?? 1);
        setAttempts(restoredAttempts);
        setCurrentIndex(restoredIdx);
        setQuizCompleted(false);

        const activeScenarioId = validStoredIds[restoredIdx];
        const existingAttempt = activeScenarioId ? restoredAttempts[activeScenarioId] : undefined;
        if (existingAttempt) {
          setSelectedVerdict(existingAttempt.selectedClassification);
          setSelectedTokens(existingAttempt.selectedTokenIds);
          setSubmitted(true);
        }
      } else {
        // Previous attempt was completed or state was from old fixed-8 format -> generate a fresh randomized set
        const prevIds = validStoredIds.length
          ? validStoredIds
          : Object.keys(parsed.attempts ?? {});
        const nextSelection = selectRandomizedAttemptQuestions(
          storedSeen.length ? storedSeen : prevIds,
          prevIds,
          QUESTIONS_PER_ATTEMPT
        );
        setActiveQuestionIds(nextSelection.selectedIds);
        setSeenHistoryIds(nextSelection.updatedSeenHistoryIds);
        setLastAttemptIds(nextSelection.selectedIds);
        setAttemptNumber((parsed.attemptNumber ?? 1) + (parsed.quizCompleted ? 1 : 0));
        setAttempts({});
        setCurrentIndex(0);
        setSelectedTokens([]);
        setSelectedVerdict(null);
        setSubmitted(false);
        setQuizCompleted(false);
      }
    } catch {
      const fallback = selectRandomizedAttemptQuestions([], [], QUESTIONS_PER_ATTEMPT);
      setActiveQuestionIds(fallback.selectedIds);
      setSeenHistoryIds(fallback.updatedSeenHistoryIds);
      setLastAttemptIds(fallback.selectedIds);
    } finally {
      setHydrated(true);
    }
  }, []);

  // Persist local educational state whenever it changes after hydration
  useEffect(() => {
    if (!hydrated) return;
    try {
      const stateToSave: StoredQuizState = {
        reviewedTopics,
        activeQuestionIds,
        currentIndex,
        attempts,
        quizCompleted,
        seenHistoryIds,
        lastAttemptIds,
        attemptNumber,
      };
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(stateToSave));
    } catch {
      // Ignore storage write errors
    }
  }, [
    hydrated,
    reviewedTopics,
    activeQuestionIds,
    currentIndex,
    attempts,
    quizCompleted,
    seenHistoryIds,
    lastAttemptIds,
    attemptNumber,
  ]);

  const activeTopic = useMemo(
    () => LEARN_TOPICS.find((t) => t.id === selectedTopicId) ?? LEARN_TOPICS[0]!,
    [selectedTopicId]
  );

  function selectTopic(topicId: string) {
    setSelectedTopicId(topicId);
    setReviewedTopics((prev) => (prev.includes(topicId) ? prev : [...prev, topicId]));
  }

  // Resolve the 8 scenarios for the current attempt from activeQuestionIds
  const activeScenarios = useMemo<QuizScenario[]>(() => {
    const mapped = activeQuestionIds
      .map((id) => QUESTION_MAP.get(id))
      .filter((item): item is QuizScenario => Boolean(item));
    return mapped.length > 0 ? mapped : QUIZ_QUESTION_BANK.slice(0, QUESTIONS_PER_ATTEMPT);
  }, [activeQuestionIds]);

  const totalScenarios = activeScenarios.length;
  const safeIndex = Math.min(currentIndex, Math.max(0, totalScenarios - 1));
  const currentScenario = activeScenarios[safeIndex] ?? activeScenarios[0]!;

  // Count only attempts belonging to the current 8 active questions
  const completedCount = useMemo(
    () => activeScenarios.filter((sc) => Boolean(attempts[sc.id])).length,
    [activeScenarios, attempts]
  );
  const correctVerdictCount = useMemo(
    () => activeScenarios.filter((sc) => attempts[sc.id]?.isClassificationCorrect).length,
    [activeScenarios, attempts]
  );

  function toggleToken(tokenId: string) {
    if (submitted) return;
    setSelectedTokens((prev) =>
      prev.includes(tokenId) ? prev.filter((id) => id !== tokenId) : [...prev, tokenId]
    );
  }

  function handleSubmitAnswer() {
    if (!selectedVerdict) {
      setValidationMsg("Please classify the message as either Legitimate or Suspicious before submitting.");
      return;
    }
    setValidationMsg("");
    const suspiciousSegments = currentScenario.segments.filter((s) => s.isSuspicious);
    const foundCount = suspiciousSegments.filter((s) => selectedTokens.includes(s.id)).length;
    const isCorrect = selectedVerdict === currentScenario.correctClassification;

    const attempt: ScenarioAttempt = {
      scenarioId: currentScenario.id,
      selectedClassification: selectedVerdict,
      selectedTokenIds: selectedTokens,
      isClassificationCorrect: isCorrect,
      suspiciousFoundCount: foundCount,
      totalSuspiciousTokens: suspiciousSegments.length,
    };

    setAttempts((prev) => ({ ...prev, [currentScenario.id]: attempt }));
    setSubmitted(true);
  }

  function loadScenarioState(index: number, nextAttempts = attempts, scenarioList = activeScenarios) {
    const scenario = scenarioList[index];
    if (!scenario) return;
    const existing = nextAttempts[scenario.id];
    setCurrentIndex(index);
    setValidationMsg("");
    if (existing) {
      setSelectedVerdict(existing.selectedClassification);
      setSelectedTokens(existing.selectedTokenIds);
      setSubmitted(true);
    } else {
      setSelectedVerdict(null);
      setSelectedTokens([]);
      setSubmitted(false);
    }
  }

  function handleNextScenario() {
    if (safeIndex + 1 < totalScenarios) {
      loadScenarioState(safeIndex + 1);
    } else {
      setQuizCompleted(true);
    }
  }

  /**
   * Starts a brand-new randomized 8-question attempt from the 44-question bank,
   * avoiding the questions from the just-finished/current attempt whenever possible.
   */
  function handleRestartQuiz() {
    const nextSelection = selectRandomizedAttemptQuestions(
      seenHistoryIds,
      activeQuestionIds,
      QUESTIONS_PER_ATTEMPT
    );
    setActiveQuestionIds(nextSelection.selectedIds);
    setSeenHistoryIds(nextSelection.updatedSeenHistoryIds);
    setLastAttemptIds(nextSelection.selectedIds);
    setAttemptNumber((n) => n + 1);
    setAttempts({});
    setCurrentIndex(0);
    setSelectedTokens([]);
    setSelectedVerdict(null);
    setSubmitted(false);
    setQuizCompleted(false);
    setValidationMsg("");
  }

  const currentAttempt = attempts[currentScenario.id];
  const suspiciousInCurrent = currentScenario.segments.filter((s) => s.isSuspicious);

  return (
    <div className="space-y-7">
      <PageHeader
        eyebrow="Interactive Cybersecurity Academy"
        title="Learn & Practise"
        description="Master the art of spotting phishing messages, deceptive URLs, impersonation lures, and advance-fee fraud through interactive visual guides and randomized hands-on training scenarios."
        actions={
          <div className="flex w-full flex-wrap items-center gap-2 sm:w-auto">
            <div className="grid w-full grid-cols-1 gap-1 rounded-lg border border-border bg-card p-1 sm:flex sm:w-auto sm:items-center">
              <button
                type="button"
                onClick={() => setActiveTab("learn")}
                className={cn(
                  "relative flex min-h-10 items-center justify-center gap-2 rounded-md px-3.5 py-1.5 text-xs font-semibold transition-colors sm:min-h-9",
                  activeTab === "learn"
                    ? "text-primary-foreground"
                    : "text-muted-foreground hover:text-foreground"
                )}
              >
                {activeTab === "learn" && (
                  <motion.span
                    layoutId="learn-practise-main-tab"
                    transition={
                      shouldReduceMotion
                        ? { duration: 0 }
                        : { type: "spring", stiffness: 380, damping: 30 }
                    }
                    className="pointer-events-none absolute inset-0 rounded-md bg-primary shadow-sm"
                  />
                )}
                <BookOpen className="relative z-10 size-3.5 shrink-0" />
                <span className="relative z-10">
                  1. Learn Threat Patterns ({reviewedTopics.length}/{LEARN_TOPICS.length})
                </span>
              </button>
              <button
                type="button"
                onClick={() => setActiveTab("practise")}
                className={cn(
                  "relative flex min-h-10 items-center justify-center gap-2 rounded-md px-3.5 py-1.5 text-xs font-semibold transition-colors sm:min-h-9",
                  activeTab === "practise"
                    ? "text-primary-foreground"
                    : "text-muted-foreground hover:text-foreground"
                )}
              >
                {activeTab === "practise" && (
                  <motion.span
                    layoutId="learn-practise-main-tab"
                    transition={
                      shouldReduceMotion
                        ? { duration: 0 }
                        : { type: "spring", stiffness: 380, damping: 30 }
                    }
                    className="pointer-events-none absolute inset-0 rounded-md bg-primary shadow-sm"
                  />
                )}
                <Target className="relative z-10 size-3.5 shrink-0" />
                <span className="relative z-10">
                  2. Practise Quiz ({correctVerdictCount}/{totalScenarios})
                </span>
              </button>
            </div>
          </div>
        }
      />

      {/* Top Progress & Separation Notice Banner */}
      <motion.section
        initial={shouldReduceMotion ? false : { opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: shouldReduceMotion ? 0 : 0.25 }}
        className="relative overflow-hidden rounded-xl border border-primary/25 bg-gradient-to-r from-sky-50/95 via-cyan-50/60 to-indigo-50/75 p-4 shadow-panel sm:p-5 dark:border-cyan-500/25 dark:from-[#07101F] dark:via-[#0A1628] dark:to-[#07101F]"
      >
        <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(to_right,rgba(14,165,233,0.06)_1px,transparent_1px),linear-gradient(to_bottom,rgba(14,165,233,0.06)_1px,transparent_1px)] bg-[size:24px_24px] dark:bg-[linear-gradient(to_right,rgba(56,189,248,0.04)_1px,transparent_1px),linear-gradient(to_bottom,rgba(56,189,248,0.04)_1px,transparent_1px)]" />
        <div className="relative z-10 grid gap-4 lg:grid-cols-[1.35fr_1fr] lg:items-center">
          <div className="space-y-2">
            <div className="inline-flex flex-wrap items-center gap-2 rounded-full border border-primary/30 bg-primary/10 px-3 py-0.5 text-[11px] font-semibold uppercase tracking-wider text-primary dark:border-cyan-500/30 dark:bg-cyan-500/10 dark:text-cyan-300">
              <GraduationCap className="size-3.5 text-primary dark:text-cyan-400" />
              <span>Safe Training Environment • {QUIZ_QUESTION_BANK.length}-Scenario Randomized Bank</span>
            </div>
            <h2 className="text-base font-bold text-foreground sm:text-lg dark:text-slate-100">
              Build Human Intuition Alongside Machine Learning Defense
            </h2>
            <p className="text-xs leading-relaxed text-muted-foreground dark:text-slate-300">
              Every quiz attempt draws <strong className="text-foreground dark:text-white">{QUESTIONS_PER_ATTEMPT} randomized scenarios</strong> from our pool of{" "}
              <strong className="text-foreground dark:text-white">{QUIZ_QUESTION_BANK.length} fictional messages</strong> using safe <code>.example</code> domains. Quiz scores are calculated from your actual answers and kept strictly separate from live ML scan history and analytics.
            </p>
          </div>

          {/* Live Progress Meters */}
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <motion.div
              whileHover={shouldReduceMotion ? { y: 0 } : { y: -2 }}
              className="rounded-lg border border-border bg-card/90 p-3.5 transition-colors hover:border-primary/40 dark:border-slate-800 dark:bg-slate-950/85 dark:hover:border-cyan-500/35"
            >
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground dark:text-slate-400">Guides Explored</span>
                <BookOpen className="size-4 text-primary dark:text-cyan-400" />
              </div>
              <p className="mt-1.5 font-mono text-xl font-bold text-foreground dark:text-slate-100">
                {reviewedTopics.length} / {LEARN_TOPICS.length}
              </p>
              <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-secondary dark:bg-slate-800">
                <motion.div
                  initial={shouldReduceMotion ? false : { width: 0 }}
                  animate={{ width: `${(reviewedTopics.length / LEARN_TOPICS.length) * 100}%` }}
                  transition={{ duration: shouldReduceMotion ? 0 : 0.45, ease: "easeOut" }}
                  className="h-full rounded-full bg-primary dark:bg-cyan-400"
                />
              </div>
            </motion.div>

            <motion.div
              whileHover={shouldReduceMotion ? { y: 0 } : { y: -2 }}
              className="rounded-lg border border-border bg-card/90 p-3.5 transition-colors hover:border-primary/40 dark:border-slate-800 dark:bg-slate-950/85 dark:hover:border-cyan-500/35"
            >
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground dark:text-slate-400">Attempt #{attemptNumber} Score</span>
                <Trophy className="size-4 text-warning dark:text-amber-400" />
              </div>
              <p className="mt-1.5 font-mono text-xl font-bold text-foreground dark:text-slate-100">
                {correctVerdictCount} / {totalScenarios}
              </p>
              <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-secondary dark:bg-slate-800">
                <motion.div
                  initial={shouldReduceMotion ? false : { width: 0 }}
                  animate={{ width: `${(completedCount / totalScenarios) * 100}%` }}
                  transition={{ duration: shouldReduceMotion ? 0 : 0.45, ease: "easeOut" }}
                  className="h-full rounded-full bg-safe"
                />
              </div>
            </motion.div>
          </div>
        </div>
      </motion.section>

      {/* Feature 8: Spot the Scam Interactive Quiz (Instant Verdict & Warning Signs) */}
      <SpotTheScamInteractiveQuiz />

      <AnimatePresence mode="wait">
        {/* ===================================================================== */}
        {/* TAB 1: LEARN SECTION                                                  */}
        {/* ===================================================================== */}
        {activeTab === "learn" ? (
          <motion.div
            key="learn-tab-view"
            initial={shouldReduceMotion ? false : { opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={shouldReduceMotion ? { opacity: 1 } : { opacity: 0, y: -6 }}
            transition={{ duration: shouldReduceMotion ? 0 : 0.22 }}
            className="space-y-7"
          >
            {/* 6 Topic Cards Selector Grid */}
            <div className="grid gap-3.5 sm:grid-cols-2 lg:grid-cols-3">
              {LEARN_TOPICS.map((topic, idx) => {
                const Icon = topic.icon;
                const isSelected = topic.id === activeTopic.id;
                const isReviewed = reviewedTopics.includes(topic.id);
                return (
                  <motion.button
                    key={topic.id}
                    type="button"
                    initial={shouldReduceMotion ? false : { opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    whileHover={shouldReduceMotion ? { y: 0 } : { y: -2.5 }}
                    whileTap={shouldReduceMotion ? { scale: 1 } : { scale: 0.99 }}
                    transition={{
                      duration: shouldReduceMotion ? 0 : 0.2,
                      delay: shouldReduceMotion ? 0 : idx * 0.035,
                    }}
                    onClick={() => selectTopic(topic.id)}
                    className={cn(
                      "group relative flex flex-col justify-between rounded-xl border p-4 text-left transition-colors",
                      isSelected
                        ? "border-primary bg-primary/10 shadow-[0_0_25px_rgba(34,211,238,0.12)]"
                        : "border-border bg-card hover:border-primary/40 hover:bg-secondary/40"
                    )}
                  >
                    <div>
                      <div className="flex items-center justify-between gap-2">
                        <span
                          className={cn(
                            "grid size-9 place-items-center rounded-lg border transition-colors",
                            isSelected
                              ? "border-primary/40 bg-primary text-primary-foreground"
                              : "border-border bg-secondary text-primary"
                          )}
                        >
                          <Icon className="size-4" />
                        </span>
                        <span
                          className={cn(
                            "rounded-full border px-2 py-0.5 text-[10px] font-semibold",
                            isReviewed
                              ? "border-safe/35 bg-safe/10 text-safe"
                              : "border-border bg-secondary text-muted-foreground"
                          )}
                        >
                          {isReviewed ? "✓ Explored" : topic.category}
                        </span>
                      </div>
                      <h3 className="mt-3 text-sm font-bold text-foreground group-hover:text-primary">
                        {topic.title}
                      </h3>
                      <p className="mt-1 line-clamp-2 text-xs leading-relaxed text-muted-foreground">
                        {topic.summary}
                      </p>
                    </div>
                    <div className="mt-3 flex items-center gap-1 text-[11px] font-semibold text-primary">
                      <span>Inspect anatomical breakdown</span>
                      <ChevronRight className="size-3.5 transition-transform group-hover:translate-x-0.5" />
                    </div>
                  </motion.button>
                );
              })}
            </div>

            {/* Active Topic Interactive Deep-Dive */}
            <AnimatePresence mode="wait">
              <motion.div
                key={activeTopic.id}
                initial={shouldReduceMotion ? false : { opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={shouldReduceMotion ? { opacity: 1 } : { opacity: 0, y: -8 }}
                transition={{ duration: shouldReduceMotion ? 0 : 0.22 }}
                className="grid gap-6 xl:grid-cols-[1.2fr_.8fr]"
              >
              {/* Left Column: Fictional Scam Dissection vs Safe Equivalent */}
              <Panel
                title={`${activeTopic.title} — Threat Anatomy & Fictional Example`}
                description={activeTopic.howItWorks}
              >
                <div className="space-y-5">
                  {/* Fictional Scam Example Box */}
                  <div className="rounded-xl border border-danger/40 bg-danger/5 p-4">
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-danger/20 pb-2.5">
                      <div className="flex items-center gap-2">
                        <ShieldAlert className="size-4 text-danger" />
                        <span className="text-xs font-bold uppercase tracking-wider text-danger">
                          Fictional Scam Example ({activeTopic.scamExample.channel})
                        </span>
                      </div>
                      <span className="font-mono text-[11px] text-muted-foreground">
                        Sender: {activeTopic.scamExample.sender}
                      </span>
                    </div>

                    <p className="mt-3 rounded-lg border border-border bg-card p-3.5 font-mono text-xs leading-6 text-foreground">
                      &ldquo;{activeTopic.scamExample.text}&rdquo;
                    </p>

                    <div className="mt-3.5 space-y-2">
                      <p className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                        Red-Flag Indicators Inside This Message:
                      </p>
                      <div className="grid gap-2 sm:grid-cols-3">
                        {activeTopic.scamExample.highlightedPhrases.map((hp) => (
                          <div
                            key={hp.phrase}
                            className="rounded-lg border border-danger/30 bg-card/90 p-2.5 text-xs"
                          >
                            <span className="inline-block rounded bg-danger/15 px-1.5 py-0.5 font-mono text-[11px] font-semibold text-danger">
                              &ldquo;{hp.phrase}&rdquo;
                            </span>
                            <p className="mt-1.5 text-[11px] leading-snug text-muted-foreground">
                              {hp.reason}
                            </p>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Legitimate Message Comparison Box */}
                  <div className="rounded-xl border border-safe/40 bg-safe/5 p-4">
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-safe/20 pb-2.5">
                      <div className="flex items-center gap-2">
                        <ShieldCheck className="size-4 text-safe" />
                        <span className="text-xs font-bold uppercase tracking-wider text-safe">
                          Legitimate Counterpart ({activeTopic.legitimateComparison.channel})
                        </span>
                      </div>
                      <span className="font-mono text-[11px] text-muted-foreground">
                        Sender: {activeTopic.legitimateComparison.sender}
                      </span>
                    </div>

                    <p className="mt-3 rounded-lg border border-border bg-card p-3.5 font-mono text-xs leading-6 text-foreground">
                      &ldquo;{activeTopic.legitimateComparison.text}&rdquo;
                    </p>

                    <p className="mt-2.5 flex items-start gap-2 text-xs text-muted-foreground">
                      <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-safe" />
                      <span>
                        <strong className="text-foreground">Why this is safe:</strong>{" "}
                        {activeTopic.legitimateComparison.whySafe}
                      </span>
                    </p>
                  </div>
                </div>
              </Panel>

              {/* Right Column: Warning Signs & Actionable Safety Checklist */}
              <div className="space-y-6">
                <Panel
                  title="Visual Warning Signs"
                  description="Key indicators that should immediately raise suspicion."
                >
                  <ul className="space-y-2.5 text-xs leading-5 text-muted-foreground">
                    {activeTopic.warningSigns.map((sign) => (
                      <li
                        key={sign}
                        className="flex items-start gap-2.5 rounded-lg border border-border bg-secondary/30 p-3"
                      >
                        <AlertTriangle className="mt-0.5 size-4 shrink-0 text-warning" />
                        <span className="text-foreground">{sign}</span>
                      </li>
                    ))}
                  </ul>
                </Panel>

                <Panel
                  title="Defensive Safety Rules"
                  description="Practical habits to protect your accounts and identity."
                >
                  <ul className="space-y-2.5 text-xs leading-5 text-muted-foreground">
                    {activeTopic.safetyTips.map((tip) => (
                      <li
                        key={tip}
                        className="flex items-start gap-2.5 rounded-lg border border-primary/25 bg-primary/5 p-3"
                      >
                        <LockKeyhole className="mt-0.5 size-4 shrink-0 text-primary" />
                        <span className="text-foreground">{tip}</span>
                      </li>
                    ))}
                  </ul>

                  <div className="mt-4 flex items-center justify-between gap-3 border-t border-border pt-4">
                    <span className="text-xs text-muted-foreground">
                      Ready to test your detection skills?
                    </span>
                    <Button size="sm" onClick={() => setActiveTab("practise")}>
                      <Target className="size-3.5" /> Start Practise Quiz
                    </Button>
                  </div>
                </Panel>
              </div>
            </motion.div>
          </AnimatePresence>

          {/* Side-by-Side Comparison Matrix: Legitimate Messages vs Scam Messages */}
          <Panel
            title="Quick Reference Matrix: Legitimate Messages vs. Scam Messages"
            description="How to distinguish authentic organizational communications from social engineering attacks across four key dimensions."
          >
            {/* Mobile Card View (< md) */}
            <div className="space-y-3 md:hidden">
              {LEGIT_VS_SCAM_ROWS.map((row) => (
                <div key={`mob-mat-${row.dimension}`} className="rounded-lg border border-border bg-secondary/20 p-3.5 space-y-2 text-xs">
                  <p className="font-bold text-foreground">{row.dimension}</p>
                  <div className="rounded border border-safe/30 bg-safe/5 p-2.5">
                    <span className="font-semibold text-safe">✓ Legitimate: </span>
                    <span className="text-muted-foreground">{row.legitimate}</span>
                  </div>
                  <div className="rounded border border-danger/30 bg-danger/5 p-2.5">
                    <span className="font-semibold text-danger">⚠ Scam / Phishing: </span>
                    <span className="text-muted-foreground">{row.scam}</span>
                  </div>
                </div>
              ))}
            </div>

            {/* Desktop Table (md+) */}
            <div className="hidden overflow-x-auto md:block">
              <table className="w-full border-collapse text-left text-xs">
                <thead>
                  <tr className="border-b border-border bg-secondary/40">
                    <th className="p-3.5 font-semibold text-foreground">Inspection Dimension</th>
                    <th className="p-3.5 font-semibold text-safe">✓ Legitimate Message</th>
                    <th className="p-3.5 font-semibold text-danger">⚠ Scam / Phishing Message</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {LEGIT_VS_SCAM_ROWS.map((row) => (
                    <tr key={row.dimension} className="transition-colors hover:bg-secondary/20">
                      <td className="p-3.5 font-semibold text-foreground">{row.dimension}</td>
                      <td className="p-3.5 text-muted-foreground">{row.legitimate}</td>
                      <td className="p-3.5 text-muted-foreground">{row.scam}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
          </motion.div>
        ) : (
          /* ===================================================================== */
          /* TAB 2: PRACTISE SECTION (INTERACTIVE RANDOMIZED SCENARIO QUIZ)        */
          /* ===================================================================== */
          <motion.div
            key="practise-tab-view"
            initial={shouldReduceMotion ? false : { opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={shouldReduceMotion ? { opacity: 1 } : { opacity: 0, y: -6 }}
            transition={{ duration: shouldReduceMotion ? 0 : 0.22 }}
            className="space-y-6"
          >
            {quizCompleted ? (
              /* Completion Screen */
              <motion.div
                initial={shouldReduceMotion ? false : { opacity: 0, scale: 0.97, y: 10 }}
                animate={{ opacity: 1, scale: 1, y: 0 }}
                transition={{ duration: shouldReduceMotion ? 0 : 0.28, ease: "easeOut" }}
                className="mx-auto max-w-3xl rounded-2xl border border-primary/35 bg-card p-5 text-center shadow-panel sm:p-8"
              >
                <motion.div
                  initial={shouldReduceMotion ? false : { scale: 0.8, rotate: -6 }}
                  animate={{ scale: 1, rotate: 0 }}
                  transition={
                    shouldReduceMotion
                      ? { duration: 0 }
                      : { type: "spring", stiffness: 280, damping: 18 }
                  }
                  className="mx-auto grid size-16 place-items-center rounded-2xl border border-primary/40 bg-primary/15 text-primary shadow-[0_0_28px_rgba(56,189,248,0.25)]"
                >
                  <Award className="size-9" />
                </motion.div>

                <p className="mt-4 text-xs font-semibold uppercase tracking-widest text-primary">
                  Attempt #{attemptNumber} Complete • {seenHistoryIds.length} of {QUIZ_QUESTION_BANK.length} Bank Scenarios Explored
                </p>
                <h2 className="mt-1 text-xl font-bold text-foreground sm:text-2xl">
                  Your Threat Detection Score: {correctVerdictCount} / {totalScenarios} (
                  {Math.round((correctVerdictCount / totalScenarios) * 100)}%)
                </h2>
                <p className="mx-auto mt-2 max-w-xl text-sm text-muted-foreground">
                  {correctVerdictCount === totalScenarios
                    ? "Outstanding work! You accurately classified every scenario in this set and spotted the key social-engineering triggers."
                    : correctVerdictCount >= 6
                      ? "Strong performance! You caught most phishing and impersonation traps. Review any missed scenarios below or launch a new randomized set."
                      : "Good effort! Review the warning signs in the Learn tab and try a new randomized set of scenarios to sharpen your instincts."}
                </p>

                {/* Scenario-by-Scenario Breakdown for the Active 8-Question Attempt */}
                <div className="mt-6 grid gap-2.5 text-left sm:grid-cols-2">
                  {activeScenarios.map((sc, idx) => {
                    const att = attempts[sc.id];
                    const ok = att?.isClassificationCorrect;
                    return (
                      <motion.button
                        key={sc.id}
                        type="button"
                        initial={shouldReduceMotion ? false : { opacity: 0, y: 6 }}
                        animate={{ opacity: 1, y: 0 }}
                        whileHover={shouldReduceMotion ? { y: 0 } : { y: -2 }}
                        whileTap={shouldReduceMotion ? { scale: 1 } : { scale: 0.985 }}
                        transition={{
                          duration: shouldReduceMotion ? 0 : 0.2,
                          delay: shouldReduceMotion ? 0 : idx * 0.035,
                        }}
                        onClick={() => {
                          setQuizCompleted(false);
                          loadScenarioState(idx);
                        }}
                        className={cn(
                          "flex items-center justify-between rounded-lg border p-3 text-xs transition-colors hover:bg-secondary/40",
                          ok ? "border-safe/35 bg-safe/5" : "border-danger/35 bg-danger/5"
                        )}
                      >
                        <div className="min-w-0 pr-2">
                          <p className="truncate font-semibold text-foreground">
                            Q{idx + 1}: {sc.title}
                          </p>
                          <p className="mt-0.5 text-[11px] text-muted-foreground">
                            Expected: <strong>{sc.correctClassification}</strong> • Your answer:{" "}
                            <strong>{att?.selectedClassification ?? "Skipped"}</strong>
                          </p>
                        </div>
                        {ok ? (
                          <CheckCircle2 className="size-4 shrink-0 text-safe" />
                        ) : (
                          <XCircle className="size-4 shrink-0 text-danger" />
                        )}
                      </motion.button>
                    );
                  })}
                </div>

                <div className="mt-7 flex flex-wrap items-center justify-center gap-3">
                  <Button onClick={handleRestartQuiz} className="min-h-10 transition-transform active:scale-97">
                    <Shuffle className="size-4" /> Start New Randomized Quiz (8 Fresh Questions)
                  </Button>
                  <Button variant="outline" onClick={() => setActiveTab("learn")} className="min-h-10 transition-transform active:scale-97">
                    <BookOpen className="size-4" /> Review Threat Guides
                  </Button>
                  <Button asChild variant="secondary" className="min-h-10 transition-transform active:scale-97">
                    <Link to="/message-analyzer">
                      <Sparkles className="size-4" /> Open Live ML Message Scanner
                    </Link>
                  </Button>
                </div>
              </motion.div>
            ) : (
              /* Active Scenario Workspace */
              <div className="grid gap-6 xl:grid-cols-[1.2fr_.8fr]">
                <Panel
                  title={`Scenario ${safeIndex + 1} of ${totalScenarios}: ${currentScenario.title}`}
                  description={`Category: ${currentScenario.category} • Channel: ${currentScenario.channel} • Question Pool: ${QUIZ_QUESTION_BANK.length} Scenarios`}
                  action={
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={cn(
                          "rounded-full border px-2.5 py-0.5 text-[11px] font-semibold",
                          currentScenario.difficulty === "Beginner"
                            ? "border-safe/35 bg-safe/10 text-safe"
                            : currentScenario.difficulty === "Intermediate"
                              ? "border-warning/35 bg-warning/10 text-warning"
                              : "border-danger/35 bg-danger/10 text-danger"
                        )}
                      >
                        {currentScenario.difficulty}
                      </span>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={handleRestartQuiz}
                        title="Draw 8 new randomized questions from the 44-question bank"
                        className="min-h-9 transition-transform active:scale-97 sm:min-h-8"
                      >
                        <Shuffle className="size-3.5" /> New Random Set
                      </Button>
                    </div>
                  }
                >
                  {/* Scenario Step Dots */}
                  <div className="mb-5 flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-1.5">
                      {activeScenarios.map((sc, idx) => {
                        const att = attempts[sc.id];
                        const isCurrent = idx === safeIndex;
                        return (
                          <motion.button
                            key={sc.id}
                            type="button"
                            whileHover={shouldReduceMotion ? { y: 0 } : { y: -1.5 }}
                            whileTap={shouldReduceMotion ? { scale: 1 } : { scale: 0.95 }}
                            onClick={() => loadScenarioState(idx)}
                            className={cn(
                              "h-8 min-w-8 rounded-md border px-2 font-mono text-xs font-semibold transition-colors sm:h-7",
                              isCurrent
                                ? "border-primary bg-primary text-primary-foreground shadow-sm"
                                : att
                                  ? att.isClassificationCorrect
                                    ? "border-safe/40 bg-safe/15 text-safe"
                                    : "border-danger/40 bg-danger/15 text-danger"
                                  : "border-border bg-secondary/40 text-muted-foreground hover:text-foreground"
                            )}
                          >
                            {idx + 1}
                          </motion.button>
                        );
                      })}
                    </div>
                    <span className="font-mono text-[11px] text-muted-foreground">
                      Attempt #{attemptNumber} • Bank ID: {currentScenario.id}
                    </span>
                  </div>

                  {/* Simulated Message Envelope with Animated Question Transition */}
                  <AnimatePresence mode="wait">
                    <motion.div
                      key={currentScenario.id}
                      initial={shouldReduceMotion ? false : { opacity: 0, y: 8 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={shouldReduceMotion ? { opacity: 1 } : { opacity: 0, y: -6 }}
                      transition={{ duration: shouldReduceMotion ? 0 : 0.22, ease: "easeOut" }}
                      className="rounded-xl border border-border bg-secondary/35 p-3.5 shadow-inner sm:p-4 dark:border-slate-800 dark:bg-[#070D19]"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border pb-3 text-xs dark:border-slate-800">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="rounded border border-primary/30 bg-primary/15 px-2 py-0.5 font-mono text-[10px] font-semibold uppercase text-primary dark:border-cyan-500/30 dark:bg-cyan-500/15 dark:text-cyan-300">
                            {currentScenario.channel}
                          </span>
                          <span className="break-all font-mono text-muted-foreground dark:text-slate-300">
                            From: <strong className="text-foreground dark:text-slate-100">{currentScenario.sender}</strong>
                          </span>
                        </div>
                        <span className="text-[11px] text-muted-foreground dark:text-slate-400">
                          Step 1: Click suspicious phrases below (optional)
                        </span>
                      </div>

                      {/* Interactive Clickable Phrase Segments */}
                      <div className="mt-4 leading-8">
                        {currentScenario.segments.map((seg) => {
                          const isSelected = selectedTokens.includes(seg.id);
                          const showSubmittedState = submitted;
                          return (
                            <motion.button
                              key={seg.id}
                              type="button"
                              disabled={submitted}
                              whileHover={
                                submitted || shouldReduceMotion ? { scale: 1 } : { scale: 1.015 }
                              }
                              whileTap={
                                submitted || shouldReduceMotion ? { scale: 1 } : { scale: 0.98 }
                              }
                              onClick={() => toggleToken(seg.id)}
                              className={cn(
                                "mr-1 mb-1 inline rounded-md px-1.5 py-0.5 text-left font-mono text-xs transition-colors",
                                showSubmittedState
                                  ? seg.isSuspicious
                                    ? isSelected
                                      ? "border border-safe bg-safe/20 text-safe font-semibold"
                                      : "border border-warning/60 bg-warning/20 text-warning font-semibold"
                                    : isSelected
                                      ? "border border-danger/50 bg-danger/15 text-danger line-through"
                                      : "text-muted-foreground dark:text-slate-300"
                                  : isSelected
                                    ? "border border-primary bg-primary/20 text-primary font-semibold shadow-[0_0_10px_rgba(34,211,238,0.2)] dark:border-cyan-400 dark:bg-cyan-500/25 dark:text-cyan-200"
                                    : "border border-border bg-card text-foreground hover:border-primary/40 hover:bg-secondary/70 dark:border-transparent dark:bg-slate-900/70 dark:text-slate-200 dark:hover:border-slate-700 dark:hover:bg-slate-800"
                              )}
                            >
                              {seg.text}
                            </motion.button>
                          );
                        })}
                      </div>

                      <div className="mt-3 flex flex-wrap items-center justify-between gap-2 border-t border-border pt-2.5 text-[11px] text-muted-foreground dark:border-slate-800/80 dark:text-slate-400">
                        <span>
                          Flagged phrases:{" "}
                          <strong className="text-primary dark:text-cyan-300">{selectedTokens.length}</strong> selected
                        </span>
                        {submitted && suspiciousInCurrent.length > 0 && (
                          <span>
                            <span className="text-safe">■ Caught red flag</span>{" "}
                            <span className="ml-2 text-warning">■ Missed red flag</span>
                          </span>
                        )}
                      </div>
                    </motion.div>
                  </AnimatePresence>

                  {/* Step 2: Classify Message as Legitimate or Suspicious */}
                  <div className="mt-5">
                    <p className="mb-2.5 text-xs font-semibold text-foreground">
                      Step 2: How do you classify this message?
                    </p>
                    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                      <motion.button
                        type="button"
                        disabled={submitted}
                        whileHover={submitted || shouldReduceMotion ? { y: 0 } : { y: -2 }}
                        whileTap={submitted || shouldReduceMotion ? { scale: 1 } : { scale: 0.985 }}
                        onClick={() => {
                          setSelectedVerdict("Legitimate");
                          setValidationMsg("");
                        }}
                        className={cn(
                          "flex min-h-12 items-center justify-center gap-2.5 rounded-xl border p-3.5 text-sm font-semibold transition-colors",
                          selectedVerdict === "Legitimate"
                            ? "border-safe bg-safe/15 text-safe shadow-[0_0_20px_rgba(34,197,94,0.15)]"
                            : "border-border bg-secondary/30 text-foreground hover:border-safe/40"
                        )}
                      >
                        <ShieldCheck className="size-5 shrink-0" />
                        <span>Legitimate Message</span>
                      </motion.button>

                      <motion.button
                        type="button"
                        disabled={submitted}
                        whileHover={submitted || shouldReduceMotion ? { y: 0 } : { y: -2 }}
                        whileTap={submitted || shouldReduceMotion ? { scale: 1 } : { scale: 0.985 }}
                        onClick={() => {
                          setSelectedVerdict("Suspicious");
                          setValidationMsg("");
                        }}
                        className={cn(
                          "flex min-h-12 items-center justify-center gap-2.5 rounded-xl border p-3.5 text-sm font-semibold transition-colors",
                          selectedVerdict === "Suspicious"
                            ? "border-danger bg-danger/15 text-danger shadow-[0_0_20px_rgba(239,68,68,0.15)]"
                            : "border-border bg-secondary/30 text-foreground hover:border-danger/40"
                        )}
                      >
                        <ShieldAlert className="size-5 shrink-0" />
                        <span>Suspicious / Scam</span>
                      </motion.button>
                    </div>
                  </div>

                  {validationMsg && (
                    <motion.p
                      role="alert"
                      initial={shouldReduceMotion ? false : { opacity: 0, y: 4 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="mt-3 rounded-md border border-warning/40 bg-warning/10 px-3 py-2 text-xs text-warning"
                    >
                      {validationMsg}
                    </motion.p>
                  )}

                  {/* Action Bar */}
                  <div className="mt-5 flex flex-wrap items-center justify-between gap-3 border-t border-border pt-4">
                    <div className="flex w-full flex-wrap items-center gap-2 sm:w-auto">
                      {!submitted ? (
                        <Button
                          onClick={handleSubmitAnswer}
                          className="min-h-11 flex-1 transition-transform active:scale-97 sm:min-h-10 sm:flex-initial"
                        >
                          <CheckCircle2 className="size-4" /> Submit Answer
                        </Button>
                      ) : (
                        <Button
                          onClick={handleNextScenario}
                          className="min-h-11 flex-1 transition-transform active:scale-97 sm:min-h-10 sm:flex-initial"
                        >
                          {safeIndex + 1 < totalScenarios ? (
                            <>
                              Next Scenario ({safeIndex + 2}/{totalScenarios}) <ArrowRight className="size-4" />
                            </>
                          ) : (
                            <>
                              View Final Score &amp; Summary <Trophy className="size-4" />
                            </>
                          )}
                        </Button>
                      )}
                      <Button variant="ghost" size="sm" onClick={handleRestartQuiz} className="min-h-10 sm:min-h-8">
                        <RotateCcw className="size-3.5" /> Restart Practise Quiz
                      </Button>
                    </div>

                    <span className="text-xs text-muted-foreground">
                      Completed: <strong>{completedCount}</strong> of <strong>{totalScenarios}</strong> in this set
                    </span>
                  </div>
                </Panel>

                {/* Right Column: Live Answer Feedback & Explanation */}
                <Panel
                  title="Scenario Feedback & Explanation"
                  description="Detailed breakdown of why this scenario is legitimate or suspicious."
                >
                  <AnimatePresence mode="wait">
                    {submitted && currentAttempt ? (
                      <motion.div
                        key={`feedback-${currentScenario.id}`}
                        initial={shouldReduceMotion ? false : { opacity: 0, y: 8 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={shouldReduceMotion ? { opacity: 1 } : { opacity: 0, y: -6 }}
                        transition={{ duration: shouldReduceMotion ? 0 : 0.22 }}
                        className="space-y-4"
                      >
                        <div
                          className={cn(
                            "rounded-xl border p-4",
                            currentAttempt.isClassificationCorrect
                              ? "border-safe/45 bg-safe/10"
                              : "border-danger/45 bg-danger/10"
                          )}
                        >
                          <div className="flex items-center gap-3">
                            {currentAttempt.isClassificationCorrect ? (
                              <CheckCircle2 className="size-6 shrink-0 text-safe" />
                            ) : (
                              <XCircle className="size-6 shrink-0 text-danger" />
                            )}
                            <div>
                              <p
                                className={cn(
                                  "text-sm font-bold",
                                  currentAttempt.isClassificationCorrect ? "text-safe" : "text-danger"
                                )}
                              >
                                {currentAttempt.isClassificationCorrect
                                  ? "Correct Classification!"
                                  : "Incorrect Classification"}
                              </p>
                              <p className="text-xs text-muted-foreground">
                                Correct Answer: <strong className="text-foreground">{currentScenario.correctClassification}</strong> • Your Choice:{" "}
                                <strong className="text-foreground">{currentAttempt.selectedClassification}</strong>
                              </p>
                            </div>
                          </div>

                          {currentAttempt.totalSuspiciousTokens > 0 && (
                            <p className="mt-2.5 border-t border-border/60 pt-2 text-xs text-muted-foreground">
                              Suspicious phrase spotting: You highlighted{" "}
                              <strong className="text-foreground">
                                {currentAttempt.suspiciousFoundCount} of {currentAttempt.totalSuspiciousTokens}
                              </strong>{" "}
                              red-flag segments in this message.
                            </p>
                          )}
                        </div>

                        <div className="rounded-lg border border-border bg-secondary/25 p-4">
                          <p className="text-xs font-semibold text-foreground">Why?</p>
                          <p className="mt-1.5 text-xs leading-6 text-muted-foreground">
                            {currentScenario.explanation}
                          </p>
                        </div>

                        <div className="rounded-lg border border-primary/25 bg-primary/5 p-4">
                          <p className="flex items-center gap-2 text-xs font-semibold text-foreground">
                            <LockKeyhole className="size-4 text-primary" />
                            Key Security Takeaway
                          </p>
                          <p className="mt-1.5 text-xs leading-5 text-muted-foreground">
                            {currentScenario.keyTakeaway}
                          </p>
                        </div>
                      </motion.div>
                    ) : (
                      <motion.div
                        key={`awaiting-${currentScenario.id}`}
                        initial={shouldReduceMotion ? false : { opacity: 0, scale: 0.985 }}
                        animate={{ opacity: 1, scale: 1 }}
                        exit={shouldReduceMotion ? { opacity: 1 } : { opacity: 0 }}
                        transition={{ duration: shouldReduceMotion ? 0 : 0.2 }}
                        className="flex min-h-64 flex-col items-center justify-center rounded-xl border border-dashed border-border bg-muted/15 p-6 text-center"
                      >
                        <HelpCircle className="size-8 text-muted-foreground" />
                        <h3 className="mt-3 text-sm font-semibold text-foreground">
                          Awaiting Your Verdict
                        </h3>
                        <p className="mt-1 max-w-sm text-xs leading-5 text-muted-foreground">
                          1. Click any suspicious words, links, or urgent threats inside the message on the left.
                          <br />
                          2. Select <strong>Legitimate Message</strong> or <strong>Suspicious / Scam</strong> and click <strong>Submit Answer</strong> to reveal the explanation.
                        </p>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </Panel>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
