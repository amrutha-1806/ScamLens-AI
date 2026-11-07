import { useEffect, useRef, useState, useCallback, useSyncExternalStore } from "react";
import { AnimatePresence, motion } from "motion/react";
import { ChevronDown, ChevronUp, ShieldAlert, ShieldCheck, Sparkles, AlertTriangle, HelpCircle } from "lucide-react";
import { cn } from "@/lib/utils";
import { useScamlensPreferences } from "@/lib/scamlens-preferences";
import type { AnalysisResult, BatchAnalysisResponse } from "@/lib/scamlens-types";

export type RobotMood =
  | "idle"
  | "greeting"
  | "scanning"
  | "legitimate"
  | "suspicious"
  | "high_risk"
  | "invalid";

export type RobotGuardianSource = "auth" | "message" | "url" | "email" | "batch" | "system";

export interface RobotGuardianState {
  mood: RobotMood;
  label: string;
  detail: string;
  source: RobotGuardianSource;
  updatedAt: number;
}

const DEFAULT_GUARDIAN_STATE: RobotGuardianState = {
  mood: "idle",
  label: "AI Guardian Ready",
  detail: "Standing by to inspect messages, URLs, emails, and CSV datasets.",
  source: "system",
  updatedAt: 0,
};

let currentGuardianState: RobotGuardianState = DEFAULT_GUARDIAN_STATE;
let greetingTimerId: ReturnType<typeof setTimeout> | null = null;
const listeners = new Set<() => void>();

function emitGuardianChange() {
  for (const listener of listeners) {
    listener();
  }
}

export function setRobotGuardianState(next: Partial<RobotGuardianState> & { mood: RobotMood }) {
  if (greetingTimerId) {
    clearTimeout(greetingTimerId);
    greetingTimerId = null;
  }

  currentGuardianState = {
    mood: next.mood,
    label: next.label ?? DEFAULT_GUARDIAN_STATE.label,
    detail: next.detail ?? DEFAULT_GUARDIAN_STATE.detail,
    source: next.source ?? "system",
    updatedAt: Date.now(),
  };
  emitGuardianChange();

  if (next.mood === "greeting") {
    greetingTimerId = setTimeout(() => {
      if (currentGuardianState.mood === "greeting") {
        currentGuardianState = {
          ...DEFAULT_GUARDIAN_STATE,
          updatedAt: Date.now(),
        };
        emitGuardianChange();
      }
    }, 5500);
  }
}

export function deriveRobotMoodFromResult(result: AnalysisResult): RobotMood {
  if (
    result.riskLevel === "High" ||
    result.riskLevel === "Very High" ||
    (result.prediction === "Scam/Phishing" && result.riskLevel !== "Suspicious")
  ) {
    return "high_risk";
  }
  if (result.riskLevel === "Suspicious") {
    return "suspicious";
  }
  return "legitimate";
}

export const robotGuardian = {
  getState: () => currentGuardianState,

  greet(detail = "Welcome back! Ready to inspect suspicious links and messages.") {
    try {
      sessionStorage.setItem("scamlens_just_signed_in", "1");
    } catch {
      // Ignore storage errors in restricted environments
    }
    setRobotGuardianState({
      mood: "greeting",
      label: "Welcome to SCAMLENS!",
      detail,
      source: "auth",
    });
  },

  consumePendingGreeting() {
    try {
      if (sessionStorage.getItem("scamlens_just_signed_in") === "1") {
        sessionStorage.removeItem("scamlens_just_signed_in");
        if (currentGuardianState.mood !== "greeting") {
          setRobotGuardianState({
            mood: "greeting",
            label: "Welcome to SCAMLENS!",
            detail: "Welcome back! Ready to inspect suspicious links and messages.",
            source: "auth",
          });
        }
        return true;
      }
    } catch {
      // Ignore storage errors
    }
    return false;
  },

  notifyScanning(detail: string, source: RobotGuardianSource = "system") {
    setRobotGuardianState({
      mood: "scanning",
      label: "Analyzing Input...",
      detail,
      source,
    });
  },

  notifyInvalid(detail: string, source: RobotGuardianSource = "system") {
    setRobotGuardianState({
      mood: "invalid",
      label: "Input Check Needed",
      detail,
      source,
    });
  },

  notifyAnalysisResult(
    result: AnalysisResult,
    sourceLabel: string,
    source: RobotGuardianSource = "system"
  ) {
    const mood = deriveRobotMoodFromResult(result);
    const pct = Math.round(result.riskProbability);

    if (mood === "high_risk") {
      setRobotGuardianState({
        mood: "high_risk",
        label: `${sourceLabel}: High-Risk Threat`,
        detail: `${result.prediction} • ${result.riskLevel} Risk (${pct}%)`,
        source,
      });
    } else if (mood === "suspicious") {
      setRobotGuardianState({
        mood: "suspicious",
        label: `${sourceLabel}: Suspicious`,
        detail: `${result.prediction} • ${result.riskLevel} Risk (${pct}%)`,
        source,
      });
    } else {
      setRobotGuardianState({
        mood: "legitimate",
        label: `${sourceLabel}: Legitimate`,
        detail: `${result.prediction} • ${result.riskLevel} Risk (${pct}%)`,
        source,
      });
    }
  },

  notifyBatchResult(batch: BatchAnalysisResponse) {
    const rows = batch.results ?? [];
    if (rows.length === 0) {
      setRobotGuardianState({
        mood: "invalid",
        label: "Batch Scan Empty",
        detail: "No valid rows were processed from the CSV.",
        source: "batch",
      });
      return;
    }

    const highRiskCount = rows.filter(
      (r) =>
        r.riskLevel === "High" ||
        r.riskLevel === "Very High" ||
        (r.prediction === "Scam/Phishing" && r.riskLevel !== "Suspicious")
    ).length;
    const suspiciousCount = rows.filter((r) => r.riskLevel === "Suspicious").length;

    if (highRiskCount > 0) {
      setRobotGuardianState({
        mood: "high_risk",
        label: "Batch: High-Risk Detected",
        detail: `${highRiskCount} of ${rows.length} row(s) flagged as high-risk Scam/Phishing.`,
        source: "batch",
      });
    } else if (suspiciousCount > 0) {
      setRobotGuardianState({
        mood: "suspicious",
        label: "Batch: Suspicious Rows",
        detail: `${suspiciousCount} of ${rows.length} row(s) marked Suspicious.`,
        source: "batch",
      });
    } else {
      setRobotGuardianState({
        mood: "legitimate",
        label: "Batch: All Legitimate",
        detail: `All ${rows.length} scanned row(s) verified Low Risk.`,
        source: "batch",
      });
    }
  },

  resetToIdle(detail = DEFAULT_GUARDIAN_STATE.detail) {
    setRobotGuardianState({
      mood: "idle",
      label: DEFAULT_GUARDIAN_STATE.label,
      detail,
      source: "system",
    });
  },
};

function subscribeGuardian(listener: () => void) {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function useRobotGuardian(): RobotGuardianState {
  return useSyncExternalStore(
    subscribeGuardian,
    () => currentGuardianState,
    () => DEFAULT_GUARDIAN_STATE
  );
}

export interface CyberRobotProps {
  className?: string;
  size?: number;
  /** Current behavioural mood of the Robot Guardian */
  mood?: RobotMood;
  /** Whether the user is actively focused on the password field */
  isPasswordFocused?: boolean;
  /** Whether password text is currently visible */
  showPassword?: boolean;
  /** Custom tracking container ref; if omitted, tracks on window or parent container */
  containerRef?: React.RefObject<HTMLElement | null>;
  /** Optional external active cursor position in viewport coordinates */
  cursorPos?: { x: number; y: number } | null;
  /** Active hover state inside the sign-in area */
  isInsideSignInArea?: boolean;
}

export function CyberRobot({
  className,
  size = 130,
  mood = "idle",
  isPasswordFocused = false,
  showPassword = false,
  cursorPos,
  isInsideSignInArea = true,
}: CyberRobotProps) {
  const { shouldReduceMotion } = useScamlensPreferences();
  const robotRef = useRef<SVGSVGElement | null>(null);

  // Natural movement limits
  // Yaw: left/right rotation in degrees (-18deg to +18deg)
  // Pitch: up/down tilt in degrees (-10deg to +10deg)
  // Head displacement: subtle translation to simulate 3D head pivot (-5px to +5px)
  // Eye offset: independent eye movement within visor (-7px to +7px)
  const [headAngles, setHeadAngles] = useState({
    yaw: 0, // rotate left/right
    pitch: 0, // tilt up/down
    headX: 0, // lateral head translation
    headY: 0, // vertical head translation
    eyeX: 0, // independent eye tracking X
    eyeY: 0, // independent eye tracking Y
  });

  const [isBlinking, setIsBlinking] = useState(false);
  const [idleHeadSway, setIdleHeadSway] = useState({ yaw: 0, pitch: 0 });
  const lastCursorMoveRef = useRef<number>(0);

  // Periodic natural digital blink (every 3.5-6.5 seconds)
  useEffect(() => {
    if (shouldReduceMotion) return;

    let timeoutId: ReturnType<typeof setTimeout>;

    const scheduleBlink = () => {
      const delay = 3500 + Math.random() * 3000;
      timeoutId = setTimeout(() => {
        setIsBlinking(true);
        setTimeout(() => {
          setIsBlinking(false);
          scheduleBlink();
        }, 160);
      }, delay);
    };

    scheduleBlink();
    return () => clearTimeout(timeoutId);
  }, [shouldReduceMotion]);

  // Subtle idle head micro-movement when cursor is inactive
  useEffect(() => {
    if (shouldReduceMotion) {
      setIdleHeadSway({ yaw: 0, pitch: 0 });
      return;
    }

    const intervalId = setInterval(() => {
      const elapsed = Date.now() - lastCursorMoveRef.current;
      if (elapsed < 2200) return;
      const randomYaw = (Math.random() - 0.5) * 5; // -2.5 to +2.5 deg
      const randomPitch = (Math.random() - 0.5) * 3; // -1.5 to +1.5 deg
      setIdleHeadSway({
        yaw: Math.round(randomYaw * 10) / 10,
        pitch: Math.round(randomPitch * 10) / 10,
      });
    }, 3200);

    return () => clearInterval(intervalId);
  }, [shouldReduceMotion]);

  // Compute angles from cursor position relative to the robot's head center
  const updateHeadTracking = useCallback(
    (clientX: number, clientY: number) => {
      if (shouldReduceMotion) {
        setHeadAngles({ yaw: 0, pitch: 0, headX: 0, headY: 0, eyeX: 0, eyeY: 0 });
        return;
      }

      if (!robotRef.current) return;
      const rect = robotRef.current.getBoundingClientRect();

      // The robot head center pivot is approximately at (width * 0.5, height * 0.38)
      const headCenterX = rect.left + rect.width * 0.5;
      const headCenterY = rect.top + rect.height * 0.38;

      const deltaX = clientX - headCenterX;
      const deltaY = clientY - headCenterY;

      // Distance normalization across typical viewport space (~380px radius)
      const maxDistanceX = Math.max(window.innerWidth * 0.35, 300);
      const maxDistanceY = Math.max(window.innerHeight * 0.35, 300);

      // Clamp normalized values strictly between -1 and +1
      const normX = Math.max(-1, Math.min(1, deltaX / maxDistanceX));
      const normY = Math.max(-1, Math.min(1, deltaY / maxDistanceY));

      // Calculate angles within strict natural limits:
      // Yaw: -18 to +18 degrees (head turns left/right to face cursor)
      const targetYaw = normX * 18;

      // Pitch: -10 to +10 degrees (subtle up/down tilt)
      const targetPitch = normY * 10;

      // Head translation on the neck pivot: -5px to +5px
      const targetHeadX = normX * 4.5;
      const targetHeadY = normY * 3.5;

      // Eye offset: independent movement inside the visor: -7px to +7px
      const targetEyeX = normX * 6.5;
      const targetEyeY = normY * 4.5;

      lastCursorMoveRef.current = Date.now();
      setIdleHeadSway({ yaw: 0, pitch: 0 });

      setHeadAngles({
        yaw: Math.round(targetYaw * 10) / 10,
        pitch: Math.round(targetPitch * 10) / 10,
        headX: Math.round(targetHeadX * 10) / 10,
        headY: Math.round(targetHeadY * 10) / 10,
        eyeX: Math.round(targetEyeX * 10) / 10,
        eyeY: Math.round(targetEyeY * 10) / 10,
      });
    },
    [shouldReduceMotion]
  );

  // Return to neutral position when cursor leaves tracking area
  const resetToNeutral = useCallback(() => {
    setHeadAngles({
      yaw: 0,
      pitch: 0,
      headX: 0,
      headY: 0,
      eyeX: 0,
      eyeY: 0,
    });
  }, []);

  // Update when external cursorPos / isInsideSignInArea is provided (Sign-In page)
  useEffect(() => {
    if (cursorPos === undefined) return;
    if (!isInsideSignInArea || !cursorPos) {
      resetToNeutral();
    } else {
      updateHeadTracking(cursorPos.x, cursorPos.y);
    }
  }, [cursorPos, isInsideSignInArea, resetToNeutral, updateHeadTracking]);

  // Global window cursor tracking when external cursorPos prop is omitted (Workspace companion)
  useEffect(() => {
    if (cursorPos !== undefined || shouldReduceMotion) return;

    const handleMouseMove = (e: MouseEvent) => {
      updateHeadTracking(e.clientX, e.clientY);
    };
    const handleMouseLeave = () => {
      resetToNeutral();
    };

    window.addEventListener("mousemove", handleMouseMove, { passive: true });
    document.addEventListener("mouseleave", handleMouseLeave);
    return () => {
      window.removeEventListener("mousemove", handleMouseMove);
      document.removeEventListener("mouseleave", handleMouseLeave);
    };
  }, [cursorPos, shouldReduceMotion, updateHeadTracking, resetToNeutral]);

  // Mood-specific head tilt adjustments combined with cursor tracking
  const moodYawOffset =
    isPasswordFocused
      ? 0
      : mood === "greeting"
        ? 5
        : mood === "invalid"
          ? -8
          : mood === "suspicious"
            ? -4
            : 0;

  const baseYaw = headAngles.yaw !== 0 ? headAngles.yaw : idleHeadSway.yaw;
  const basePitch = headAngles.pitch !== 0 ? headAngles.pitch : idleHeadSway.pitch;

  const effectiveYaw =
    isPasswordFocused && !cursorPos
      ? -3
      : Math.max(-18, Math.min(18, baseYaw + moodYawOffset));
  const effectivePitch = isPasswordFocused && !cursorPos ? 6 : basePitch;
  const effectiveEyeY = isPasswordFocused && !cursorPos ? 4 : headAngles.eyeY;

  // When hands are raised to cover the eyes, gently follow the head's visor displacement
  // so both hands remain squarely over the eyes even as the head tracks the cursor.
  const visorCoverX = headAngles.headX + effectiveYaw * 0.62;
  const visorCoverY = headAngles.headY + Math.abs(effectivePitch) * 0.15;
  const visorCoverRotate = effectiveYaw * 0.85;

  const armSpringTransition = shouldReduceMotion
    ? { duration: 0 }
    : {
        type: "spring" as const,
        stiffness: 210,
        damping: 19,
        mass: 0.65,
      };

  // Compute Left & Right Arm Target Poses based on isPasswordFocused and mood
  const leftArmAnimate = isPasswordFocused
    ? {
        x: visorCoverX,
        y: visorCoverY,
        rotate: visorCoverRotate,
      }
    : mood === "high_risk"
      ? {
          x: -32,
          y: -4,
          rotate: -28,
        }
      : mood === "scanning"
        ? {
            x: -30,
            y: 40,
            rotate: -20,
          }
        : {
            x: -34,
            y: 50,
            rotate: -30,
          };

  const rightArmAnimate = isPasswordFocused
    ? {
        x: visorCoverX,
        y: visorCoverY,
        rotate: visorCoverRotate,
      }
    : mood === "greeting"
      ? {
          x: 34,
          y: -10,
          rotate: shouldReduceMotion ? 24 : [16, 36, 14, 36, 22],
        }
      : mood === "legitimate"
        ? {
            x: 36,
            y: 26,
            rotate: 12,
          }
        : mood === "suspicious"
          ? {
              x: 22,
              y: 34,
              rotate: 6,
            }
          : mood === "high_risk"
            ? {
                x: 32,
                y: -4,
                rotate: 28,
              }
            : mood === "invalid"
              ? {
                  x: 34,
                  y: 12,
                  rotate: 18,
                }
              : mood === "scanning"
                ? {
                    x: 30,
                    y: 40,
                    rotate: 20,
                  }
                : {
                    x: 34,
                    y: 50,
                    rotate: 30,
                  };

  const rightArmTransition =
    !isPasswordFocused && mood === "greeting" && !shouldReduceMotion
      ? {
          rotate: {
            duration: 1.35,
            repeat: Infinity,
            ease: "easeInOut" as const,
          },
          x: armSpringTransition,
          y: armSpringTransition,
        }
      : armSpringTransition;

  // Dynamic accent colors for aura & antenna based on mood
  const auraColorClass =
    !isPasswordFocused && mood === "high_risk"
      ? "bg-red-500/30 dark:bg-red-500/35"
      : !isPasswordFocused && mood === "suspicious"
        ? "bg-amber-400/25 dark:bg-amber-500/30"
        : !isPasswordFocused && (mood === "legitimate" || mood === "greeting")
          ? "bg-emerald-400/25 dark:bg-emerald-500/30"
          : !isPasswordFocused && mood === "invalid"
            ? "bg-violet-400/25 dark:bg-violet-500/30"
            : "bg-cyan-400/20 dark:bg-cyan-500/25";

  const antennaColor =
    !isPasswordFocused && mood === "high_risk"
      ? "#EF4444"
      : !isPasswordFocused && mood === "suspicious"
        ? "#F59E0B"
        : !isPasswordFocused && (mood === "legitimate" || mood === "greeting")
          ? "#10B981"
          : !isPasswordFocused && mood === "invalid"
            ? "#A855F7"
            : "#22D3EE";

  return (
    <div
      data-password-focused={isPasswordFocused ? "true" : "false"}
      data-show-password={showPassword ? "true" : "false"}
      data-robot-mood={isPasswordFocused ? "password_shield" : mood}
      className={cn(
        "relative flex flex-col items-center justify-center select-none pointer-events-none",
        className
      )}
      style={{ width: size, height: size * 1.05 }}
    >
      {/* Ambient Cyber Aura / Reactor Backlight */}
      <div
        className={cn(
          "pointer-events-none absolute -inset-2 rounded-full blur-xl transition-colors duration-300",
          auraColorClass
        )}
      />

      <svg
        ref={robotRef}
        viewBox="0 0 160 170"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="w-full h-full drop-shadow-[0_8px_20px_rgba(6,182,212,0.35)] overflow-visible"
      >
        <defs>
          {/* Gradients for Body & Shoulders */}
          <linearGradient id="cyber_body_grad" x1="80" y1="105" x2="80" y2="165" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#1E293B" />
            <stop offset="50%" stopColor="#0F172A" />
            <stop offset="100%" stopColor="#020617" />
          </linearGradient>

          <linearGradient id="cyber_body_trim" x1="20" y1="110" x2="140" y2="165" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#22D3EE" />
            <stop offset="50%" stopColor="#0EA5E9" />
            <stop offset="100%" stopColor="#14B8A6" />
          </linearGradient>

          {/* Gradients for Arms & Hands */}
          <linearGradient id="cyber_hand_grad" x1="80" y1="40" x2="80" y2="100" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#334155" />
            <stop offset="55%" stopColor="#1E293B" />
            <stop offset="100%" stopColor="#0F172A" />
          </linearGradient>

          {/* Gradients for Head Helmet & Ears */}
          <linearGradient id="cyber_head_grad" x1="80" y1="15" x2="80" y2="95" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#F8FAFC" />
            <stop offset="45%" stopColor="#E2E8F0" />
            <stop offset="100%" stopColor="#CBD5E1" />
          </linearGradient>

          <linearGradient id="cyber_head_dark" x1="80" y1="15" x2="80" y2="95" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#334155" />
            <stop offset="50%" stopColor="#1E293B" />
            <stop offset="100%" stopColor="#0F172A" />
          </linearGradient>

          <linearGradient id="cyber_visor_grad" x1="80" y1="36" x2="80" y2="82" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#030712" />
            <stop offset="70%" stopColor="#081426" />
            <stop offset="100%" stopColor="#0C1F38" />
          </linearGradient>

          {/* Eye Glow Radial Gradients */}
          <radialGradient id="cyber_eye_glow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#FFFFFF" />
            <stop offset="35%" stopColor="#67E8F9" />
            <stop offset="75%" stopColor="#06B6D4" stopOpacity="0.9" />
            <stop offset="100%" stopColor="#0284C7" stopOpacity="0" />
          </radialGradient>

          <radialGradient id="cyber_eye_safe" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#FFFFFF" />
            <stop offset="35%" stopColor="#6EE7B7" />
            <stop offset="75%" stopColor="#10B981" stopOpacity="0.95" />
            <stop offset="100%" stopColor="#059669" stopOpacity="0" />
          </radialGradient>

          <radialGradient id="cyber_eye_warn" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#FFFFFF" />
            <stop offset="35%" stopColor="#FDE68A" />
            <stop offset="75%" stopColor="#F59E0B" stopOpacity="0.95" />
            <stop offset="100%" stopColor="#D97706" stopOpacity="0" />
          </radialGradient>

          <radialGradient id="cyber_eye_danger" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#FFFFFF" />
            <stop offset="35%" stopColor="#FCA5A5" />
            <stop offset="75%" stopColor="#EF4444" stopOpacity="0.95" />
            <stop offset="100%" stopColor="#DC2626" stopOpacity="0" />
          </radialGradient>

          {/* Chest Core Shield Gradient */}
          <radialGradient id="cyber_core_reactor" cx="80" cy="136" r="16" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#FFFFFF" />
            <stop offset="30%" stopColor="#67E8F9" />
            <stop offset="70%" stopColor="#06B6D4" />
            <stop offset="100%" stopColor="#0F172A" stopOpacity="0" />
          </radialGradient>
        </defs>

        {/* =================================================================== */}
        {/* 1. STABLE BODY & SHOULDERS (Does NOT rotate - stays anchored)       */}
        {/* =================================================================== */}
        <g id="stable-robot-body">
          {/* Shoulder Plates (Left & Right) */}
          <path
            d="M34 128 C26 128, 20 134, 18 142 L16 156 C24 158, 36 156, 44 150 L42 134 Z"
            fill="url(#cyber_body_grad)"
            stroke="url(#cyber_body_trim)"
            strokeWidth="1.6"
            strokeLinejoin="round"
          />
          <path
            d="M126 128 C134 128, 140 134, 142 142 L144 156 C136 158, 124 156, 116 150 L118 134 Z"
            fill="url(#cyber_body_grad)"
            stroke="url(#cyber_body_trim)"
            strokeWidth="1.6"
            strokeLinejoin="round"
          />

          {/* Armored Chest Torso */}
          <path
            d="M48 118 C48 114, 54 110, 62 110 L98 110 C106 110, 112 114, 112 118 L118 146 C118 156, 110 164, 98 165 L62 165 C50 164, 42 156, 42 146 Z"
            fill="url(#cyber_body_grad)"
            stroke="url(#cyber_body_trim)"
            strokeWidth="2.2"
            strokeLinejoin="round"
          />

          {/* Cybernetic Panel Seams & Accent Insets on Torso */}
          <path
            d="M56 120 L70 134 L90 134 L104 120"
            stroke="#22D3EE"
            strokeWidth="1.2"
            strokeOpacity="0.4"
            fill="none"
          />
          <line x1="80" y1="146" x2="80" y2="162" stroke="#22D3EE" strokeWidth="1.4" strokeOpacity="0.5" strokeDasharray="3 2" />

          {/* Central Reactor Core Emblem (SCAMLENS Shield) */}
          <circle cx="80" cy="136" r="9" fill="url(#cyber_core_reactor)" />
          <path
            d="M80 129 L86 132 C86 138, 83 142, 80 144 C77 142, 74 138, 74 132 Z"
            fill="none"
            stroke="#FFFFFF"
            strokeWidth="1.2"
            strokeLinejoin="round"
          />

          {/* Mechanical Neck Swivel Ring & Base Joint (anchored at center 80, 102) */}
          <ellipse cx="80" cy="104" rx="14" ry="5.5" fill="#0B132B" stroke="#38BDF8" strokeWidth="1.5" />
          <rect x="74" y="98" width="12" height="6" rx="2" fill="#1E293B" stroke="#0EA5E9" strokeWidth="1" />
        </g>

        {/* =================================================================== */}
        {/* 2. THE ROBOT'S ENTIRE HEAD (Rotates, Tilts, and Tracks the Cursor)  */}
        {/* Pivot is centered around the neck joint at (x: 80, y: 98)            */}
        {/* =================================================================== */}
        <motion.g
          id="tracking-robot-head"
          animate={{
            rotate: effectiveYaw,
            x: headAngles.headX,
            y: headAngles.headY,
            scaleY: 1 - Math.abs(effectivePitch) * 0.008, // 3D foreshortening on pitch tilt
            originX: "80px",
            originY: "98px",
          }}
          transition={
            shouldReduceMotion
              ? { duration: 0 }
              : {
                  type: "spring",
                  stiffness: 220,
                  damping: 20,
                  mass: 0.65,
                }
          }
          style={{ transformOrigin: "80px 98px" }}
        >
          {/* Head Top Sensory Antenna */}
          <line x1="80" y1="20" x2="80" y2="9" stroke={antennaColor} strokeWidth="2.5" strokeLinecap="round" />
          <circle cx="80" cy="7" r="3.8" fill={antennaColor} className={cn(!shouldReduceMotion && "animate-pulse")} />
          <circle cx="80" cy="7" r="1.5" fill="#FFFFFF" />

          {/* High-Risk Antenna Alert Ring */}
          {!isPasswordFocused && mood === "high_risk" && (
            <circle
              cx="80"
              cy="7"
              r="7.5"
              stroke="#EF4444"
              strokeWidth="1.4"
              strokeOpacity="0.75"
              fill="none"
            />
          )}

          {/* Left Audio Sensor / Cyber Ear Muff */}
          <rect
            x="24"
            y="48"
            width="8"
            height="26"
            rx="4"
            fill="#1E293B"
            stroke="#22D3EE"
            strokeWidth="1.4"
          />
          <circle cx="28" cy="61" r="2" fill={antennaColor} />

          {/* Right Audio Sensor / Cyber Ear Muff */}
          <rect
            x="128"
            y="48"
            width="8"
            height="26"
            rx="4"
            fill="#1E293B"
            stroke="#22D3EE"
            strokeWidth="1.4"
          />
          <circle cx="132" cy="61" r="2" fill={antennaColor} />

          {/* Outer Main Helmet Dome / Armor Shell */}
          <path
            d="M40 38 C40 22, 58 16, 80 16 C102 16, 120 22, 120 38 L122 72 C122 86, 106 96, 80 96 C54 96, 38 86, 38 72 Z"
            fill="url(#cyber_head_dark)"
            stroke="url(#cyber_body_trim)"
            strokeWidth="2.6"
            strokeLinejoin="round"
          />

          {/* Helmet Top Brow Trim Plate */}
          <path
            d="M48 34 C58 26, 70 24, 80 24 C90 24, 102 26, 112 34 L110 40 C100 32, 90 30, 80 30 C70 30, 60 32, 50 40 Z"
            fill={antennaColor}
            fillOpacity="0.45"
          />

          {/* Deep Cybernetic Visor Screen (Eye Display Window) */}
          <rect
            x="44"
            y="38"
            width="72"
            height="44"
            rx="14"
            fill="url(#cyber_visor_grad)"
            stroke={!isPasswordFocused && mood === "high_risk" ? "#EF4444" : !isPasswordFocused && mood === "suspicious" ? "#F59E0B" : !isPasswordFocused && (mood === "legitimate" || mood === "greeting") ? "#10B981" : "#0EA5E9"}
            strokeWidth="1.8"
          />

          {/* Inner Visor Scan HUD Crosshairs / Subtle Reticle Marks */}
          <line x1="48" y1="60" x2="52" y2="60" stroke="#22D3EE" strokeWidth="1" strokeOpacity="0.4" />
          <line x1="108" y1="60" x2="112" y2="60" stroke="#22D3EE" strokeWidth="1" strokeOpacity="0.4" />

          {/* Subtle Visor Laser Sweep when Scanning */}
          {!isPasswordFocused && mood === "scanning" && (
            <motion.line
              id="visor-scan-beam"
              x1="47"
              x2="113"
              y1="44"
              y2="44"
              stroke="#22D3EE"
              strokeWidth="1.8"
              strokeOpacity="0.85"
              animate={shouldReduceMotion ? { y: 16 } : { y: [0, 30, 0] }}
              transition={
                shouldReduceMotion
                  ? { duration: 0 }
                  : { duration: 1.5, repeat: Infinity, ease: "easeInOut" }
              }
            />
          )}

          {/* =================================================================== */}
          {/* 3. INDEPENDENT EYE ASSEMBLY (Moves independently to follow cursor)  */}
          {/* =================================================================== */}
          <motion.g
            id="independent-tracking-eyes"
            animate={{
              x: headAngles.eyeX,
              y: effectiveEyeY,
              scaleY: isBlinking ? 0.08 : 1, // Digital blink
              originX: "80px",
              originY: "60px",
            }}
            transition={
              shouldReduceMotion
                ? { duration: 0 }
                : {
                    type: "spring",
                    stiffness: 280,
                    damping: 22,
                    mass: 0.45,
                  }
            }
          >
            {/* Left Eye */}
            <g id="left-eye">
              {!isPasswordFocused && (mood === "greeting" || mood === "legitimate") ? (
                <>
                  <circle cx="64" cy="59" r="8" fill="#031526" stroke="#34D399" strokeWidth="1.5" />
                  <path
                    d="M58 61 Q64 52 70 61"
                    stroke="#6EE7B7"
                    strokeWidth="3"
                    strokeLinecap="round"
                    fill="none"
                  />
                  <path
                    d="M59.5 61 Q64 54 68.5 61"
                    stroke="#FFFFFF"
                    strokeWidth="1.4"
                    strokeLinecap="round"
                    fill="none"
                  />
                </>
              ) : !isPasswordFocused && mood === "suspicious" ? (
                <>
                  <circle cx="64" cy="60" r="7.8" fill="#1F1206" stroke="#F59E0B" strokeWidth="1.5" />
                  <circle cx="64" cy="60" r="4.8" fill="url(#cyber_eye_warn)" />
                  <circle cx="64" cy="60" r="2.1" fill="#FFFFFF" />
                  {/* Concerned worried brow (inner end raised) */}
                  <path d="M55 54 Q63 48 72 50" stroke="#FBBF24" strokeWidth="2.4" strokeLinecap="round" fill="none" />
                </>
              ) : !isPasswordFocused && mood === "high_risk" ? (
                <>
                  <circle cx="64" cy="59" r="8.5" fill="#2A0808" stroke="#EF4444" strokeWidth="1.7" />
                  <circle cx="64" cy="59" r="5.5" fill="url(#cyber_eye_danger)" />
                  <circle cx="64" cy="59" r="2.3" fill="#FFFFFF" />
                  {/* High-alert sharp brow */}
                  <line x1="56" y1="49" x2="72" y2="54" stroke="#F87171" strokeWidth="2.5" strokeLinecap="round" />
                </>
              ) : !isPasswordFocused && mood === "invalid" ? (
                <>
                  {/* Confused squinted left eye */}
                  <ellipse cx="64" cy="60" rx="8" ry="5.2" fill="#031526" stroke="#22D3EE" strokeWidth="1.5" />
                  <ellipse cx="64" cy="60" rx="4.2" ry="3.2" fill="url(#cyber_eye_glow)" />
                  <circle cx="64" cy="60" r="1.6" fill="#FFFFFF" />
                  <line x1="55" y1="52" x2="72" y2="52" stroke="#67E8F9" strokeWidth="2.2" strokeLinecap="round" />
                </>
              ) : (
                <>
                  {/* Standard / Scanning Left Eye */}
                  <circle cx="64" cy="59" r="8" fill="#031526" stroke="#22D3EE" strokeWidth="1.4" />
                  <circle cx="64" cy="59" r="5" fill="url(#cyber_eye_glow)" />
                  <circle cx="64" cy="59" r="2.2" fill="#FFFFFF" />
                  <path
                    d="M61 56 A4 4 0 0 1 67 56"
                    stroke="#FFFFFF"
                    strokeWidth="0.8"
                    strokeLinecap="round"
                  />
                  {!isPasswordFocused && mood === "scanning" && (
                    <>
                      {/* Focused upper/lower eyelid shutters */}
                      <line x1="55" y1="53" x2="73" y2="54.5" stroke="#38BDF8" strokeWidth="2.2" strokeLinecap="round" />
                      <line x1="55" y1="65" x2="73" y2="64" stroke="#38BDF8" strokeWidth="1.8" strokeLinecap="round" />
                    </>
                  )}
                </>
              )}
            </g>

            {/* Right Eye */}
            <g id="right-eye">
              {!isPasswordFocused && (mood === "greeting" || mood === "legitimate") ? (
                <>
                  <circle cx="96" cy="59" r="8" fill="#031526" stroke="#34D399" strokeWidth="1.5" />
                  <path
                    d="M90 61 Q96 52 102 61"
                    stroke="#6EE7B7"
                    strokeWidth="3"
                    strokeLinecap="round"
                    fill="none"
                  />
                  <path
                    d="M91.5 61 Q96 54 100.5 61"
                    stroke="#FFFFFF"
                    strokeWidth="1.4"
                    strokeLinecap="round"
                    fill="none"
                  />
                </>
              ) : !isPasswordFocused && mood === "suspicious" ? (
                <>
                  <circle cx="96" cy="60" r="7.8" fill="#1F1206" stroke="#F59E0B" strokeWidth="1.5" />
                  <circle cx="96" cy="60" r="4.8" fill="url(#cyber_eye_warn)" />
                  <circle cx="96" cy="60" r="2.1" fill="#FFFFFF" />
                  {/* Concerned worried brow (inner end raised) */}
                  <path d="M105 54 Q97 48 88 50" stroke="#FBBF24" strokeWidth="2.4" strokeLinecap="round" fill="none" />
                </>
              ) : !isPasswordFocused && mood === "high_risk" ? (
                <>
                  <circle cx="96" cy="59" r="8.5" fill="#2A0808" stroke="#EF4444" strokeWidth="1.7" />
                  <circle cx="96" cy="59" r="5.5" fill="url(#cyber_eye_danger)" />
                  <circle cx="96" cy="59" r="2.3" fill="#FFFFFF" />
                  {/* High-alert sharp brow */}
                  <line x1="104" y1="49" x2="88" y2="54" stroke="#F87171" strokeWidth="2.5" strokeLinecap="round" />
                </>
              ) : !isPasswordFocused && mood === "invalid" ? (
                <>
                  {/* Confused wide raised right eye */}
                  <circle cx="96" cy="58" r="8.8" fill="#031526" stroke="#A855F7" strokeWidth="1.5" />
                  <circle cx="96" cy="58" r="5.4" fill="url(#cyber_eye_glow)" />
                  <circle cx="96" cy="58" r="2.2" fill="#FFFFFF" />
                  <path d="M88 49 Q96 44 104 50" stroke="#C084FC" strokeWidth="2.2" strokeLinecap="round" fill="none" />
                </>
              ) : (
                <>
                  {/* Standard / Scanning Right Eye */}
                  <circle cx="96" cy="59" r="8" fill="#031526" stroke="#22D3EE" strokeWidth="1.4" />
                  <circle cx="96" cy="59" r="5" fill="url(#cyber_eye_glow)" />
                  <circle cx="96" cy="59" r="2.2" fill="#FFFFFF" />
                  <path
                    d="M93 56 A4 4 0 0 1 99 56"
                    stroke="#FFFFFF"
                    strokeWidth="0.8"
                    strokeLinecap="round"
                  />
                  {!isPasswordFocused && mood === "scanning" && (
                    <>
                      {/* Focused upper/lower eyelid shutters */}
                      <line x1="87" y1="54.5" x2="105" y2="53" stroke="#38BDF8" strokeWidth="2.2" strokeLinecap="round" />
                      <line x1="87" y1="64" x2="105" y2="65" stroke="#38BDF8" strokeWidth="1.8" strokeLinecap="round" />
                    </>
                  )}
                </>
              )}
            </g>

            {/* Center Visor HUD Mood Indicator */}
            {!isPasswordFocused && mood === "high_risk" && (
              <g id="high-risk-visor-alert">
                <line x1="80" y1="51" x2="80" y2="61" stroke="#F87171" strokeWidth="2.4" strokeLinecap="round" />
                <circle cx="80" cy="66" r="1.5" fill="#F87171" />
              </g>
            )}

            {!isPasswordFocused && mood === "invalid" && (
              <g id="invalid-visor-question">
                <path
                  d="M77.5 53 C77.5 50.5, 82.5 50.5, 82.5 53.5 C82.5 55.5, 80 56, 80 58.5"
                  stroke="#C084FC"
                  strokeWidth="2"
                  strokeLinecap="round"
                  fill="none"
                />
                <circle cx="80" cy="62.5" r="1.3" fill="#C084FC" />
              </g>
            )}

            {/* Playful Blush Cheek Marks when hiding eyes or greeting/happy */}
            {(isPasswordFocused || mood === "greeting" || mood === "legitimate") && (
              <g opacity="0.75">
                <line x1="52" y1="73" x2="56" y2="71" stroke={mood === "legitimate" || mood === "greeting" ? "#34D399" : "#22D3EE"} strokeWidth="1.3" strokeLinecap="round" />
                <line x1="56" y1="74" x2="60" y2="72" stroke={mood === "legitimate" || mood === "greeting" ? "#34D399" : "#22D3EE"} strokeWidth="1.3" strokeLinecap="round" />
                <line x1="100" y1="72" x2="104" y2="74" stroke={mood === "legitimate" || mood === "greeting" ? "#34D399" : "#22D3EE"} strokeWidth="1.3" strokeLinecap="round" />
                <line x1="104" y1="71" x2="108" y2="73" stroke={mood === "legitimate" || mood === "greeting" ? "#34D399" : "#22D3EE"} strokeWidth="1.3" strokeLinecap="round" />
              </g>
            )}
          </motion.g>

          {/* Curved Visor Specular Glass Glare Arc (Overlay on top of eyes for realistic depth) */}
          <path
            d="M48 48 C64 40, 96 40, 112 48"
            stroke="#FFFFFF"
            strokeWidth="1.5"
            strokeLinecap="round"
            strokeOpacity="0.45"
            fill="none"
          />

          {/* Chin Plate / Ventilation Mesh */}
          <path
            d="M66 86 L94 86 L90 91 L70 91 Z"
            fill="#0F172A"
            stroke="#0EA5E9"
            strokeWidth="1"
          />
          <line x1="74" y1="88" x2="86" y2="88" stroke="#38BDF8" strokeWidth="1" strokeDasharray="1.5 1.5" />
        </motion.g>

        {/* =================================================================== */}
        {/* 4. ARTICULATED ROBOT ARMS & HANDS                                   */}
        {/* - Password Focus: Both hands visibly cover the eyes.                */}
        {/* - Greeting: Right hand waves hello.                                 */}
        {/* - Legitimate: Right hand gives a clear thumbs-up.                   */}
        {/* - High Risk: Both arms raised in alert warning gesture.             */}
        {/* =================================================================== */}
        <g id="robot-arms-layer">
          {/* LEFT ARM & HAND (Covers Left Eye at cx=64, cy=59 when password focused) */}
          <motion.g
            id="left-robot-arm"
            initial={false}
            animate={leftArmAnimate}
            transition={armSpringTransition}
            style={{ transformOrigin: "56px 76px" }}
          >
            {/* Left Forearm Gauntlet (reaches from shoulder/elbow up to wrist) */}
            <path
              d="M32 110 C30 96, 39 78, 49 66 L64 72 C57 84, 49 98, 46 112 C42 115, 34 114, 32 110 Z"
              fill="url(#cyber_hand_grad)"
              stroke="#22D3EE"
              strokeWidth="1.8"
              strokeLinejoin="round"
            />
            {/* Forearm Energy Seam */}
            <path
              d="M39 106 C41 94, 47 82, 54 72"
              stroke="#38BDF8"
              strokeWidth="1.1"
              strokeOpacity="0.55"
              strokeLinecap="round"
            />
            {/* Wrist Articulation Band */}
            <path
              d="M47 67 L64 73"
              stroke="#38BDF8"
              strokeWidth="2.4"
              strokeLinecap="round"
            />
            {/* Left Palm / Back of Cyber-Glove (Centered directly over Left Eye 64, 59) */}
            <path
              d="M46 56 C46 48, 53 44, 63 45 L75 48 C79 50, 80 56, 78 63 L74 69 C70 73, 59 73, 51 69 C47 66, 46 61, 46 56 Z"
              fill="url(#cyber_hand_grad)"
              stroke="url(#cyber_body_trim)"
              strokeWidth="2"
              strokeLinejoin="round"
            />
            {/* Left Thumb (Outer visor edge) */}
            <rect
              x="44"
              y="47"
              width="7"
              height="14"
              rx="3.5"
              transform="rotate(-14 47 54)"
              fill="#1E293B"
              stroke="#22D3EE"
              strokeWidth="1.4"
            />
            {/* 3 Splayed Cyber Fingers over Left Eye */}
            <rect
              x="55"
              y="43"
              width="23"
              height="6.5"
              rx="3.2"
              transform="rotate(-8 66 46)"
              fill="#1E293B"
              stroke="#22D3EE"
              strokeWidth="1.4"
            />
            <rect
              x="57"
              y="50.5"
              width="23"
              height="6.5"
              rx="3.2"
              transform="rotate(-3 68 54)"
              fill="#1E293B"
              stroke="#22D3EE"
              strokeWidth="1.4"
            />
            <rect
              x="56"
              y="58"
              width="22"
              height="6.5"
              rx="3.2"
              transform="rotate(3 67 61)"
              fill="#1E293B"
              stroke="#22D3EE"
              strokeWidth="1.4"
            />
            {/* Glowing Cyan Back-of-Hand Node & Knuckle Accents */}
            <circle cx="59" cy="60" r="3.8" fill="#082F49" stroke="#22D3EE" strokeWidth="1.3" />
            <circle cx="59" cy="60" r="1.6" fill="#67E8F9" />
          </motion.g>

          {/* RIGHT ARM & HAND (Covers Right Eye at cx=96, cy=59 when password focused) */}
          <motion.g
            id="right-robot-arm"
            initial={false}
            animate={rightArmAnimate}
            transition={rightArmTransition}
            style={{ transformOrigin: "104px 76px" }}
          >
            {/* Right Forearm Gauntlet (reaches from shoulder/elbow up to wrist) */}
            <path
              d="M128 110 C130 96, 121 78, 111 66 L96 72 C103 84, 111 98, 114 112 C118 115, 126 114, 128 110 Z"
              fill="url(#cyber_hand_grad)"
              stroke="#22D3EE"
              strokeWidth="1.8"
              strokeLinejoin="round"
            />
            {/* Forearm Energy Seam */}
            <path
              d="M121 106 C119 94, 113 82, 106 72"
              stroke="#38BDF8"
              strokeWidth="1.1"
              strokeOpacity="0.55"
              strokeLinecap="round"
            />
            {/* Wrist Articulation Band */}
            <path
              d="M113 67 L96 73"
              stroke="#38BDF8"
              strokeWidth="2.4"
              strokeLinecap="round"
            />
            {/* Right Palm / Back of Cyber-Glove (Centered directly over Right Eye 96, 59) */}
            <path
              d="M114 56 C114 48, 107 44, 97 45 L85 48 C81 50, 80 56, 82 63 L86 69 C90 73, 101 73, 109 69 C113 66, 114 61, 114 56 Z"
              fill="url(#cyber_hand_grad)"
              stroke="url(#cyber_body_trim)"
              strokeWidth="2"
              strokeLinejoin="round"
            />

            {/* Upward Thumbs-Up Extension when mood === "legitimate" and not password-focused */}
            {!isPasswordFocused && mood === "legitimate" ? (
              <g id="robot-thumbs-up">
                <rect
                  x="92"
                  y="28"
                  width="8.5"
                  height="19"
                  rx="4.2"
                  fill="#10B981"
                  stroke="#A7F3D0"
                  strokeWidth="1.6"
                />
                <circle cx="96.2" cy="33" r="2" fill="#FFFFFF" />
              </g>
            ) : (
              /* Standard Right Thumb (Outer visor edge) */
              <rect
                x="109"
                y="47"
                width="7"
                height="14"
                rx="3.5"
                transform="rotate(14 113 54)"
                fill="#1E293B"
                stroke="#22D3EE"
                strokeWidth="1.4"
              />
            )}

            {/* 3 Splayed Cyber Fingers over Right Eye */}
            <rect
              x="82"
              y="43"
              width="23"
              height="6.5"
              rx="3.2"
              transform="rotate(8 94 46)"
              fill="#1E293B"
              stroke="#22D3EE"
              strokeWidth="1.4"
            />
            <rect
              x="80"
              y="50.5"
              width="23"
              height="6.5"
              rx="3.2"
              transform="rotate(3 92 54)"
              fill="#1E293B"
              stroke="#22D3EE"
              strokeWidth="1.4"
            />
            <rect
              x="82"
              y="58"
              width="22"
              height="6.5"
              rx="3.2"
              transform="rotate(-3 93 61)"
              fill="#1E293B"
              stroke="#22D3EE"
              strokeWidth="1.4"
            />
            {/* Glowing Back-of-Hand Node & Knuckle Accents */}
            <circle
              cx="101"
              cy="60"
              r="3.8"
              fill="#082F49"
              stroke={!isPasswordFocused && mood === "legitimate" ? "#34D399" : "#22D3EE"}
              strokeWidth="1.3"
            />
            <circle
              cx="101"
              cy="60"
              r="1.6"
              fill={!isPasswordFocused && mood === "legitimate" ? "#6EE7B7" : "#67E8F9"}
            />

            {/* Friendly Wave Motion Lines when mood === "greeting" */}
            {!isPasswordFocused && mood === "greeting" && (
              <g id="greeting-wave-lines" opacity="0.85">
                <path
                  d="M118 38 C123 42, 124 50, 120 56"
                  stroke="#34D399"
                  strokeWidth="1.8"
                  strokeLinecap="round"
                  fill="none"
                />
                <path
                  d="M123 34 C129 40, 130 51, 125 59"
                  stroke="#22D3EE"
                  strokeWidth="1.4"
                  strokeLinecap="round"
                  fill="none"
                />
              </g>
            )}
          </motion.g>
        </g>
      </svg>
    </div>
  );
}

/**
 * Interactive, unobtrusive SCAMLENS AI Robot Guardian companion widget
 * rendered across the workspace in AppShell.
 */
export function RobotGuardianCompanion() {
  const state = useRobotGuardian();
  const { shouldReduceMotion } = useScamlensPreferences();
  const [minimized, setMinimized] = useState(false);

  // Trigger greeting wave if the user just signed in
  useEffect(() => {
    robotGuardian.consumePendingGreeting();
  }, []);

  const badgeToneClass =
    state.mood === "high_risk"
      ? "border-danger/45 bg-danger/10 text-danger dark:border-red-500/45 dark:bg-red-950/80 dark:text-red-200"
      : state.mood === "suspicious"
        ? "border-warning/45 bg-warning/10 text-warning dark:border-amber-500/45 dark:bg-amber-950/80 dark:text-amber-200"
        : state.mood === "legitimate" || state.mood === "greeting"
          ? "border-safe/45 bg-safe/10 text-safe dark:border-emerald-500/45 dark:bg-emerald-950/80 dark:text-emerald-200"
          : state.mood === "invalid"
            ? "border-purple-400/45 bg-purple-500/10 text-purple-700 dark:border-purple-500/45 dark:bg-purple-950/80 dark:text-purple-200"
            : "border-primary/35 bg-card/95 text-foreground dark:border-cyan-500/35 dark:bg-slate-950/90 dark:text-cyan-100";

  const MoodIcon =
    state.mood === "high_risk"
      ? ShieldAlert
      : state.mood === "suspicious"
        ? AlertTriangle
        : state.mood === "legitimate" || state.mood === "greeting"
          ? ShieldCheck
          : state.mood === "invalid"
            ? HelpCircle
            : Sparkles;

  return (
    <aside
      aria-label="SCAMLENS AI Robot Guardian"
      data-guardian-mood={state.mood}
      className="pointer-events-none fixed bottom-3 right-3 z-30 flex items-end gap-2 sm:bottom-4 sm:right-4"
    >
      <AnimatePresence initial={false}>
        {!minimized && (
          <motion.div
            key="guardian-status-bubble"
            initial={shouldReduceMotion ? false : { opacity: 0, y: 6, scale: 0.96 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={shouldReduceMotion ? { opacity: 0 } : { opacity: 0, y: 6, scale: 0.96 }}
            transition={{ duration: shouldReduceMotion ? 0 : 0.2 }}
            className={cn(
              "pointer-events-auto max-w-[220px] rounded-xl border px-3 py-2 shadow-lg backdrop-blur-md sm:max-w-[256px]",
              badgeToneClass
            )}
          >
            <div className="flex items-center justify-between gap-2">
              <span className="inline-flex items-center gap-1.5 text-[11px] font-bold tracking-tight">
                <MoodIcon className="size-3.5 shrink-0" />
                <span className="truncate">{state.label}</span>
              </span>
              <button
                type="button"
                onClick={() => setMinimized(true)}
                aria-label="Minimize Robot Guardian status"
                className="rounded p-0.5 opacity-70 transition-opacity hover:opacity-100"
                title="Minimize status bubble"
              >
                <ChevronDown className="size-3.5" />
              </button>
            </div>
            <p className="mt-0.5 line-clamp-2 text-[10px] leading-snug opacity-90">
              {state.detail}
            </p>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="relative flex flex-col items-center">
        {minimized && (
          <button
            type="button"
            onClick={() => setMinimized(false)}
            aria-label="Expand Robot Guardian status"
            title={`${state.label}: ${state.detail}`}
            className={cn(
              "pointer-events-auto mb-1 inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-semibold shadow-sm backdrop-blur-md",
              badgeToneClass
            )}
          >
            <MoodIcon className="size-3" />
            <ChevronUp className="size-3" />
          </button>
        )}
        <div className="pointer-events-none origin-bottom-right scale-90 rounded-2xl border border-primary/25 bg-card/85 p-1 shadow-[0_6px_24px_rgba(6,182,212,0.18)] backdrop-blur-md sm:scale-100 dark:border-cyan-500/30 dark:bg-slate-950/85">
          <CyberRobot mood={state.mood} size={64} />
        </div>
      </div>
    </aside>
  );
}
