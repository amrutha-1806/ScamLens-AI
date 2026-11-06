import { motion } from "motion/react";
import { cn } from "@/lib/utils";
import { useScamlensPreferences } from "@/lib/scamlens-preferences";

interface ScamLensIconProps {
  size?: number | string;
  className?: string;
  glow?: boolean;
  animate?: boolean;
}

export function ScamLensIcon({
  size = 36,
  className,
  glow = true,
  animate = false,
}: ScamLensIconProps) {
  const { shouldReduceMotion } = useScamlensPreferences();
  const dimension = typeof size === "number" ? `${size}px` : size;

  return (
    <div
      style={{ width: dimension, height: dimension }}
      className={cn("relative grid place-items-center shrink-0", className)}
    >
      {glow && (
        <div className="pointer-events-none absolute -inset-1 rounded-full bg-cyan-400/25 blur-sm dark:bg-cyan-500/20" />
      )}
      <svg
        viewBox="0 0 100 100"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="size-full drop-shadow-[0_2px_8px_rgba(6,182,212,0.35)]"
      >
        <defs>
          <linearGradient id="scamlens_shield_bg" x1="50" y1="6" x2="50" y2="94" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#0E1D38" />
            <stop offset="50%" stopColor="#091427" />
            <stop offset="100%" stopColor="#040914" />
          </linearGradient>

          <linearGradient id="scamlens_shield_border" x1="16" y1="8" x2="84" y2="92" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#22D3EE" />
            <stop offset="35%" stopColor="#14B8A6" />
            <stop offset="70%" stopColor="#0EA5E9" />
            <stop offset="100%" stopColor="#06B6D4" />
          </linearGradient>

          <linearGradient id="scamlens_lens_ring" x1="28" y1="28" x2="72" y2="72" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#22D3EE" />
            <stop offset="50%" stopColor="#14B8A6" />
            <stop offset="100%" stopColor="#0284C7" />
          </linearGradient>

          <radialGradient id="scamlens_pupil_glow" cx="50" cy="48" r="14" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#FFFFFF" />
            <stop offset="28%" stopColor="#67E8F9" />
            <stop offset="70%" stopColor="#06B6D4" stopOpacity="0.8" />
            <stop offset="100%" stopColor="#091427" stopOpacity="0" />
          </radialGradient>
        </defs>

        {/* Shield Silhouette */}
        <path
          d="M50 7 C72 7, 85 14, 85 28 C85 60, 68 83, 50 93 C32 83, 15 60, 15 28 C15 14, 28 7, 50 7 Z"
          fill="url(#scamlens_shield_bg)"
          stroke="url(#scamlens_shield_border)"
          strokeWidth="3.2"
          strokeLinejoin="round"
        />

        {/* Inner Shield Trim Line */}
        <path
          d="M50 13 C68 13, 79 19, 79 30 C79 57, 64 76, 50 85 C36 76, 21 57, 21 30 C21 19, 32 13, 50 13 Z"
          stroke="#06B6D4"
          strokeOpacity="0.28"
          strokeWidth="1.2"
          strokeDasharray="3 2"
        />

        {/* Scanning Sensor Outer Ring */}
        <circle
          cx="50"
          cy="48"
          r="23"
          stroke="url(#scamlens_lens_ring)"
          strokeWidth="2.5"
          strokeDasharray="28 4 6 4"
          strokeLinecap="round"
        />

        {/* Reticle Crosshair Ticks */}
        <line x1="50" y1="21" x2="50" y2="28" stroke="#22D3EE" strokeWidth="2" strokeLinecap="round" />
        <line x1="50" y1="68" x2="50" y2="75" stroke="#22D3EE" strokeWidth="2" strokeLinecap="round" />
        <line x1="23" y1="48" x2="30" y2="48" stroke="#22D3EE" strokeWidth="2" strokeLinecap="round" />
        <line x1="70" y1="48" x2="77" y2="48" stroke="#22D3EE" strokeWidth="2" strokeLinecap="round" />

        {/* Inner Optical Ring */}
        <circle
          cx="50"
          cy="48"
          r="14"
          stroke="#14B8A6"
          strokeWidth="1.8"
          strokeOpacity="0.9"
        />

        {/* Iris Core Glow & White Center Focal Dot */}
        <circle cx="50" cy="48" r="8" fill="url(#scamlens_pupil_glow)" />
        <circle cx="50" cy="48" r="3.5" fill="#FFFFFF" />

        {/* Specular Lens Reflection Arc */}
        <path
          d="M37 36 A19 19 0 0 1 58 30"
          stroke="#FFFFFF"
          strokeWidth="1.8"
          strokeLinecap="round"
          strokeOpacity="0.75"
        />
      </svg>
    </div>
  );
}

interface ScamLensLogoProps {
  size?: "sm" | "md" | "lg" | "xl";
  showTagline?: boolean;
  showText?: boolean;
  className?: string;
  interactive?: boolean;
}

export function ScamLensLogo({
  size = "md",
  showTagline = true,
  showText = true,
  className,
  interactive = false,
}: ScamLensLogoProps) {
  const { shouldReduceMotion } = useScamlensPreferences();

  const iconSizes = {
    sm: 28,
    md: 36,
    lg: 48,
    xl: 60,
  };

  const textStyles = {
    sm: {
      title: "text-sm",
      badge: "text-[10px] px-1.5 py-0.5",
      tagline: "text-[10px]",
    },
    md: {
      title: "text-base font-bold",
      badge: "text-[10px] px-1.5 py-0.5",
      tagline: "text-[11px]",
    },
    lg: {
      title: "text-xl font-extrabold",
      badge: "text-xs px-2 py-0.5",
      tagline: "text-xs",
    },
    xl: {
      title: "text-2xl font-extrabold sm:text-3xl",
      badge: "text-xs px-2.5 py-1",
      tagline: "text-sm",
    },
  };

  const style = textStyles[size];

  const content = (
    <div className={cn("flex items-center gap-3 select-none", className)}>
      <ScamLensIcon size={iconSizes[size]} glow={size !== "sm"} />

      {showText && (
        <div className="flex flex-col min-w-0">
          <div className="flex items-center gap-1.5">
            <span
              className={cn(
                "tracking-tight text-foreground font-mono font-bold uppercase",
                style.title
              )}
            >
              SCAMLENS
            </span>
            <span
              className={cn(
                "rounded-md border border-cyan-400/40 bg-gradient-to-r from-sky-600/30 to-teal-600/30 font-mono font-bold text-cyan-300 shadow-[0_0_10px_rgba(6,182,212,0.25)]",
                style.badge
              )}
            >
              AI
            </span>
          </div>
          {showTagline && (
            <p className={cn("truncate font-medium text-cyan-500 dark:text-cyan-400/90", style.tagline)}>
              See the risk before you click.
            </p>
          )}
        </div>
      )}
    </div>
  );

  if (interactive && !shouldReduceMotion) {
    return (
      <motion.div
        whileHover={{ scale: 1.02 }}
        whileTap={{ scale: 0.98 }}
        transition={{ duration: 0.16 }}
      >
        {content}
      </motion.div>
    );
  }

  return content;
}
