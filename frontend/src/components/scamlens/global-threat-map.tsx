import { useMemo, useState } from "react";
import { Link } from "@tanstack/react-router";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Globe2,
  Link2,
  Mail,
  MessageSquareText,
  Pause,
  Play,
  Radar,
  ShieldAlert,
} from "lucide-react";
import { motion } from "motion/react";
import { Button } from "@/components/ui/button";
import { useScamlensPreferences } from "@/lib/scamlens-preferences";
import type { RiskLevel, ScanRecord } from "@/lib/scamlens-types";
import { cn } from "@/lib/utils";
import { Panel } from "./primitives";

type VectorFilter = "all" | "url" | "message" | "email";

interface ThreatRegionHub {
  id: string;
  name: string;
  shortCode: string;
  /** SVG viewBox (0..1000 x 0..500) coordinates */
  x: number;
  y: number;
  baseRisk: RiskLevel;
  baseThreatScore: number;
  dominantVector: "url" | "message" | "email";
  primaryVectorsLabel: string;
  targetedSectors: string[];
  topIndicators: string[];
  tldKeywords: string[];
  sampleAction: {
    to: "/message-analyzer" | "/url-analyzer";
    label: string;
  };
}

interface ThreatCorridor {
  id: string;
  fromId: string;
  toId: string;
  vector: "url" | "message" | "email";
  risk: RiskLevel;
  label: string;
}

const THREAT_HUBS: ThreatRegionHub[] = [
  {
    id: "na",
    name: "North America",
    shortCode: "NA-EAST",
    x: 225,
    y: 175,
    baseRisk: "High",
    baseThreatScore: 78,
    dominantVector: "url",
    primaryVectorsLabel: "Brand Credential Phishing & Toll SMS Lures",
    targetedSectors: ["Cloud SaaS", "Retail Banking", "Parcel Logistics"],
    topIndicators: ["Lookalike login domains (.xyz, .top)", "Urgent 2FA reset links", "Toll-road SMS payment lures"],
    tldKeywords: [".us", ".ca", ".com", "usps", "fedex", "irs", " chase", "wellsfargo", "toll"],
    sampleAction: { to: "/url-analyzer", label: "Inspect URL Vector" },
  },
  {
    id: "latam",
    name: "Latin America",
    shortCode: "LATAM",
    x: 315,
    y: 350,
    baseRisk: "Suspicious",
    baseThreatScore: 62,
    dominantVector: "message",
    primaryVectorsLabel: "Instant Messaging Banking & PIX Social Engineering",
    targetedSectors: ["Mobile Payments", "Telecom", "E-Commerce"],
    topIndicators: ["Shortened redirect chains", "Fake account tax suspension", "WhatsApp/SMS verification bait"],
    tldKeywords: [".br", ".mx", ".ar", ".cl", ".co", "banco", "pix", "entrega"],
    sampleAction: { to: "/message-analyzer", label: "Inspect Message Vector" },
  },
  {
    id: "eu",
    name: "Europe & UK",
    shortCode: "EU-WEST",
    x: 495,
    y: 145,
    baseRisk: "High",
    baseThreatScore: 74,
    dominantVector: "email",
    primaryVectorsLabel: "SEPA Invoice Redirection & Customs Phishing",
    targetedSectors: ["Enterprise Finance", "Postal Customs", "Digital Tax"],
    topIndicators: ["Reply-To domain mismatch", "Homograph IDN domains", "Fake customs clearance fee"],
    tldKeywords: [".uk", ".de", ".fr", ".eu", ".nl", "hmrc", "dhl", "royalmail", "iban", "sepa"],
    sampleAction: { to: "/message-analyzer", label: "Inspect Email Vector" },
  },
  {
    id: "mea",
    name: "Middle East & Africa",
    shortCode: "MEA",
    x: 545,
    y: 265,
    baseRisk: "High",
    baseThreatScore: 71,
    dominantVector: "email",
    primaryVectorsLabel: "Advance-Fee BEC & Telecom Wallet Phishing",
    targetedSectors: ["Cross-Border Trade", "Mobile Money", "Courier Services"],
    topIndicators: ["VIP executive impersonation", "Free webmail business claims", "Urgent wire transfer instructions"],
    tldKeywords: [".ae", ".za", ".ng", ".ke", ".sa", "wire", "beneficiary", "customs"],
    sampleAction: { to: "/message-analyzer", label: "Inspect Message Vector" },
  },
  {
    id: "sa",
    name: "South Asia",
    shortCode: "APAC-IN",
    x: 690,
    y: 235,
    baseRisk: "Very High",
    baseThreatScore: 88,
    dominantVector: "message",
    primaryVectorsLabel: "KYC Suspension SMS, UPI Collect & APK Lures",
    targetedSectors: ["UPI & Digital Banking", "Electricity / Utility KYC", "Tax & Identity Portals"],
    topIndicators: ["PAN/KYC immediate block warning", "Malicious shortlinks & .apk links", "Fake cashback / lottery collect request"],
    tldKeywords: [".in", "kyc", "upi", "pan", "aadhaar", "sbi", "hdfc", "icici", "otp", "rs.", "inr"],
    sampleAction: { to: "/message-analyzer", label: "Analyze SMS / KYC Vector" },
  },
  {
    id: "sea",
    name: "Southeast Asia",
    shortCode: "ASEAN",
    x: 768,
    y: 280,
    baseRisk: "Very High",
    baseThreatScore: 84,
    dominantVector: "url",
    primaryVectorsLabel: "Job Task Scams & Crypto Investment Portals",
    targetedSectors: ["Digital Exchanges", "Remote Recruitment", "Super-App Wallets"],
    topIndicators: ["Newly registered .vip / .cc domains", "High-return task recruitment", "Fake exchange security alert"],
    tldKeywords: [".sg", ".my", ".id", ".ph", ".vn", ".th", ".vip", ".cc", "usdt", "crypto", "task"],
    sampleAction: { to: "/url-analyzer", label: "Scan Suspicious URL" },
  },
  {
    id: "ea",
    name: "East Asia",
    shortCode: "APAC-EA",
    x: 815,
    y: 185,
    baseRisk: "High",
    baseThreatScore: 76,
    dominantVector: "url",
    primaryVectorsLabel: "E-Commerce Credential Harvesting & Smishing",
    targetedSectors: ["E-Commerce Marketplaces", "Consumer FinTech", "Gaming & Digital Assets"],
    topIndicators: ["IP-literal & punycode phishing hosts", "Fake failed delivery notification", "Account freeze verification"],
    tldKeywords: [".jp", ".kr", ".cn", ".tw", ".hk", ".top", ".xyz", "login-verify"],
    sampleAction: { to: "/url-analyzer", label: "Inspect URL Vector" },
  },
  {
    id: "oc",
    name: "Oceania",
    shortCode: "ANZ",
    x: 845,
    y: 385,
    baseRisk: "Suspicious",
    baseThreatScore: 59,
    dominantVector: "message",
    primaryVectorsLabel: "GovID / MyGov Impersonation & Toll Smishing",
    targetedSectors: ["Government Portals", "Toll & Transport", "Telecom Billing"],
    topIndicators: ["Spoofed sender alphanumeric ID", "Refund claim credential harvest", "Missed parcel re-booking link"],
    tldKeywords: [".au", ".nz", "mygov", "auspost", "linkt"],
    sampleAction: { to: "/message-analyzer", label: "Inspect Message Vector" },
  },
];

const THREAT_CORRIDORS: ThreatCorridor[] = [
  { id: "c1", fromId: "sea", toId: "sa", vector: "message", risk: "Very High", label: "SMS / KYC Smishing Wave" },
  { id: "c2", fromId: "ea", toId: "na", vector: "url", risk: "High", label: "Credential Phishing Domains" },
  { id: "c3", fromId: "mea", toId: "eu", vector: "email", risk: "High", label: "BEC & Invoice Redirection" },
  { id: "c4", fromId: "sa", toId: "eu", vector: "url", risk: "High", label: "Parcel & Customs Lure URLs" },
  { id: "c5", fromId: "sea", toId: "oc", vector: "message", risk: "Suspicious", label: "Toll & GovID Smishing" },
  { id: "c6", fromId: "na", toId: "latam", vector: "url", risk: "Suspicious", label: "FinTech Login Spoofing" },
  { id: "c7", fromId: "eu", toId: "na", vector: "email", risk: "High", label: "SaaS OAuth Token Phishing" },
  { id: "c8", fromId: "sea", toId: "ea", vector: "url", risk: "Very High", label: "Crypto Drainer Kits" },
];

/** Stylized, lightweight SVG continent paths in a 1000x500 equirectangular projection */
const WORLD_LANDMASS_PATHS = [
  // North America
  "M 75 85 L 185 70 L 295 85 L 320 135 L 275 195 L 245 235 L 210 250 L 175 225 L 130 175 L 85 130 Z",
  // Greenland
  "M 325 52 L 395 45 L 410 85 L 355 102 L 320 82 Z",
  // South America
  "M 255 265 L 330 275 L 368 330 L 345 415 L 302 455 L 278 410 L 252 330 Z",
  // Europe
  "M 442 88 L 535 72 L 585 102 L 572 158 L 525 175 L 462 172 L 438 135 Z",
  // Africa
  "M 445 192 L 545 188 L 605 235 L 592 325 L 555 405 L 505 412 L 478 345 L 438 265 Z",
  // Mainland Asia & Middle East
  "M 588 85 L 745 68 L 895 92 L 915 162 L 855 235 L 795 278 L 735 262 L 685 278 L 632 238 L 585 195 L 575 132 Z",
  // Southeast Asia & Archipelago
  "M 748 285 L 832 282 L 862 328 L 785 338 L 742 315 Z",
  // Japan
  "M 862 155 L 882 165 L 874 205 L 854 195 Z",
  // Australia & New Zealand
  "M 778 355 L 878 350 L 902 405 L 858 438 L 785 425 L 768 388 Z",
  "M 918 425 L 940 435 L 930 462 L 910 452 Z",
] as const;

function riskColorClasses(risk: RiskLevel) {
  switch (risk) {
    case "Very High":
      return {
        badge: "border-danger/35 bg-danger/15 text-danger",
        dot: "#ef4444",
        glow: "rgba(239, 68, 68, 0.45)",
      };
    case "High":
      return {
        badge: "border-orange-500/35 bg-orange-500/15 text-orange-400",
        dot: "#f97316",
        glow: "rgba(249, 115, 22, 0.4)",
      };
    case "Suspicious":
      return {
        badge: "border-warning/35 bg-warning/15 text-warning",
        dot: "#f59e0b",
        glow: "rgba(245, 158, 11, 0.38)",
      };
    default:
      return {
        badge: "border-safe/35 bg-safe/15 text-safe",
        dot: "#22c55e",
        glow: "rgba(34, 197, 94, 0.35)",
      };
  }
}

function buildCurvedPath(x1: number, y1: number, x2: number, y2: number): string {
  const mx = (x1 + x2) / 2;
  const my = (y1 + y2) / 2;
  const dx = x2 - x1;
  const dy = y2 - y1;
  const dist = Math.hypot(dx, dy);
  const arcLift = Math.min(95, Math.max(32, dist * 0.22));
  const cx = mx;
  const cy = Math.max(28, my - arcLift);
  return `M ${x1} ${y1} Q ${cx} ${cy} ${x2} ${y2}`;
}

export function GlobalThreatMap({ records }: { records: ScanRecord[] }) {
  const { shouldReduceMotion } = useScamlensPreferences();
  const [selectedHubId, setSelectedHubId] = useState<string>("sa");
  const [vectorFilter, setVectorFilter] = useState<VectorFilter>("all");
  const [highRiskOnly, setHighRiskOnly] = useState<boolean>(false);
  const [liveFeedPaused, setLiveFeedPaused] = useState<boolean>(false);

  const animateMap = !shouldReduceMotion && !liveFeedPaused;

  // Correlate real workspace scan history with regional hubs when records are present
  const enrichedHubs = useMemo(() => {
    const scamRecords = records.filter((r) => r.prediction === "Scam/Phishing");

    return THREAT_HUBS.map((hub, idx) => {
      let matchedCount = 0;
      for (const rec of scamRecords) {
        if (vectorFilter !== "all" && rec.inputType !== vectorFilter) continue;
        const previewLower = rec.inputPreview.toLowerCase();
        const matchesKeyword = hub.tldKeywords.some((kw) => previewLower.includes(kw));
        const matchesVectorFallback =
          !matchesKeyword &&
          rec.inputType === hub.dominantVector &&
          Number(String(rec.id).replace(/\D/g, "") || idx) % THREAT_HUBS.length === idx;

        if (matchesKeyword || matchesVectorFallback) {
          matchedCount += 1;
        }
      }

      const boostedScore = Math.min(99, hub.baseThreatScore + matchedCount * 3);
      const effectiveRisk: RiskLevel =
        boostedScore >= 82
          ? "Very High"
          : boostedScore >= 70
            ? "High"
            : boostedScore >= 45
              ? "Suspicious"
              : hub.baseRisk;

      return {
        ...hub,
        matchedCount,
        effectiveScore: boostedScore,
        effectiveRisk,
      };
    });
  }, [records, vectorFilter]);

  const visibleHubs = useMemo(() => {
    return enrichedHubs.filter((hub) => {
      if (vectorFilter !== "all" && hub.dominantVector !== vectorFilter && hub.matchedCount === 0) {
        return false;
      }
      if (highRiskOnly && hub.effectiveRisk !== "High" && hub.effectiveRisk !== "Very High") {
        return false;
      }
      return true;
    });
  }, [enrichedHubs, vectorFilter, highRiskOnly]);

  const activeHub = useMemo(() => {
    const found = visibleHubs.find((h) => h.id === selectedHubId) ?? visibleHubs[0] ?? enrichedHubs[0];
    return found!;
  }, [visibleHubs, selectedHubId, enrichedHubs]);

  const visibleCorridors = useMemo(() => {
    const visibleIds = new Set(visibleHubs.map((h) => h.id));
    return THREAT_CORRIDORS.filter((c) => {
      if (!visibleIds.has(c.fromId) || !visibleIds.has(c.toId)) return false;
      if (vectorFilter !== "all" && c.vector !== vectorFilter) return false;
      if (highRiskOnly && c.risk !== "High" && c.risk !== "Very High") return false;
      return true;
    });
  }, [visibleHubs, vectorFilter, highRiskOnly]);

  const hubMap = useMemo(() => {
    const map = new Map<string, (typeof enrichedHubs)[number]>();
    for (const h of enrichedHubs) {
      map.set(h.id, h);
    }
    return map;
  }, [enrichedHubs]);

  const totalWorkspaceScams = useMemo(
    () => records.filter((r) => r.prediction === "Scam/Phishing").length,
    [records]
  );

  return (
    <Panel
      title="Global Scam Threat Map"
      description="Interactive telemetry of global phishing corridors, regional scam vectors, and workspace threat correlation."
      delay={0.06}
      action={
        <div className="flex flex-wrap items-center gap-1.5">
          {(
            [
              { id: "all", label: "All Vectors", icon: Globe2 },
              { id: "url", label: "URLs", icon: Link2 },
              { id: "message", label: "SMS / Chat", icon: MessageSquareText },
              { id: "email", label: "Email", icon: Mail },
            ] as const
          ).map((item) => {
            const Icon = item.icon;
            const active = vectorFilter === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setVectorFilter(item.id)}
                aria-pressed={active}
                className={cn(
                  "inline-flex min-h-8 items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-medium transition-colors",
                  active
                    ? "border-primary/40 bg-primary/15 text-primary"
                    : "border-border bg-secondary/35 text-muted-foreground hover:border-primary/25 hover:text-foreground"
                )}
              >
                <Icon className="size-3.5" />
                <span>{item.label}</span>
              </button>
            );
          })}

          <button
            type="button"
            onClick={() => setHighRiskOnly((prev) => !prev)}
            aria-pressed={highRiskOnly}
            className={cn(
              "inline-flex min-h-8 items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-medium transition-colors",
              highRiskOnly
                ? "border-danger/40 bg-danger/15 text-danger"
                : "border-border bg-secondary/35 text-muted-foreground hover:border-danger/30 hover:text-foreground"
            )}
          >
            <AlertTriangle className="size-3.5" />
            <span>High Risk Only</span>
          </button>

          {!shouldReduceMotion && (
            <button
              type="button"
              onClick={() => setLiveFeedPaused((prev) => !prev)}
              aria-pressed={liveFeedPaused}
              title={liveFeedPaused ? "Resume map telemetry animation" : "Pause map telemetry animation"}
              className="inline-flex min-h-8 items-center gap-1.5 rounded-lg border border-border bg-secondary/35 px-2.5 py-1 text-xs font-medium text-muted-foreground transition-colors hover:border-primary/25 hover:text-foreground"
            >
              {liveFeedPaused ? <Play className="size-3.5 text-primary" /> : <Pause className="size-3.5 text-primary" />}
              <span>{liveFeedPaused ? "Paused" : "Live"}</span>
            </button>
          )}
        </div>
      }
    >
      <div className="grid gap-5 xl:grid-cols-[1.55fr_1fr]">
        {/* Left: Interactive World Threat Map Canvas */}
        <div className="flex flex-col justify-between rounded-xl border border-border bg-secondary/20 p-3 sm:p-4">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2 text-xs">
            <div className="flex items-center gap-2">
              <span className="inline-flex items-center gap-1.5 rounded-md border border-primary/25 bg-primary/10 px-2 py-0.5 font-mono text-[11px] font-semibold text-primary">
                <Radar className={cn("size-3.5", animateMap && "animate-spin")} style={{ animationDuration: "6s" }} />
                THREAT RADAR
              </span>
              <span className="text-muted-foreground">
                Select any regional node to inspect active scam vectors and indicators
              </span>
            </div>
            <div className="flex items-center gap-3 text-[11px] text-muted-foreground">
              <span className="inline-flex items-center gap-1.5">
                <span className="size-2 rounded-full bg-danger" /> Very High
              </span>
              <span className="inline-flex items-center gap-1.5">
                <span className="size-2 rounded-full bg-orange-500" /> High
              </span>
              <span className="inline-flex items-center gap-1.5">
                <span className="size-2 rounded-full bg-warning" /> Suspicious
              </span>
            </div>
          </div>

          <div className="relative aspect-[2/1] w-full overflow-hidden rounded-lg border border-border/80 bg-slate-950/90 shadow-inner">
            <svg
              viewBox="0 0 1000 500"
              className="h-full w-full select-none"
              role="img"
              aria-label="Global Scam Threat Map showing regional phishing and scam telemetry hubs"
            >
              <defs>
                <pattern id="scamlens-map-grid" width="50" height="50" patternUnits="userSpaceOnUse">
                  <path
                    d="M 50 0 L 0 0 0 50"
                    fill="none"
                    stroke="rgba(56, 189, 248, 0.08)"
                    strokeWidth="1"
                  />
                </pattern>
                <radialGradient id="scamlens-map-glow" cx="50%" cy="50%" r="60%">
                  <stop offset="0%" stopColor="rgba(14, 165, 233, 0.14)" />
                  <stop offset="100%" stopColor="rgba(2, 6, 23, 0)" />
                </radialGradient>
              </defs>

              {/* Cyber Grid & Equator / Tropics Reference Lines */}
              <rect width="1000" height="500" fill="url(#scamlens-map-grid)" />
              <rect width="1000" height="500" fill="url(#scamlens-map-glow)" />
              <line x1="0" y1="250" x2="1000" y2="250" stroke="rgba(56, 189, 248, 0.14)" strokeDasharray="6 6" />
              <line x1="0" y1="145" x2="1000" y2="145" stroke="rgba(56, 189, 248, 0.07)" strokeDasharray="4 8" />
              <line x1="0" y1="355" x2="1000" y2="355" stroke="rgba(56, 189, 248, 0.07)" strokeDasharray="4 8" />

              {/* Stylized Continents */}
              <g>
                {WORLD_LANDMASS_PATHS.map((d, i) => (
                  <path
                    key={i}
                    d={d}
                    fill="rgba(30, 41, 59, 0.72)"
                    stroke="rgba(56, 189, 248, 0.24)"
                    strokeWidth="1.25"
                    strokeLinejoin="round"
                  />
                ))}
              </g>

              {/* Threat Attack Corridors */}
              <g>
                {visibleCorridors.map((corridor) => {
                  const fromHub = hubMap.get(corridor.fromId);
                  const toHub = hubMap.get(corridor.toId);
                  if (!fromHub || !toHub) return null;
                  const pathD = buildCurvedPath(fromHub.x, fromHub.y, toHub.x, toHub.y);
                  const isHighlighted =
                    activeHub.id === corridor.fromId || activeHub.id === corridor.toId;
                  const colors = riskColorClasses(corridor.risk);

                  return (
                    <g key={corridor.id}>
                      <path
                        d={pathD}
                        fill="none"
                        stroke={colors.dot}
                        strokeOpacity={isHighlighted ? 0.55 : 0.22}
                        strokeWidth={isHighlighted ? 2.2 : 1.25}
                        strokeDasharray="5 5"
                      />
                      {animateMap && (
                        <motion.path
                          d={pathD}
                          fill="none"
                          stroke={colors.dot}
                          strokeWidth={isHighlighted ? 2.8 : 1.8}
                          strokeLinecap="round"
                          initial={{ pathLength: 0.18, pathOffset: 0, opacity: isHighlighted ? 0.95 : 0.55 }}
                          animate={{ pathOffset: [0, 1] }}
                          transition={{
                            duration: isHighlighted ? 2.6 : 3.8,
                            repeat: Infinity,
                            ease: "linear",
                          }}
                        />
                      )}
                    </g>
                  );
                })}
              </g>

              {/* Interactive Regional Hub Nodes */}
              <g>
                {visibleHubs.map((hub) => {
                  const isSelected = activeHub.id === hub.id;
                  const colors = riskColorClasses(hub.effectiveRisk);

                  return (
                    <g
                      key={hub.id}
                      transform={`translate(${hub.x}, ${hub.y})`}
                      onClick={() => setSelectedHubId(hub.id)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" || e.key === " ") {
                          e.preventDefault();
                          setSelectedHubId(hub.id);
                        }
                      }}
                      tabIndex={0}
                      role="button"
                      aria-label={`${hub.name} (${hub.effectiveRisk} risk, threat index ${hub.effectiveScore})`}
                      aria-pressed={isSelected}
                      className="cursor-pointer focus:outline-none"
                    >
                      {/* Outer pulse ring */}
                      {animateMap && (
                        <motion.circle
                          r={isSelected ? 22 : 16}
                          fill="none"
                          stroke={colors.dot}
                          strokeWidth={isSelected ? 2 : 1.5}
                          initial={{ scale: 0.65, opacity: 0.85 }}
                          animate={{ scale: 1.55, opacity: 0 }}
                          transition={{
                            duration: isSelected ? 1.8 : 2.6,
                            repeat: Infinity,
                            ease: "easeOut",
                          }}
                        />
                      )}

                      {/* Selection halo */}
                      {isSelected && (
                        <circle
                          r="15"
                          fill={colors.glow}
                          stroke={colors.dot}
                          strokeWidth="1.5"
                          strokeDasharray="3 2"
                        />
                      )}

                      {/* Core node */}
                      <circle
                        r={isSelected ? 7.5 : 6}
                        fill={colors.dot}
                        stroke="#020617"
                        strokeWidth="2"
                      />

                      {/* Compact HUD label */}
                      <g transform="translate(0, -14)">
                        <rect
                          x="-34"
                          y="-14"
                          width="68"
                          height="16"
                          rx="4"
                          fill={isSelected ? "rgba(15, 23, 42, 0.95)" : "rgba(15, 23, 42, 0.78)"}
                          stroke={isSelected ? colors.dot : "rgba(148, 163, 184, 0.3)"}
                          strokeWidth={isSelected ? "1.2" : "0.8"}
                        />
                        <text
                          x="0"
                          y="-3"
                          textAnchor="middle"
                          fill={isSelected ? "#f8fafc" : "#cbd5e1"}
                          fontSize="9.5"
                          fontFamily="monospace"
                          fontWeight="700"
                        >
                          {hub.shortCode}
                        </text>
                      </g>
                    </g>
                  );
                })}
              </g>
            </svg>

            {/* Bottom Overlay Telemetry Bar */}
            <div className="pointer-events-none absolute inset-x-2.5 bottom-2.5 flex flex-wrap items-center justify-between gap-2 rounded-md border border-slate-800/90 bg-slate-950/85 px-3 py-1.5 text-[11px] text-slate-300 backdrop-blur-xs">
              <span className="flex items-center gap-1.5 font-mono">
                <Activity className="size-3.5 text-sky-400" />
                Active Corridors: <strong className="text-white">{visibleCorridors.length}</strong>
              </span>
              <span className="font-mono">
                Workspace Scams Mapped:{" "}
                <strong className="text-sky-400">{totalWorkspaceScams}</strong>
              </span>
            </div>
          </div>

          {/* Region Quick-Select Pill Strip */}
          <div className="mt-3 flex flex-wrap items-center gap-1.5">
            {visibleHubs.map((hub) => {
              const isSelected = activeHub.id === hub.id;
              const colors = riskColorClasses(hub.effectiveRisk);
              return (
                <button
                  key={hub.id}
                  type="button"
                  onClick={() => setSelectedHubId(hub.id)}
                  className={cn(
                    "inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium transition-colors",
                    isSelected
                      ? "border-primary/50 bg-primary/15 text-foreground shadow-2xs"
                      : "border-border bg-card/60 text-muted-foreground hover:border-primary/30 hover:text-foreground"
                  )}
                >
                  <span className="size-2 rounded-full" style={{ backgroundColor: colors.dot }} />
                  <span>{hub.name}</span>
                  <span className="font-mono text-[10px] opacity-80">{hub.effectiveScore}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Right: Regional Threat Intelligence Inspector */}
        <div className="flex flex-col justify-between rounded-xl border border-border bg-secondary/20 p-4 sm:p-5">
          <div className="space-y-4">
            <div className="flex items-start justify-between gap-3 border-b border-border pb-3.5">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-primary">
                    {activeHub.shortCode} REGION
                  </span>
                  {activeHub.matchedCount > 0 && (
                    <span className="rounded bg-primary/15 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-primary">
                      +{activeHub.matchedCount} workspace {activeHub.matchedCount === 1 ? "hit" : "hits"}
                    </span>
                  )}
                </div>
                <h3 className="mt-1 text-base font-bold text-foreground sm:text-lg">{activeHub.name}</h3>
                <p className="mt-0.5 text-xs text-muted-foreground">{activeHub.primaryVectorsLabel}</p>
              </div>

              <div className="text-right">
                <span
                  className={cn(
                    "inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-[11px] font-semibold",
                    riskColorClasses(activeHub.effectiveRisk).badge
                  )}
                >
                  <ShieldAlert className="size-3" />
                  {activeHub.effectiveRisk}
                </span>
                <p className="mt-1.5 font-mono text-xs text-muted-foreground">
                  Threat Index: <strong className="text-foreground">{activeHub.effectiveScore}/100</strong>
                </p>
              </div>
            </div>

            {/* Targeted Sectors */}
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                Primary Targeted Sectors
              </p>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {activeHub.targetedSectors.map((sector) => (
                  <span
                    key={sector}
                    className="rounded-md border border-border bg-card px-2.5 py-1 text-xs font-medium text-foreground"
                  >
                    {sector}
                  </span>
                ))}
              </div>
            </div>

            {/* Dominant Threat Signatures */}
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                Active Regional Indicators & Signatures
              </p>
              <ul className="mt-2 space-y-1.5">
                {activeHub.topIndicators.map((indicator) => (
                  <li
                    key={indicator}
                    className="flex items-start gap-2 rounded-lg border border-border/70 bg-card/60 px-3 py-2 text-xs text-foreground"
                  >
                    <span className="mt-1 size-1.5 shrink-0 rounded-full bg-primary" />
                    <span>{indicator}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          <div className="mt-5 flex flex-wrap items-center justify-between gap-2 border-t border-border pt-3.5">
            <span className="text-[11px] text-muted-foreground">
              {totalWorkspaceScams > 0
                ? `Correlated with ${totalWorkspaceScams} detected scam/phishing scan${totalWorkspaceScams === 1 ? "" : "s"} in history.`
                : "Showing baseline regional scam intelligence. Run a scan to correlate live hits."}
            </span>
            <Button asChild size="sm" variant="outline" className="min-h-8 text-xs">
              <Link to={activeHub.sampleAction.to}>
                {activeHub.sampleAction.label}
                <ArrowUpRight className="ml-1 size-3.5" />
              </Link>
            </Button>
          </div>
        </div>
      </div>
    </Panel>
  );
}
