import React, { useMemo, useState, useRef, useEffect, useCallback, Component, type ReactNode } from "react";
import { Link } from "@tanstack/react-router";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Globe2,
  Info,
  Link2,
  Mail,
  Maximize2,
  MessageSquareText,
  Minus,
  Pause,
  Play,
  Plus,
  Radar,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  X,
  Layers,
} from "lucide-react";
import { motion, AnimatePresence } from "motion/react";
import { Button } from "@/components/ui/button";
import { useScamlensPreferences } from "@/lib/scamlens-preferences";
import type { RiskLevel, ScanRecord } from "@/lib/scamlens-types";
import { cn } from "@/lib/utils";
import { Panel } from "./primitives";
import worldGeoData from "./world-geo-data.json";

type VectorFilter = "all" | "url" | "message" | "email";

export interface GeoCountry {
  id: string;
  name: string;
  d: string;
  cx: number;
  cy: number;
  bounds: [[number, number], [number, number]] | null;
}

interface ThreatRegionHub {
  id: string;
  name: string;
  shortCode: string;
  /** Actual projected coordinates in 960x500 Equal Earth space */
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

// Projected coordinates on Equal Earth (960 x 500)
const THREAT_HUBS: ThreatRegionHub[] = [
  {
    id: "na",
    name: "North America",
    shortCode: "NA-EAST",
    x: 306,
    y: 110,
    baseRisk: "High",
    baseThreatScore: 78,
    dominantVector: "url",
    primaryVectorsLabel: "Brand Credential Phishing & Toll SMS Lures",
    targetedSectors: ["Cloud SaaS", "Retail Banking", "Parcel Logistics"],
    topIndicators: ["Lookalike login domains (.xyz, .top)", "Urgent 2FA reset links", "Toll-road SMS payment lures"],
    tldKeywords: [".us", ".ca", ".com", "usps", "fedex", "irs", "chase", "wellsfargo", "toll"],
    sampleAction: { to: "/url-analyzer", label: "Inspect URL Vector" },
  },
  {
    id: "latam",
    name: "Latin America",
    shortCode: "LATAM",
    x: 361,
    y: 333,
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
    x: 480,
    y: 79,
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
    x: 621,
    y: 161,
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
    x: 674,
    y: 150,
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
    x: 757,
    y: 245,
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
    x: 819,
    y: 126,
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
    x: 850,
    y: 368,
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
  const arcLift = Math.min(85, Math.max(28, dist * 0.2));
  const cx = mx;
  const cy = Math.max(20, my - arcLift);
  return `M ${x1} ${y1} Q ${cx} ${cy} ${x2} ${y2}`;
}

interface MapErrorBoundaryProps {
  children: ReactNode;
}

interface MapErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

export class MapErrorBoundary extends Component<MapErrorBoundaryProps, MapErrorBoundaryState> {
  constructor(props: MapErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): MapErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error("GlobalThreatMap caught error:", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <Panel
          title="Global Scam Threat Map"
          description="Geographical threat intelligence visualization."
        >
          <div className="flex flex-col items-center justify-center rounded-xl border border-border bg-secondary/20 p-8 text-center">
            <Globe2 className="size-10 text-cyan-400 mb-3" />
            <h3 className="text-base font-bold text-foreground">Interactive Map Initializing</h3>
            <p className="mt-1 max-w-md text-xs text-muted-foreground">
              Unable to render world map view in this environment. All workspace scan analysis and security tools remain fully operational.
            </p>
            <Button
              variant="outline"
              size="sm"
              className="mt-4 text-xs"
              onClick={() => this.setState({ hasError: false, error: null })}
            >
              Retry Map View
            </Button>
          </div>
        </Panel>
      );
    }
    return this.props.children;
  }
}

function GlobalThreatMapInner({ records = [] }: { records?: ScanRecord[] }) {
  const { shouldReduceMotion } = useScamlensPreferences();

  const [vectorFilter, setVectorFilter] = useState<VectorFilter>("all");
  const [highRiskOnly, setHighRiskOnly] = useState<boolean>(false);
  const [liveFeedPaused, setLiveFeedPaused] = useState<boolean>(false);
  const [selectedHubId, setSelectedHubId] = useState<string>("sa");
  const [selectedCountry, setSelectedCountry] = useState<GeoCountry | null>(null);
  const [hoveredCountry, setHoveredCountry] = useState<GeoCountry | null>(null);
  const [tooltipPos, setTooltipPos] = useState<{ x: number; y: number } | null>(null);

  // Zoom and Pan State
  const [zoom, setZoom] = useState<number>(1);
  const [pan, setPan] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState<boolean>(false);
  const dragStartRef = useRef<{ x: number; y: number; panX: number; panY: number } | null>(null);
  const svgContainerRef = useRef<HTMLDivElement | null>(null);

  const animateMap = !shouldReduceMotion && !liveFeedPaused;

  // Zoom handlers
  const handleZoomIn = () => setZoom((z) => Math.min(4, +(z + 0.4).toFixed(1)));
  const handleZoomOut = () => setZoom((z) => Math.max(1, +(z - 0.4).toFixed(1)));
  const handleResetView = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
    setSelectedCountry(null);
  };

  // Mouse pan handling
  const handleMouseDown = (e: React.MouseEvent) => {
    if (e.button !== 0) return; // Only primary click
    setIsPanning(true);
    dragStartRef.current = {
      x: e.clientX,
      y: e.clientY,
      panX: pan.x,
      panY: pan.y,
    };
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (isPanning && dragStartRef.current) {
      const dx = (e.clientX - dragStartRef.current.x) / zoom;
      const dy = (e.clientY - dragStartRef.current.y) / zoom;
      setPan({
        x: Math.max(-400, Math.min(400, dragStartRef.current.panX + dx)),
        y: Math.max(-250, Math.min(250, dragStartRef.current.panY + dy)),
      });
    }

    // Update tooltip position relative to container
    if (svgContainerRef.current) {
      const rect = svgContainerRef.current.getBoundingClientRect();
      setTooltipPos({
        x: e.clientX - rect.left,
        y: e.clientY - rect.top,
      });
    }
  };

  const handleMouseUp = () => {
    setIsPanning(false);
    dragStartRef.current = null;
  };

  // Enriched workspace telemetry correlation
  const enrichedHubs = useMemo(() => {
    const scamRecords = records.filter(
      (r) => r.prediction_label === "Scam/Phishing" || r.prediction === "Scam/Phishing"
    );

    return THREAT_HUBS.map((hub) => {
      let matchedCount = 0;
      for (const rec of scamRecords) {
        const text = ((rec.content || "") + " " + (rec.explanation_summary || "")).toLowerCase();
        const hit = hub.tldKeywords.some((kw) => text.includes(kw));
        if (hit) matchedCount++;
      }

      const scoreBonus = Math.min(12, matchedCount * 3);
      const effectiveScore = Math.min(99, hub.baseThreatScore + scoreBonus);

      let effectiveRisk: RiskLevel = hub.baseRisk;
      if (effectiveScore >= 85) effectiveRisk = "Very High";
      else if (effectiveScore >= 70) effectiveRisk = "High";
      else if (effectiveScore >= 50) effectiveRisk = "Suspicious";
      else effectiveRisk = "Low";

      return {
        ...hub,
        matchedCount,
        effectiveScore,
        effectiveRisk,
      };
    });
  }, [records]);

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
    () => records.filter((r) => r.prediction_label === "Scam/Phishing" || r.prediction === "Scam/Phishing").length,
    [records]
  );

  // Filter country hits from workspace scans
  const countryWorkspaceMatches = useMemo(() => {
    if (!selectedCountry) return [];
    const nameLower = selectedCountry.name.toLowerCase();
    return records.filter((rec) => {
      const text = ((rec.content || "") + " " + (rec.explanation_summary || "")).toLowerCase();
      return text.includes(nameLower);
    });
  }, [selectedCountry, records]);

  const countries = worldGeoData.countries as GeoCountry[];

  return (
    <Panel
      title="Global Scam Threat Map"
      description="Geographically accurate world telemetry of phishing vectors, regional telemetry nodes, and workspace threat correlation."
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
                  "inline-flex min-h-8 items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-medium transition-colors cursor-pointer",
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
              "inline-flex min-h-8 items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-medium transition-colors cursor-pointer",
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
              className="inline-flex min-h-8 items-center gap-1.5 rounded-lg border border-border bg-secondary/35 px-2.5 py-1 text-xs font-medium text-muted-foreground transition-colors hover:border-primary/25 hover:text-foreground cursor-pointer"
            >
              {liveFeedPaused ? <Play className="size-3.5 text-primary" /> : <Pause className="size-3.5 text-primary" />}
              <span>{liveFeedPaused ? "Paused" : "Live"}</span>
            </button>
          )}
        </div>
      }
    >
      <div className="grid gap-5 xl:grid-cols-[1.55fr_1fr]">
        {/* Left: Interactive Real World Threat Map Canvas */}
        <div className="flex flex-col justify-between rounded-xl border border-border bg-secondary/20 p-3 sm:p-4">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2 text-xs">
            <div className="flex items-center gap-2">
              <span className="inline-flex items-center gap-1.5 rounded-md border border-primary/25 bg-primary/10 px-2 py-0.5 font-mono text-[11px] font-semibold text-primary">
                <Radar className={cn("size-3.5", animateMap && "animate-spin")} style={{ animationDuration: "8s" }} />
                REAL WORLD MAP
              </span>
              <span className="text-muted-foreground hidden sm:inline">
                Hover or click any country for geography • Drag to pan • Scroll/buttons to zoom
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

          {/* Map Viewport Container */}
          <div
            ref={svgContainerRef}
            className={cn(
              "relative aspect-[16/9] sm:aspect-[2/1] w-full overflow-hidden rounded-lg border border-border/80 bg-[#030712] shadow-inner select-none",
              isPanning ? "cursor-grabbing" : "cursor-grab"
            )}
            onMouseDown={handleMouseDown}
            onMouseMove={handleMouseMove}
            onMouseUp={handleMouseUp}
            onMouseLeave={handleMouseUp}
          >
            {/* Interactive SVG Render */}
            <svg
              viewBox="0 0 960 500"
              className="h-full w-full pointer-events-auto"
              role="img"
              aria-label="Real Geographical World Map with Natural Earth Country Boundaries and Threat Intelligence Hubs"
            >
              <defs>
                {/* Cyber Grid Pattern */}
                <pattern id="scamlens-real-grid" width="40" height="40" patternUnits="userSpaceOnUse">
                  <path
                    d="M 40 0 L 0 0 0 40"
                    fill="none"
                    stroke="rgba(56, 189, 248, 0.05)"
                    strokeWidth="0.8"
                  />
                </pattern>
                {/* Deep Cyber Radial Glow */}
                <radialGradient id="scamlens-ocean-glow" cx="50%" cy="50%" r="65%">
                  <stop offset="0%" stopColor="rgba(14, 165, 233, 0.08)" />
                  <stop offset="70%" stopColor="rgba(2, 6, 23, 0.95)" />
                  <stop offset="100%" stopColor="rgba(1, 4, 14, 1)" />
                </radialGradient>
              </defs>

              {/* Ocean Background & Coordinate Grid */}
              <rect width="960" height="500" fill="url(#scamlens-ocean-glow)" />
              <rect width="960" height="500" fill="url(#scamlens-real-grid)" />

              {/* Transform group for Pan and Zoom */}
              <g
                transform={`translate(${pan.x * zoom + (1 - zoom) * 480}, ${
                  pan.y * zoom + (1 - zoom) * 250
                }) scale(${zoom})`}
                style={{ transformOrigin: "480px 250px", transition: isPanning ? "none" : "transform 0.15s ease-out" }}
              >
                {/* Global Sphere Boundary */}
                <path
                  d={worldGeoData.spherePath}
                  fill="none"
                  stroke="rgba(56, 189, 248, 0.15)"
                  strokeWidth="1.2"
                />

                {/* Natural Earth 10° Graticule Network */}
                <path
                  d={worldGeoData.graticulePath}
                  fill="none"
                  stroke="rgba(56, 189, 248, 0.04)"
                  strokeWidth="0.6"
                  strokeDasharray="2 3"
                />

                {/* Real Natural Earth Country Outlines */}
                <g id="world-countries-layer">
                  {countries.map((country) => {
                    const isSelected = selectedCountry?.id === country.id;
                    const isHovered = hoveredCountry?.id === country.id;

                    return (
                      <path
                        key={country.id}
                        d={country.d}
                        fill={
                          isSelected
                            ? "rgba(6, 182, 212, 0.35)"
                            : isHovered
                            ? "rgba(14, 165, 233, 0.28)"
                            : "rgba(15, 23, 42, 0.85)"
                        }
                        stroke={
                          isSelected
                            ? "#22d3ee"
                            : isHovered
                            ? "#38bdf8"
                            : "rgba(56, 189, 248, 0.22)"
                        }
                        strokeWidth={isSelected ? 1.6 / zoom : isHovered ? 1.2 / zoom : 0.6 / zoom}
                        strokeLinejoin="round"
                        className="transition-colors duration-150 cursor-pointer outline-none"
                        onMouseEnter={() => setHoveredCountry(country)}
                        onMouseLeave={() => setHoveredCountry(null)}
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedCountry(country);
                        }}
                      />
                    );
                  })}
                </g>

                {/* Threat Attack Corridors (Curved Geodesic Bezier Paths) */}
                <g id="corridors-layer">
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
                          strokeOpacity={isHighlighted ? 0.6 : 0.2}
                          strokeWidth={isHighlighted ? 2 / zoom : 1 / zoom}
                          strokeDasharray="4 4"
                        />
                        {animateMap && (
                          <motion.path
                            d={pathD}
                            fill="none"
                            stroke={colors.dot}
                            strokeWidth={isHighlighted ? 2.5 / zoom : 1.5 / zoom}
                            strokeLinecap="round"
                            initial={{ pathLength: 0.16, pathOffset: 0, opacity: isHighlighted ? 0.95 : 0.55 }}
                            animate={{ pathOffset: [0, 1] }}
                            transition={{
                              duration: isHighlighted ? 2.4 : 3.6,
                              repeat: Infinity,
                              ease: "linear",
                            }}
                          />
                        )}
                      </g>
                    );
                  })}
                </g>

                {/* Interactive Regional Telemetry Hub Nodes */}
                <g id="hubs-layer">
                  {visibleHubs.map((hub) => {
                    const isSelected = activeHub.id === hub.id;
                    const colors = riskColorClasses(hub.effectiveRisk);

                    return (
                      <g
                        key={hub.id}
                        transform={`translate(${hub.x}, ${hub.y})`}
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedHubId(hub.id);
                        }}
                        className="cursor-pointer focus:outline-none"
                        tabIndex={0}
                        role="button"
                        aria-label={`${hub.name} node (${hub.effectiveRisk})`}
                      >
                        {/* Outer Pulse Ring */}
                        {animateMap && (
                          <motion.circle
                            r={isSelected ? 18 / zoom : 13 / zoom}
                            fill="none"
                            stroke={colors.dot}
                            strokeWidth={isSelected ? 1.8 / zoom : 1.2 / zoom}
                            initial={{ scale: 0.7, opacity: 0.85 }}
                            animate={{ scale: 1.5, opacity: 0 }}
                            transition={{
                              duration: isSelected ? 1.8 : 2.6,
                              repeat: Infinity,
                              ease: "easeOut",
                            }}
                          />
                        )}

                        {/* Selection Halo */}
                        {isSelected && (
                          <circle
                            r={13 / zoom}
                            fill={colors.glow}
                            stroke={colors.dot}
                            strokeWidth={1.2 / zoom}
                            strokeDasharray="3 2"
                          />
                        )}

                        {/* Core Node Circle */}
                        <circle
                          r={isSelected ? 6 / zoom : 4.5 / zoom}
                          fill={colors.dot}
                          stroke="#030712"
                          strokeWidth={1.8 / zoom}
                        />

                        {/* HUD Node Label Badge */}
                        <g transform={`translate(0, ${-12 / zoom}) scale(${1 / zoom})`}>
                          <rect
                            x="-28"
                            y="-11"
                            width="56"
                            height="14"
                            rx="3"
                            fill={isSelected ? "rgba(3, 7, 18, 0.95)" : "rgba(3, 7, 18, 0.8)"}
                            stroke={isSelected ? colors.dot : "rgba(148, 163, 184, 0.4)"}
                            strokeWidth={isSelected ? "1.2" : "0.75"}
                          />
                          <text
                            x="0"
                            y="-1.5"
                            textAnchor="middle"
                            fill={isSelected ? "#ffffff" : "#cbd5e1"}
                            fontSize="8"
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
              </g>
            </svg>

            {/* Hover Tooltip (Country Info under cursor) */}
            {hoveredCountry && tooltipPos && (
              <div
                className="pointer-events-none absolute z-20 -translate-x-1/2 -translate-y-full rounded-md border border-cyan-500/40 bg-slate-950/95 px-2.5 py-1 text-xs text-white shadow-lg backdrop-blur-xs font-mono"
                style={{
                  left: tooltipPos.x,
                  top: tooltipPos.y - 12,
                }}
              >
                <div className="flex items-center gap-1.5 font-bold text-cyan-300">
                  <Globe2 className="size-3 text-cyan-400" />
                  <span>{hoveredCountry.name}</span>
                </div>
                <span className="text-[10px] text-slate-400">Click to view territory telemetry</span>
              </div>
            )}

            {/* Floating Map Zoom / Pan Controls */}
            <div className="absolute right-3 top-3 z-10 flex flex-col items-center gap-1.5 rounded-lg border border-border/80 bg-slate-950/85 p-1 backdrop-blur-xs shadow-md">
              <button
                type="button"
                onClick={handleZoomIn}
                title="Zoom in"
                className="flex size-7 items-center justify-center rounded text-slate-300 hover:bg-slate-800 hover:text-white transition-colors cursor-pointer"
              >
                <Plus className="size-3.5" />
              </button>
              <button
                type="button"
                onClick={handleZoomOut}
                title="Zoom out"
                className="flex size-7 items-center justify-center rounded text-slate-300 hover:bg-slate-800 hover:text-white transition-colors cursor-pointer"
              >
                <Minus className="size-3.5" />
              </button>
              <div className="h-px w-4 bg-slate-800 my-0.5" />
              <button
                type="button"
                onClick={handleResetView}
                title="Reset map view"
                className="flex size-7 items-center justify-center rounded text-slate-300 hover:bg-slate-800 hover:text-white transition-colors cursor-pointer"
              >
                <RotateCcw className="size-3.5" />
              </button>
            </div>

            {/* Zoom Indicator Pill */}
            <div className="absolute left-3 top-3 z-10 rounded border border-slate-800 bg-slate-950/80 px-2 py-0.5 font-mono text-[10px] text-slate-400 backdrop-blur-xs">
              SCALE {zoom.toFixed(1)}x
            </div>

            {/* Bottom Overlay Telemetry Bar */}
            <div className="pointer-events-none absolute inset-x-2.5 bottom-2.5 flex flex-wrap items-center justify-between gap-2 rounded-md border border-slate-800/90 bg-slate-950/85 px-3 py-1.5 text-[11px] text-slate-300 backdrop-blur-xs">
              <span className="flex items-center gap-1.5 font-mono">
                <Activity className="size-3.5 text-sky-400" />
                Active Corridors: <strong className="text-white">{visibleCorridors.length}</strong>
              </span>
              <span className="font-mono text-[10px] text-slate-400 hidden sm:inline">
                Natural Earth 1:110m Boundaries • 177 Sovereign Territories
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
                    "inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium transition-colors cursor-pointer",
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

        {/* Right: Regional & Country Threat Intelligence Inspector */}
        <div className="flex flex-col justify-between rounded-xl border border-border bg-secondary/20 p-4 sm:p-5">
          <div className="space-y-4">
            {/* Country Inspection Banner when a country is selected */}
            {selectedCountry ? (
              <div className="rounded-xl border border-cyan-500/40 bg-slate-950/70 p-3.5 space-y-2.5">
                <div className="flex items-start justify-between gap-2 border-b border-slate-800 pb-2.5">
                  <div>
                    <span className="font-mono text-[10px] font-semibold uppercase tracking-wider text-cyan-400">
                      SELECTED TERRITORY
                    </span>
                    <h4 className="text-base font-bold text-white mt-0.5">{selectedCountry.name}</h4>
                  </div>
                  <button
                    type="button"
                    onClick={() => setSelectedCountry(null)}
                    className="rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-white transition-colors cursor-pointer"
                    title="Close country inspector"
                  >
                    <X className="size-4" />
                  </button>
                </div>

                {/* Separation of Workspace vs Global Intelligence */}
                <div className="space-y-2 text-xs">
                  <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-2.5">
                    <span className="font-semibold text-slate-300 block mb-1">
                      A. Workspace Scan Correlation
                    </span>
                    {countryWorkspaceMatches.length > 0 ? (
                      <p className="text-cyan-300 font-mono text-[11px]">
                        ✓ {countryWorkspaceMatches.length} detected scan(s) in local history contain keywords associated with {selectedCountry.name}.
                      </p>
                    ) : (
                      <p className="text-slate-400 text-[11px]">
                        No scans in this workspace currently reference {selectedCountry.name}. Scans logged via Message or URL Analyzer will automatically correlate here.
                      </p>
                    )}
                  </div>

                  <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-2.5 text-amber-200/90">
                    <span className="font-semibold text-amber-300 block mb-1 flex items-center gap-1.5">
                      <Info className="size-3.5 text-amber-400" />
                      B. External Threat Feed Status
                    </span>
                    <p className="text-[11px] leading-relaxed text-slate-300">
                      Global threat intelligence feed not connected. SCAMLENS displays accurate geographical boundaries without synthesizing fake external national cyberattack counts.
                    </p>
                  </div>
                </div>
              </div>
            ) : null}

            {/* Regional Hub Inspector Header */}
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
                  Regional Index: <strong className="text-foreground">{activeHub.effectiveScore}/100</strong>
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
                ? `Correlated with ${totalWorkspaceScams} detected scam scan${totalWorkspaceScams === 1 ? "" : "s"} in workspace.`
                : "Showing regional heuristic signatures. Perform scans to correlate live hits."}
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

export function GlobalThreatMap({ records = [] }: { records?: ScanRecord[] }) {
  return (
    <MapErrorBoundary>
      <GlobalThreatMapInner records={records} />
    </MapErrorBoundary>
  );
}
