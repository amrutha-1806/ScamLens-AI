import { z } from "zod";
import type {
  AlertReviewRequest,
  AlertReviewStatus,
  AlertsResponse,
  AnalysisResult,
  BatchAnalysisResponse,
  EmailAnalysisRequest,
  HealthStatus,
  MessageAnalysisRequest,
  ModelInfo,
  ScanRecord,
  UrlAnalysisRequest,
} from "./scamlens-types";

const messageSchema = z.object({
  message: z.string().trim().min(3).max(10000),
  user_id: z.string().optional(),
});
const urlSchema = z.object({
  url: z.string().trim().max(2048),
  user_id: z.string().optional(),
});
const emailSchema = z.object({
  sender: z.string().trim().min(3).max(500),
  subject: z.string().trim().max(1000).optional(),
  body: z.string().trim().min(3).max(50000),
  user_id: z.string().optional(),
});

const resultSchema = z.object({
  prediction: z.string(),
  risk_level: z.string(),
  // Backend sends risk_probability as a 0–1 fraction and risk_score as 0–100.
  risk_probability: z.number().optional().default(0),
  risk_score: z.number().optional().default(0),
  indicators: z.array(z.string()).optional().default([]),
  guidance: z.string().optional().default(""),
  model: z.string().optional().default("Random Forest"),
  scan_id: z.union([z.number(), z.string()]).nullish(),
  timestamp: z.string().nullish(),
  explainability: z.any().optional(),
  language_info: z.any().optional(),
  url_intelligence: z.any().optional(),
  sender_analysis: z.any().optional(),
  subject_analysis: z.any().optional(),
  embedded_urls: z.array(z.any()).nullish(),
}).passthrough();

// The backend persists records with a wider field set than the analyze endpoints
// (content / prediction_label / scam_probability / explanation_summary), so every
// documented alias is accepted and normalized without inventing missing values.
// Note: Database columns can be null (e.g. user_id, review_notes, reviewed_at),
// so fields use .nullish() to accept both null and undefined safely.
const historyItemSchema = z.object({
  id: z.union([z.string(), z.number()]).transform(String),
  timestamp: z.string().nullish().transform((val) => val ?? ""),
  input_type: z.string().nullish(),
  type: z.string().nullish(),
  content: z.string().nullish(),
  input_preview: z.string().nullish(),
  message: z.string().nullish(),
  url: z.string().nullish(),
  prediction: z.string().nullish(),
  prediction_label: z.string().nullish(),
  risk_level: z.string().nullish(),
  risk_probability: z.number().nullish(),
  scam_probability: z.number().nullish(),
  risk_score: z.number().nullish(),
  indicators: z.union([z.array(z.string()), z.string(), z.any()]).nullish(),
  guidance: z.string().nullish(),
  explanation_summary: z.string().nullish(),
  model: z.string().nullish(),
  scan_id: z.union([z.number(), z.string()]).nullish(),
  user_id: z.string().nullish(),
  review_status: z.string().nullish(),
  review_notes: z.string().nullish(),
  reviewed_at: z.string().nullish(),
}).passthrough();

type HistoryItem = z.infer<typeof historyItemSchema>;

function mapHistoryRecord(item: HistoryItem): ScanRecord {
  const rawPrediction = item.prediction ?? item.prediction_label ?? "";
  const lowered = rawPrediction.toLowerCase();
  const prediction = (lowered.includes("scam") || lowered.includes("phish") || lowered.includes("spam")
    ? "Scam/Phishing"
    : lowered.includes("legit") || lowered.includes("ham")
      ? "Legitimate"
      : rawPrediction) as ScanRecord["prediction"];
  const rawFraction = item.risk_probability ?? item.scam_probability;
  // Backend probabilities are 0–1 fractions; a 0–100 value is only scaled for display.
  const fraction = rawFraction === undefined || rawFraction === null ? undefined : rawFraction > 1 ? rawFraction / 100 : rawFraction;
  const rawType = (item.input_type ?? item.type ?? "").toLowerCase();
  const inputType: ScanRecord["inputType"] = rawType === "url" ? "url" : rawType === "email" ? "email" : "message";

  let indicators: string[] = [];
  if (Array.isArray(item.indicators)) {
    indicators = item.indicators.map(String);
  } else if (typeof item.indicators === "string") {
    try {
      const parsed = JSON.parse(item.indicators);
      indicators = Array.isArray(parsed) ? parsed.map(String) : [item.indicators];
    } catch {
      indicators = item.indicators ? [item.indicators] : [];
    }
  }

  return {
    id: item.id,
    timestamp: item.timestamp ?? "",
    inputType,
    inputPreview: item.input_preview ?? item.content ?? item.message ?? item.url ?? "",
    prediction,
    riskLevel: (item.risk_level ?? "Low") as ScanRecord["riskLevel"],
    riskProbability: fraction === undefined ? (item.risk_score ?? 0) : fraction * 100,
    riskScore: item.risk_score ?? (fraction !== undefined ? fraction * 100 : 0),
    riskFraction: fraction,
    indicators,
    guidance: item.guidance ?? item.explanation_summary ?? "",
    model: item.model ?? "Random Forest",
    scanId: typeof item.scan_id === "number" ? item.scan_id : item.scan_id ? Number(item.scan_id) : undefined,
    userId: item.user_id ?? undefined,
    reviewStatus: (item.review_status as AlertReviewStatus | undefined) ?? "unreviewed",
    reviewNotes: item.review_notes ?? undefined,
    reviewedAt: item.reviewed_at ?? undefined,
  };
}


const healthSchema = z.object({
  status: z.string().default("healthy"),
  healthy: z.boolean().optional(),
}).passthrough();

const modelInfoSchema = z.object({
  // Backend uses model_name; older/future shapes may use model.
  model_name: z.string().optional(),
  model: z.string().optional(),
  dataset: z.string().optional(),
  dataset_size: z.number().optional(),
  classes: z.array(z.string()).optional(),
  // Backend returns feature_extraction as a single string; also accept a features array.
  feature_extraction: z.string().optional(),
  features: z.array(z.string()).optional(),
  candidate_models: z.array(z.string()).optional(),
  supported_analysis_types: z.array(z.string()).optional(),
  // Metrics may include string annotations like N/A or unit labels alongside numbers.
  metrics: z.record(z.union([z.number(), z.string()])).optional(),
  confusion_matrix: z.array(z.array(z.number())).optional(),
  version: z.string().optional(),
}).passthrough();

/**
 * Normalizes and sanitizes the configured API base URL.
 * Extracts the valid HTTP/HTTPS origin, safely discarding any inadvertent trailing text
 * (such as clipboard artifacts like "copy value", "%20copy%20value", extra whitespace, or trailing slashes),
 * without hardcoding.
 */
export function resolveApiBaseUrl(raw: string | undefined): string | undefined {
  if (!raw || typeof raw !== "string") return undefined;

  let cleaned = raw.trim();
  if (!cleaned) return undefined;

  // 1. Decode URI encodings repeatedly (handles single "%20" and double "%2520" encodings)
  for (let i = 0; i < 3; i++) {
    try {
      const decoded = decodeURIComponent(cleaned);
      if (decoded === cleaned) break;
      cleaned = decoded.trim();
    } catch {
      break;
    }
  }

  // 2. Normalize any remaining literal '%20' sequences to spaces
  cleaned = cleaned.replace(/%20/gi, " ").trim();

  // 3. Discard any trailing text after whitespace (e.g. "https://domain.com copy value")
  cleaned = cleaned.split(/\s+/)[0] || "";

  // 4. Remove common accidental clipboard text/suffixes even if concatenated without spaces
  cleaned = cleaned.replace(/(?:copy[\s_.-]*value|copy)$/i, "").trim();

  // 5. Strip trailing slashes
  cleaned = cleaned.replace(/\/+$/, "");

  if (!cleaned) return undefined;

  // 6. Prepend https:// if protocol is missing
  if (!/^https?:\/\//i.test(cleaned)) {
    cleaned = `https://${cleaned}`;
  }

  // 7. Validate and extract clean origin + pathname using URL
  try {
    const url = new URL(cleaned);
    if (url.protocol !== "http:" && url.protocol !== "https:") return undefined;
    const path = url.pathname === "/" ? "" : url.pathname.replace(/\/+$/, "");
    return `${url.origin}${path}`;
  } catch {
    // If URL parsing threw, strictly extract valid protocol + hostname + optional port
    const match = cleaned.match(/^(https?:\/\/[a-zA-Z0-9.-]+(?::\d+)?)/i);
    if (match) {
      return match[1].replace(/\/+$/, "");
    }
    return undefined; // NEVER return an invalid or malformed URL string!
  }
}

// Resolve API base URL from client build environment (import.meta.env) or server/SSR (process.env)
const rawApiBaseUrl: string | undefined = (
  (typeof import.meta !== "undefined" && import.meta.env && (import.meta.env.VITE_API_BASE_URL ?? import.meta.env["VITE_API_BASE_URL"])) ||
  (typeof process !== "undefined" && process.env && (process.env.VITE_API_BASE_URL ?? process.env.API_BASE_URL))
) as string | undefined;

const apiBaseUrl = resolveApiBaseUrl(rawApiBaseUrl);

/**
 * Dynamically resolves the normalized API base URL.
 * Checks import.meta.env (client Vite), process.env (SSR / Nitro), and module fallback.
 */
export function getCleanBaseUrl(): string {
  const raw: string | undefined = (
    (typeof import.meta !== "undefined" && import.meta.env && (import.meta.env.VITE_API_BASE_URL ?? import.meta.env["VITE_API_BASE_URL"])) ||
    (typeof process !== "undefined" && process.env && (process.env.VITE_API_BASE_URL ?? process.env.API_BASE_URL)) ||
    rawApiBaseUrl
  ) as string | undefined;

  const clean = resolveApiBaseUrl(raw) ?? apiBaseUrl;
  if (!clean) {
    throw new ScamlensApiError("Backend unavailable");
  }
  return clean;
}

/**
 * Builds a clean, fully-qualified API URL for the given endpoint path.
 * Guarantees no duplicate slashes, no 'copy value', and valid URL format.
 */
export function buildApiUrl(path: string): string {
  const base = getCleanBaseUrl();
  const cleanPath = path.startsWith("/") ? path : `/${path}`;
  const full = `${base}${cleanPath}`;
  try {
    const u = new URL(full);
    return u.href;
  } catch {
    return full;
  }
}

export class ScamlensApiError extends Error {
  constructor(message: string, public status?: number) { super(message); this.name = "ScamlensApiError"; }
}

function mapResult(value: z.infer<typeof resultSchema>): AnalysisResult {
  const rawProb = value.risk_probability ?? (value.risk_score ? value.risk_score / 100 : 0);
  const fraction = rawProb > 1 ? rawProb / 100 : rawProb;
  const rawPred = value.prediction ?? "";
  const predLower = rawPred.toLowerCase();
  const prediction: AnalysisResult["prediction"] =
    predLower.includes("scam") || predLower.includes("phish") || predLower.includes("spam")
      ? "Scam/Phishing"
      : "Legitimate";
  const rawLevel = value.risk_level ?? "Low";
  const riskLevel: AnalysisResult["riskLevel"] =
    rawLevel === "Very High" || rawLevel === "High" || rawLevel === "Suspicious" || rawLevel === "Low"
      ? rawLevel
      : fraction >= 0.75 ? "High" : fraction >= 0.4 ? "Suspicious" : "Low";

  // Normalize embedded_urls to string array if elements are objects
  const embeddedUrls = Array.isArray(value.embedded_urls)
    ? value.embedded_urls.map((item: unknown) => {
        if (typeof item === "string") return item;
        if (item && typeof item === "object") {
          const obj = item as Record<string, unknown>;
          return String(obj.input ?? obj.normalized_url ?? obj.url ?? JSON.stringify(obj));
        }
        return String(item);
      })
    : undefined;

  return {
    prediction,
    riskLevel,
    riskProbability: fraction * 100,
    riskScore: value.risk_score ?? fraction * 100,
    riskFraction: fraction,
    indicators: value.indicators ?? [],
    guidance: value.guidance ?? "",
    model: value.model ?? "Random Forest",
    scanId: typeof value.scan_id === "number" ? value.scan_id : value.scan_id ? Number(value.scan_id) : undefined,
    timestamp: value.timestamp ?? undefined,
    explainability: value.explainability,
    languageInfo: value.language_info,
    urlIntelligence: value.url_intelligence,
    senderAnalysis: value.sender_analysis,
    subjectAnalysis: value.subject_analysis,
    embeddedUrls,
  };
}

async function errorMessage(response: Response) {
  try {
    const data = await response.json() as { detail?: unknown; message?: unknown };
    if (typeof data.detail === "string") return data.detail;
    if (typeof data.message === "string") return data.message;
  } catch { /* Use the safe status fallback below. */ }
  return response.status >= 500 ? "Backend unavailable" : "The backend could not complete this request.";
}

async function request(path: string, init?: RequestInit): Promise<unknown> {
  const url = buildApiUrl(path);
  let response: Response;
  try {
    response = await fetch(url, { ...init, headers: { Accept: "application/json", ...init?.headers } });
  } catch { throw new ScamlensApiError("Backend unavailable"); }
  if (!response.ok) throw new ScamlensApiError(await errorMessage(response), response.status);
  try { return await response.json(); } catch { throw new ScamlensApiError("The backend returned an invalid response.", response.status); }
}

async function postJson(path: string, body: unknown) {
  return request(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}

function parseResult(data: unknown) {
  const parsed = resultSchema.safeParse(data);
  if (!parsed.success) {
    console.warn("[scamlens] /api/analyze validation error:", parsed.error.issues);
    throw new ScamlensApiError("The backend response did not match the expected analysis format.");
  }
  return mapResult(parsed.data);
}

export const scamlensApi = {
  get isConfigured(): boolean {
    try {
      return Boolean(getCleanBaseUrl());
    } catch {
      return false;
    }
  },
  get baseUrl(): string | undefined {
    try {
      return getCleanBaseUrl();
    } catch {
      return undefined;
    }
  },
  analyzeMessage: async (input: MessageAnalysisRequest) => parseResult(await postJson("/api/analyze/message", messageSchema.parse(input))),
  analyzeUrl: async (input: UrlAnalysisRequest) => parseResult(await postJson("/api/analyze/url", urlSchema.parse(input))),
  analyzeEmail: async (input: EmailAnalysisRequest) => parseResult(await postJson("/api/analyze/email", emailSchema.parse(input))),
  getAlerts: async (status: string = "all", limit: number = 50): Promise<AlertsResponse> => {
    const query = new URLSearchParams({ status, limit: String(limit) });
    const raw = await request(`/api/alerts?${query.toString()}`);
    const alertsSchema = z.object({
      count: z.number().optional(),
      alerts: z.array(historyItemSchema),
      unreviewed_count: z.number().optional(),
      high_count: z.number().optional(),
      very_high_count: z.number().optional(),
    }).passthrough();
    const parsed = alertsSchema.safeParse(raw);
    if (!parsed.success) {
      console.warn("[scamlens] /api/alerts parse issues:", parsed.error.issues);
      throw new ScamlensApiError("The backend response did not match the expected alerts format.");
    }
    const d = parsed.data;
    const mapped = d.alerts.map(mapHistoryRecord);
    return {
      count: mapped.length,
      alerts: mapped,
      unreviewed_count: d.unreviewed_count ?? mapped.filter(a => a.reviewStatus === "unreviewed").length,
      high_count: d.high_count ?? mapped.filter(a => a.riskLevel === "High").length,
      very_high_count: d.very_high_count ?? mapped.filter(a => a.riskLevel === "Very High").length,
    };
  },
  reviewAlert: async (scanId: number | string, req: AlertReviewRequest): Promise<{ success: boolean; scan_id: number; review_status: string }> => {
    const raw = await postJson(`/api/alerts/${scanId}/review`, req);
    return raw as { success: boolean; scan_id: number; review_status: string };
  },
  downloadIncidentPdf: async (scanId: number | string): Promise<{ filename: string; size: number }> => {
    let response: Response;
    try {
      const url = buildApiUrl(`/api/reports/incident-pdf/${scanId}`);
      response = await fetch(url, {
        method: "GET",
        headers: { Accept: "application/pdf" },
      });
    } catch {
      throw new ScamlensApiError("Backend unavailable");
    }
    if (!response.ok) {
      throw new ScamlensApiError(await errorMessage(response), response.status);
    }
    const blob = await response.blob();
    if (!blob || blob.size === 0) {
      throw new ScamlensApiError("The backend returned an empty report file.");
    }
    const disposition = response.headers.get("Content-Disposition") ?? "";
    const match = /filename="?([^";]+)"?/i.exec(disposition);
    const filename = match?.[1] ?? `SCAMLENS_Incident_SL${scanId}.pdf`;
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setTimeout(() => URL.revokeObjectURL(url), 5000);
    return { filename, size: blob.size };
  },
  analyzeBatch: async (file: File, column?: string): Promise<BatchAnalysisResponse> => {
    const form = new FormData();
    form.append("file", file);
    if (column && column.trim().length > 0) {
      form.append("column", column.trim());
    }
    const raw = await request("/api/analyze/batch", { method: "POST", body: form });
    const batchObjectSchema = z.object({
      results: z.array(historyItemSchema),
      total: z.number().optional(),
      total_rows: z.number().optional(),
      processed_rows: z.number().optional(),
      failed_rows: z.number().optional(),
      selected_column: z.string().optional(),
      errors: z.array(z.string()).optional(),
    }).passthrough();
    const container = z.union([z.array(historyItemSchema), batchObjectSchema]).safeParse(raw);
    if (!container.success) throw new ScamlensApiError("The backend response did not match the expected batch format.");
    if (Array.isArray(container.data)) {
      const mapped = container.data.map(mapHistoryRecord);
      return {
        results: mapped,
        total: mapped.length,
        totalRows: mapped.length,
        processedRows: mapped.length,
        failedRows: 0,
      };
    }
    const d = container.data;
    const mapped = d.results.map(mapHistoryRecord);
    return {
      results: mapped,
      total: d.total ?? mapped.length,
      totalRows: d.total_rows ?? d.total ?? mapped.length,
      processedRows: d.processed_rows ?? mapped.length,
      failedRows: d.failed_rows ?? 0,
      selectedColumn: d.selected_column,
      errors: d.errors ?? [],
    };
  },
  downloadReportPdf: async (params: { scope: string; days: number; limit?: number }): Promise<{ filename: string; size: number }> => {
    const query = new URLSearchParams({
      scope: params.scope,
      days: String(params.days),
      limit: String(params.limit ?? 100),
    });
    let response: Response;
    try {
      const url = buildApiUrl(`/api/reports/pdf?${query.toString()}`);
      response = await fetch(url, {
        method: "GET",
        headers: { Accept: "application/pdf" },
      });
    } catch {
      throw new ScamlensApiError("Backend unavailable");
    }
    if (!response.ok) {
      throw new ScamlensApiError(await errorMessage(response), response.status);
    }
    const blob = await response.blob();
    if (!blob || blob.size === 0) {
      throw new ScamlensApiError("The backend returned an empty report file.");
    }
    const disposition = response.headers.get("Content-Disposition") ?? "";
    const match = /filename="?([^";]+)"?/i.exec(disposition);
    const filename = match?.[1] ?? `SCAMLENS_AI_Security_Report_${new Date().toISOString().slice(0, 10)}.pdf`;
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setTimeout(() => URL.revokeObjectURL(url), 5000);
    return { filename, size: blob.size };
  },
  getHistory: async (userIdOrContext?: unknown): Promise<ScanRecord[]> => {
    const userId = typeof userIdOrContext === "string" && userIdOrContext.trim().length > 0
      ? userIdOrContext.trim()
      : undefined;
    const path = userId ? `/api/history?user_id=${encodeURIComponent(userId)}` : "/api/history";
    const raw = await request(path);
    // The backend returns { count, total, records, items }; plain arrays and
    // { history } are also accepted so every documented container shape works.
    const parsed = z.union([
      z.array(historyItemSchema),
      z.object({ records: z.array(historyItemSchema) }).passthrough(),
      z.object({ items: z.array(historyItemSchema) }).passthrough(),
      z.object({ history: z.array(historyItemSchema) }).passthrough(),
    ]).safeParse(raw);
    if (!parsed.success) {
      console.warn("[scamlens] /api/history parse issues:", parsed.error.issues);
      throw new ScamlensApiError("The backend response did not match the expected history format.");
    }
    const data = parsed.data as HistoryItem[] | { records?: HistoryItem[]; items?: HistoryItem[]; history?: HistoryItem[] };
    const values = Array.isArray(data) ? data : data.records ?? data.items ?? data.history ?? [];
    return values.map(mapHistoryRecord);
  },

  getHealth: async (): Promise<HealthStatus> => {
    const parsed = healthSchema.safeParse(await request("/api/health"));
    if (!parsed.success) throw new ScamlensApiError("Backend unavailable");
    const normalized = parsed.data.status.toLowerCase();
    return { status: parsed.data.status, healthy: parsed.data.healthy ?? ["ok", "healthy", "ready", "connected"].includes(normalized) };
  },
  getModelInfo: async (): Promise<ModelInfo> => {
    const raw = await request("/api/model-info");
    const parsed = modelInfoSchema.safeParse(raw);
    if (!parsed.success) {
      // Log the Zod issues to help diagnose future backend changes.
      console.warn("[scamlens] /api/model-info parse issues:", parsed.error.issues);
      throw new ScamlensApiError("The backend response did not match the expected model information format.");
    }
    const d = parsed.data;
    return {
      // Prefer model_name (actual backend field) then fall back to model.
      model: d.model_name ?? d.model,
      dataset: d.dataset,
      datasetSize: d.dataset_size ?? (d.metrics?.["total_samples"] ? Number(d.metrics["total_samples"]) : undefined),
      classes: d.classes,
      // feature_extraction is a single string; split on " + " for individual line display.
      featureExtraction: d.feature_extraction,
      features: d.features ?? (d.feature_extraction
        ? d.feature_extraction.split(" + ").map((s: string) => s.trim())
        : undefined),
      candidateModels: d.candidate_models,
      supportedAnalysisTypes: d.supported_analysis_types,
      metrics: d.metrics,
      confusionMatrix: d.confusion_matrix,
      version: d.version,
    };
  },
};
// ---- Read-only API diagnostics (real browser requests to the configured origin only) ----
export type DiagnosticCategory = "CORS" | "Mixed content" | "Local Network Access" | "Network connection" | "Timeout" | "Backend HTTP error" | "Malformed response";
export interface DiagnosticResult { path: string; method: "GET" | "POST"; status: "PASS" | "FAIL" | "BLOCKED"; httpStatus?: number | undefined; durationMs?: number | undefined; category?: DiagnosticCategory | undefined; detail: string }
export interface DiagnosticsRun { results: DiagnosticResult[]; permissions: { loopbackNetwork: PermissionStateReport; localNetwork: PermissionStateReport }; embedded: boolean; overall: "Connected" | "Partially connected" | "Browser blocked" | "Backend unavailable"; finishedAt: string }

const DIAGNOSTIC_TIMEOUT_MS = 10_000;

export type PermissionStateReport = "granted" | "prompt" | "denied" | "unsupported/error";
async function queryPermission(name: string): Promise<PermissionStateReport> {
  try {
    const perms = (navigator as Navigator & { permissions?: Permissions }).permissions;
    if (!perms) return "unsupported/error";
    return (await perms.query({ name: name as PermissionName })).state as PermissionStateReport;
  } catch { return "unsupported/error"; }
}
function isEmbedded(): boolean { try { return window.self !== window.top; } catch { return true; } }

async function probe(path: string, method: "GET" | "POST", body: BodyInit | undefined, contentType: string | undefined, validate: (data: unknown) => boolean, lnaState: string | undefined): Promise<DiagnosticResult> {
  let url: string;
  try {
    url = buildApiUrl(path);
  } catch {
    return { path, method, status: "FAIL", category: "Network connection", detail: "VITE_API_BASE_URL is not configured." };
  }
  const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), DIAGNOSTIC_TIMEOUT_MS);
  const started = performance.now();
  try {
    const headers: Record<string, string> = { Accept: "application/json" }; if (contentType) headers["Content-Type"] = contentType;
    const response = await fetch(url, { method, headers, body: body ?? null, signal: controller.signal, cache: "no-store" });
    const durationMs = Math.round(performance.now() - started);
    if (!response.ok) return { path, method, status: "FAIL", httpStatus: response.status, durationMs, category: "Backend HTTP error", detail: await errorMessage(response) };
    let data: unknown; try { data = await response.json(); } catch { return { path, method, status: "FAIL", httpStatus: response.status, durationMs, category: "Malformed response", detail: "Response body was not valid JSON." }; }
    return validate(data) ? { path, method, status: "PASS", httpStatus: response.status, durationMs, detail: "Valid response received." } : { path, method, status: "FAIL", httpStatus: response.status, durationMs, category: "Malformed response", detail: "Response did not match the expected format." };
  } catch (error) {
    const message = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
    if (error instanceof DOMException && error.name === "AbortError") return { path, method, status: "FAIL", category: "Timeout", detail: `No HTTP response received within ${DIAGNOSTIC_TIMEOUT_MS / 1000}s.` };
    const lower = message.toLowerCase();
    if (lower.includes("cors") || lower.includes("access-control")) return { path, method, status: "BLOCKED", category: "CORS", detail: `CORS-related browser blocking reported. ${message}` };
    if (lower.includes("mixed content")) return { path, method, status: "BLOCKED", category: "Mixed content", detail: `Mixed-content blocking reported. ${message}` };
    if (lnaState === "denied" || lower.includes("private network") || lower.includes("local network")) return { path, method, status: "BLOCKED", category: "Local Network Access", detail: `Browser Local Network Access permission may be blocking the request${lnaState === "denied" ? " (loopback-network permission: denied)" : ""}. ${message}` };
    return { path, method, status: "FAIL", category: "Network connection", detail: `No HTTP response received. Browser error: ${message}` };
  } finally { clearTimeout(timer); }
}

export async function runApiDiagnostics(): Promise<DiagnosticsRun> {
  const [loopback, localNetwork] = await Promise.all([queryPermission("loopback-network"), queryPermission("local-network")]);
  const embedded = isEmbedded();
  // Target is a loopback origin, so only an explicit "denied" from loopback-network counts as evidence.
  const lna = loopback === "denied" ? "denied" : undefined;
  const csv = new FormData(); csv.append("file", new File(["message\n\"SCAMLENS diagnostic test message - not a real scan\"\n"], "scamlens-diagnostic.csv", { type: "text/csv" }));
  const ok = (schema: z.ZodTypeAny) => (d: unknown) => schema.safeParse(d).success;
  const results = await Promise.all([
    probe("/api/health", "GET", undefined, undefined, ok(healthSchema), lna),
    probe("/api/model-info", "GET", undefined, undefined, ok(modelInfoSchema), lna),
    probe("/api/history", "GET", undefined, undefined, ok(z.union([z.array(historyItemSchema), z.object({ history: z.array(historyItemSchema) }), z.object({ records: z.array(historyItemSchema) })])), lna),
    probe("/api/analyze/message", "POST", JSON.stringify({ message: "SCAMLENS diagnostic test message - not a real scan" }), "application/json", ok(resultSchema), lna),
    // Inert reserved-TLD string; only sent as JSON text, never fetched or opened.
    probe("/api/analyze/url", "POST", JSON.stringify({ url: "http://example.invalid/diagnostic-test" }), "application/json", ok(resultSchema), lna),
    probe("/api/analyze/batch", "POST", csv, undefined, ok(z.union([z.array(historyItemSchema), z.object({ results: z.array(historyItemSchema) }).passthrough()])), lna),
  ]);
  const pass = results.filter((r) => r.status === "PASS").length;
  const received = results.some((r) => r.httpStatus !== undefined);
  const overall: DiagnosticsRun["overall"] = pass === results.length ? "Connected" : pass > 0 || received ? "Partially connected" : results.some((r) => r.status === "BLOCKED") ? "Browser blocked" : "Backend unavailable";
  return { results, overall, permissions: { loopbackNetwork: loopback, localNetwork }, embedded, finishedAt: new Date().toISOString() };
}
