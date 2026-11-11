export type RiskLevel = "Low" | "Suspicious" | "High" | "Very High";
export type Prediction = "Legitimate" | "Scam/Phishing";
export type AlertReviewStatus = "unreviewed" | "reviewed" | "flagged_fp" | "investigating";

export interface TokenAttribution {
  text: string;
  start: number;
  end: number;
  influence: number;
  direction: "scam" | "legitimate" | "neutral";
  source: "model";
}

export interface RuleHighlight {
  start: number;
  end: number;
  text: string;
  category: string;
  category_label: string;
  source: "rule";
}

export interface ExplainabilityData {
  method: string;
  analyzed_text: string;
  truncated?: boolean;
  base_probability?: number | null;
  token_attributions: TokenAttribution[];
  top_scam_terms: Array<{ text: string; influence: number }>;
  top_legitimate_terms: Array<{ text: string; influence: number }>;
  rule_highlights: RuleHighlight[];
  summary: string;
  limitations: string[];
}

export interface ScriptInfo {
  primary_script: string;
  scripts_detected: string[];
  is_multilingual: boolean;
  has_indic_script: boolean;
  has_latin: boolean;
  indic_script_name?: string | null;
  proportions?: Record<string, number>;
  character_counts?: Record<string, number>;
}

export interface RegionalSignal {
  matched_text: string;
  pattern_type: string;
  description: string;
}

export interface LanguageData {
  script_info: ScriptInfo;
  regional_signals: {
    hinglish_signals: RegionalSignal[];
    kanglish_signals: RegionalSignal[];
    hindi_native_signals?: RegionalSignal[];
    kannada_native_signals?: RegionalSignal[];
    total_regional_signals: number;
  };
  transparency_notes: string[];
}

export interface UrlFinding {
  code: string;
  severity: "low" | "medium" | "high";
  title: string;
  detail: string;
  component?: string | undefined;
}

export interface UrlComponents {
  scheme: string;
  scheme_supplied: boolean;
  host: string;
  decoded_host?: string | null;
  registrable_domain: string;
  subdomain?: string | null;
  subdomain_count: number;
  tld?: string | null;
  port?: number | null;
  path: string;
  query_parameter_count: number;
  query_parameter_names: string[];
  fragment?: string | null;
  is_ip_address: boolean;
  ip_address?: string | null;
  offsets?: Record<string, [number, number]> | null;
}

export interface UrlMetrics {
  url_length: number;
  host_length: number;
  domain_entropy_bits: number;
  digit_count_in_host: number;
  hyphen_count_in_host: number;
  dot_count: number;
  uses_https: boolean;
  is_shortener: boolean;
  suspicious_tld: boolean;
}

export interface UrlBrandMatch {
  brand: string;
  type: "official_domain" | "impersonation" | "typosquat";
  edit_distance?: number;
  official_domains: string[];
}

export interface StructuralCheckResult {
  id: string;
  name: string;
  status: "Detected" | "Not Detected" | "Unable to Evaluate";
  severity: "safe" | "warning" | "danger" | "info";
  explanation: string;
}

export interface UrlIntelligenceData {
  valid: boolean;
  /** Submitted URL text (trimmed); `components.offsets` are character indexes into this string. */
  input?: string;
  normalized_url: string;
  components: UrlComponents;
  metrics: UrlMetrics;
  brand_match?: UrlBrandMatch | null;
  findings: UrlFinding[];
  heuristic_level: "High" | "Elevated" | "Low" | "No notable indicators";
  heuristic_score: number;
  structural_checks?: StructuralCheckResult[];
  lexical_features?: Record<string, number>;
}

export interface SenderAnalysis {
  raw_sender: string;
  display_name: string;
  email_address: string;
  domain: string;
  registrable_domain: string;
  is_free_webmail: boolean;
  header_findings: Array<{ code: string; severity: string; title: string; detail: string }>;
  spoofed_brand?: string | null;
}

export interface SubjectAnalysis {
  subject: string;
  has_urgency: boolean;
}

export interface AnalysisResult {
  prediction: Prediction;
  riskProbability: number;
  riskLevel: RiskLevel;
  indicators: string[];
  guidance: string;
  model: string;
  timestamp?: string | undefined;
  riskScore?: number | undefined;
  riskFraction?: number | undefined;
  scanId?: number | undefined;
  explainability?: ExplainabilityData | undefined;
  languageInfo?: LanguageData | undefined;
  urlIntelligence?: UrlIntelligenceData | undefined;
  senderAnalysis?: SenderAnalysis | undefined;
  subjectAnalysis?: SubjectAnalysis | undefined;
  embeddedUrls?: string[] | undefined;
}

export interface MessageAnalysisRequest {
  message: string;
  user_id?: string | undefined;
  sandbox_demo?: boolean | undefined;
}

export interface UrlAnalysisRequest {
  url: string;
  user_id?: string | undefined;
  sandbox_demo?: boolean | undefined;
}

export type SupportedLanguage = "en" | "hi" | "hinglish" | "kn";

export interface AdvancedUrlWarning {
  code: string;
  severity: "low" | "medium" | "high";
  title: string;
  plain_explanation: string;
  matched_brand?: string;
  official_domains?: string[];
  substitution_hint?: string | null;
}

export interface RedirectHop {
  hop: number;
  url: string;
  status_code?: number;
  resolved_ip?: string;
  location?: string | null;
}

export interface AdvancedUrlResolutionResult {
  original_url: string;
  normalized_url: string;
  final_resolved_url?: string | null;
  destination_verified: boolean;
  is_shortened: boolean;
  redirect_hops: RedirectHop[];
  redirect_count: number;
  resolution_status: string;
  resolution_note: string;
  advanced_warnings: AdvancedUrlWarning[];
  safety_disclaimer: string;
}

export interface UpiWarning {
  code: string;
  severity: "low" | "medium" | "high";
  title: string;
  explanation: string;
}

export interface ExtractedUpiDetails {
  raw_payload: string;
  payload_type: string;
  upi_id: string | null;
  payee_name: string | null;
  amount: string | null;
  currency: string | null;
  note: string | null;
  merchant_code: string | null;
  transaction_ref: string | null;
  psp_handle: string | null;
  psp_provider: string | null;
  is_mandate: boolean;
  mode: string | null;
}

export interface UpiInspectionResult {
  valid: boolean;
  error?: string;
  source_type: string;
  extracted_details: ExtractedUpiDetails | null;
  prediction: Prediction;
  risk_level: RiskLevel;
  risk_score: number;
  warnings: UpiWarning[];
  indicators: string[];
  guidance: string;
  safety_disclaimers: string[];
}

export interface EmailAnalysisRequest {
  sender: string;
  subject?: string;
  body: string;
  user_id?: string;
}

export interface AlertReviewRequest {
  review_status: AlertReviewStatus;
  review_notes?: string;
  user_id?: string;
}

export interface HealthStatus {
  healthy: boolean;
  status: string;
}

export interface ScanRecord extends AnalysisResult {
  id: string;
  inputType: "message" | "url" | "email";
  inputPreview: string;
  timestamp: string;
  userId?: string | undefined;
  reviewStatus?: AlertReviewStatus | undefined;
  reviewNotes?: string | undefined;
  reviewedAt?: string | undefined;
}

export interface AlertsResponse {
  count: number;
  alerts: ScanRecord[];
  unreviewed_count: number;
  high_count: number;
  very_high_count: number;
}

export interface ModelInfo {
  /** Formatted model name (from backend's model_name field) */
  model?: string | undefined;
  dataset?: string | undefined;
  datasetSize?: number | undefined;
  classes?: string[] | undefined;
  /** Feature list as individual strings (array) */
  features?: string[] | undefined;
  /** Single-string description of the full feature extraction pipeline */
  featureExtraction?: string | undefined;
  candidateModels?: string[] | undefined;
  supportedAnalysisTypes?: string[] | undefined;
  /** Metrics may contain numbers or string annotations (e.g. "N/A") */
  metrics?: Record<string, number | string> | undefined;
  confusionMatrix?: number[][] | undefined;
  version?: string | undefined;
}

export interface BatchAnalysisResponse {
  results: ScanRecord[];
  total?: number | undefined;
  totalRows?: number | undefined;
  processedRows?: number | undefined;
  failedRows?: number | undefined;
  selectedColumn?: string | undefined;
  errors?: string[] | undefined;
}

export interface ApiErrorShape {
  message: string;
  status?: number;
}
