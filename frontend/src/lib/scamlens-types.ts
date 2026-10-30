export type RiskLevel = "Low" | "Suspicious" | "High" | "Very High";
export type Prediction = "Legitimate" | "Scam/Phishing";

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
}

export interface MessageAnalysisRequest { message: string }
export interface UrlAnalysisRequest { url: string }

export interface HealthStatus {
  healthy: boolean;
  status: string;
}

export interface ScanRecord extends AnalysisResult {
  id: string;
  inputType: "message" | "url";
  inputPreview: string;
  timestamp: string;
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
