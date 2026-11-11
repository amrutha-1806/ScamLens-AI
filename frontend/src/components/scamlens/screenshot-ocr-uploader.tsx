import * as React from "react";
import {
  AlertTriangle,
  Camera,
  CheckCircle2,
  Edit3,
  FileImage,
  Loader2,
  Lock,
  ScanText,
  Sparkles,
  Trash2,
  Upload,
} from "lucide-react";
import { Badge, Button, Card, Textarea, cn } from "./ui";

const ALLOWED_MIME_TYPES = new Set(["image/png", "image/jpeg", "image/jpg"]);
const ALLOWED_EXTENSIONS = /\.(png|jpe?g)$/i;
const MAX_SCREENSHOT_BYTES = 5 * 1024 * 1024; // 5 MB limit

/**
 * Generates an in-memory PNG screenshot of a realistic scam SMS so users can test
 * the full browser OCR pipeline with a single click.
 */
async function generateSampleScamScreenshotFile(): Promise<File> {
  const canvas = document.createElement("canvas");
  canvas.width = 760;
  canvas.height = 280;
  const ctx = canvas.getContext("2d");
  if (!ctx) {
    throw new Error("Canvas context unavailable");
  }

  // High-contrast clean background for reliable Tesseract OCR recognition
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  ctx.fillStyle = "#0f172a";
  ctx.font = "bold 24px Arial, sans-serif";
  ctx.fillText("URGENT: Your bank account will be blocked today!", 32, 62);

  ctx.font = "22px Arial, sans-serif";
  ctx.fillText("Act immediately to verify your account KYC at:", 32, 112);

  ctx.fillStyle = "#1d4ed8";
  ctx.font = "bold 22px Courier New, monospace";
  ctx.fillText("http://sbi-kyc-verify-account.xyz/login", 32, 158);

  ctx.fillStyle = "#0f172a";
  ctx.font = "22px Arial, sans-serif";
  ctx.fillText("Or share your OTP 482910 to avoid suspension.", 32, 208);

  const blob: Blob = await new Promise((resolve, reject) => {
    canvas.toBlob((b) => (b ? resolve(b) : reject(new Error("Failed to encode PNG"))), "image/png");
  });

  return new File([blob], "sample-scam-sms-screenshot.png", { type: "image/png" });
}

export function ScreenshotOcrUploader({
  onAnalyzeExtractedText,
  analyzing = false,
}: {
  onAnalyzeExtractedText: (extractedText: string) => void;
  analyzing?: boolean;
}) {
  const [selectedFile, setSelectedFile] = React.useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = React.useState<string | null>(null);
  const [ocrStatus, setOcrStatus] = React.useState<"idle" | "extracting" | "ready" | "empty" | "error">("idle");
  const [ocrProgress, setOcrProgress] = React.useState<number>(0);
  const [extractedText, setExtractedText] = React.useState<string>("");
  const [errorMsg, setErrorMsg] = React.useState<string | null>(null);
  const [dragActive, setDragActive] = React.useState<boolean>(false);
  const fileInputRef = React.useState<React.RefObject<HTMLInputElement | null>>(() => React.createRef())[0];

  // Clean up object URL on unmount or file change
  React.useEffect(() => {
    return () => {
      if (previewUrl) {
        URL.revokeObjectURL(previewUrl);
      }
    };
  }, [previewUrl]);

  const resetUploader = () => {
    if (previewUrl) URL.revokeObjectURL(previewUrl);
    setSelectedFile(null);
    setPreviewUrl(null);
    setOcrStatus("idle");
    setOcrProgress(0);
    setExtractedText("");
    setErrorMsg(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  const runLocalBrowserOcr = async (file: File) => {
    setOcrStatus("extracting");
    setOcrProgress(10);
    setErrorMsg(null);

    try {
      const TesseractModule = await import("tesseract.js");
      const recognizeFn =
        TesseractModule.recognize ??
        (TesseractModule.default as { recognize?: typeof TesseractModule.recognize } | undefined)?.recognize;

      if (!recognizeFn) {
        throw new Error("Local OCR engine could not be initialized.");
      }

      const result = await recognizeFn(file, "eng", {
        logger: (m: { status?: string; progress?: number }) => {
          if (typeof m.progress === "number") {
            setOcrProgress(Math.max(15, Math.min(99, Math.round(m.progress * 100))));
          }
        },
      });

      const cleanedText = (result?.data?.text ?? "")
        .replace(/\r\n/g, "\n")
        .replace(/\n{3,}/g, "\n\n")
        .trim();

      setOcrProgress(100);
      if (!cleanedText || cleanedText.length < 3) {
        setOcrStatus("empty");
        setExtractedText("");
        setErrorMsg(
          "No readable text was detected in this screenshot. You can try a clearer screenshot or type/paste the message manually below."
        );
      } else {
        setOcrStatus("ready");
        setExtractedText(cleanedText);
      }
    } catch (err) {
      setOcrStatus("error");
      setErrorMsg(
        err instanceof Error
          ? `OCR extraction failed: ${err.message}. You can still type or edit the message text manually below.`
          : "Could not extract text from this image. Please try another screenshot or enter the text manually."
      );
    }
  };

  const handleFileValidationAndLoad = (file: File | undefined | null) => {
    if (!file) return;
    setErrorMsg(null);

    // 1. Validate format (PNG, JPG, JPEG only)
    const validType = ALLOWED_MIME_TYPES.has(file.type.toLowerCase()) || ALLOWED_EXTENSIONS.test(file.name);
    if (!validType) {
      setOcrStatus("error");
      setErrorMsg(
        `Unsupported file format (${file.name}). Please upload a PNG, JPG, or JPEG screenshot image.`
      );
      return;
    }

    // 2. Validate file size (max 5 MB)
    if (file.size > MAX_SCREENSHOT_BYTES) {
      setOcrStatus("error");
      setErrorMsg(
        `File is too large (${(file.size / (1024 * 1024)).toFixed(2)} MB). Maximum allowed screenshot size is 5.0 MB.`
      );
      return;
    }

    if (file.size === 0) {
      setOcrStatus("error");
      setErrorMsg("The selected image file is empty (0 bytes).");
      return;
    }

    if (previewUrl) URL.revokeObjectURL(previewUrl);
    const objUrl = URL.createObjectURL(file);
    setSelectedFile(file);
    setPreviewUrl(objUrl);
    void runLocalBrowserOcr(file);
  };

  const handleLoadSampleScreenshot = async () => {
    try {
      const sampleFile = await generateSampleScamScreenshotFile();
      handleFileValidationAndLoad(sampleFile);
    } catch {
      setErrorMsg("Unable to generate sample screenshot in this browser environment.");
    }
  };

  return (
    <Card
      className="p-5 space-y-4 border-cyan-500/25 bg-slate-900/80"
      data-testid="screenshot-ocr-uploader"
    >
      {/* Header & Local Privacy Guarantee */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 border-b border-slate-800/80 pb-3.5">
        <div className="flex items-start gap-2.5">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-cyan-500/35 bg-cyan-500/10 text-cyan-300">
            <Camera className="h-4 w-4" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="text-sm font-bold text-white">Screenshot Upload with Local OCR</h3>
              <Badge tone="info">PNG / JPG / JPEG</Badge>
              <Badge tone="success">100% Local Browser OCR</Badge>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Upload a screenshot of a suspicious SMS, WhatsApp, email, or payment alert to extract and inspect its text.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button
            type="button"
            variant="secondary"
            size="sm"
            data-testid="ocr-sample-screenshot-btn"
            onClick={() => void handleLoadSampleScreenshot()}
            disabled={ocrStatus === "extracting"}
          >
            <Sparkles className="h-3.5 w-3.5 text-cyan-400" />
            <span>Try Sample Screenshot</span>
          </Button>
          {selectedFile && (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={resetUploader}
              data-testid="ocr-clear-btn"
            >
              <Trash2 className="h-3.5 w-3.5" />
              <span>Clear</span>
            </Button>
          )}
        </div>
      </div>

      {/* Privacy Notice */}
      <div className="flex items-center gap-2 rounded-lg border border-emerald-500/20 bg-emerald-950/15 px-3 py-2 text-[11px] text-emerald-200/90">
        <Lock className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
        <span>
          <strong>Privacy Guarantee:</strong> Optical Character Recognition (OCR) runs locally inside your browser. Screenshots are never stored permanently or uploaded to third-party OCR servers.
        </span>
      </div>

      {/* Drag-and-Drop / Browse Zone */}
      <div
        onDragOver={(e) => {
          e.preventDefault();
          e.stopPropagation();
          setDragActive(true);
        }}
        onDragLeave={(e) => {
          e.preventDefault();
          e.stopPropagation();
          setDragActive(false);
        }}
        onDrop={(e) => {
          e.preventDefault();
          e.stopPropagation();
          setDragActive(false);
          const dropped = e.dataTransfer?.files?.[0];
          handleFileValidationAndLoad(dropped);
        }}
        className={cn(
          "relative flex flex-col items-center justify-center rounded-xl border-2 border-dashed p-5 text-center transition-all",
          dragActive
            ? "border-cyan-400 bg-cyan-500/10"
            : "border-slate-700/80 bg-slate-950/60 hover:border-cyan-500/40"
        )}
        data-testid="ocr-dropzone"
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".png,.jpg,.jpeg,image/png,image/jpeg"
          data-testid="ocr-file-input"
          className="hidden"
          onChange={(e) => handleFileValidationAndLoad(e.target.files?.[0])}
        />
        <FileImage className="h-8 w-8 text-cyan-400 mb-2" />
        <p className="text-xs font-medium text-slate-200">
          Drag & drop a screenshot here, or{" "}
          <button
            type="button"
            data-testid="ocr-browse-btn"
            onClick={() => fileInputRef.current?.click()}
            className="text-cyan-400 underline hover:text-cyan-300 font-semibold"
          >
            browse from your device
          </button>
        </p>
        <p className="text-[11px] text-slate-500 mt-1">
          Supports PNG, JPG, JPEG up to 5 MB (SMS, WhatsApp, Email, or UPI screenshots)
        </p>
      </div>

      {/* Validation / OCR Error Alert */}
      {errorMsg && (
        <div
          className="flex items-start gap-2.5 rounded-xl border border-amber-500/35 bg-amber-950/25 p-3 text-xs text-amber-200"
          data-testid="ocr-error-banner"
        >
          <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Preview & Editable Extracted Text Area */}
      {selectedFile && previewUrl && (
        <div className="grid gap-4 md:grid-cols-12 pt-1">
          {/* Screenshot Preview */}
          <div className="md:col-span-5 space-y-2">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span className="font-mono uppercase tracking-wider">Screenshot Preview</span>
              <span className="truncate max-w-[180px] text-[11px] text-slate-500">{selectedFile.name}</span>
            </div>
            <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-950 p-2 flex items-center justify-center min-h-[160px] max-h-[240px]">
              <img
                src={previewUrl}
                alt="Uploaded suspicious message screenshot preview"
                data-testid="ocr-image-preview"
                className="max-h-[220px] w-auto object-contain rounded-lg"
              />
            </div>
          </div>

          {/* Extracted Text & Edit Box */}
          <div className="md:col-span-7 space-y-2.5 flex flex-col justify-between">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label
                  htmlFor="ocr-extracted-textarea"
                  className="text-xs font-mono uppercase tracking-wider text-slate-300 flex items-center gap-1.5"
                >
                  <Edit3 className="h-3.5 w-3.5 text-cyan-400" />
                  <span>Extracted Text (Editable Before Analysis)</span>
                </label>
                {ocrStatus === "extracting" && (
                  <span className="inline-flex items-center gap-1.5 text-xs text-cyan-300 font-mono">
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    Extracting ({ocrProgress}%)...
                  </span>
                )}
                {ocrStatus === "ready" && (
                  <span className="inline-flex items-center gap-1 text-xs text-emerald-400 font-mono">
                    <CheckCircle2 className="h-3.5 w-3.5" />
                    OCR Complete
                  </span>
                )}
              </div>

              <Textarea
                id="ocr-extracted-textarea"
                data-testid="ocr-extracted-textarea"
                rows={5}
                value={extractedText}
                onChange={(e) => setExtractedText(e.target.value)}
                disabled={ocrStatus === "extracting"}
                placeholder={
                  ocrStatus === "extracting"
                    ? "Running local browser OCR on your screenshot..."
                    : "Extracted text will appear here. You can edit or correct any OCR typos before analyzing."
                }
              />
              <p className="text-[11px] text-slate-400">
                Review and correct any OCR recognition typos above, then click <strong>Analyze Extracted Text</strong> to run the full SCAMLENS AI detector.
              </p>
            </div>

            <div className="flex flex-wrap items-center justify-end gap-2 pt-1">
              <Button
                type="button"
                data-testid="analyze-extracted-text-btn"
                disabled={ocrStatus === "extracting" || analyzing || extractedText.trim().length < 3}
                onClick={() => onAnalyzeExtractedText(extractedText.trim())}
              >
                <ScanText className="h-4 w-4" />
                <span>{analyzing ? "Analyzing Extracted Text..." : "Analyze Extracted Text"}</span>
              </Button>
            </div>
          </div>
        </div>
      )}
    </Card>
  );
}
