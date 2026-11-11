import * as React from "react";
import {
  AlertTriangle,
  CheckCircle2,
  CreditCard,
  FileImage,
  HelpCircle,
  Info,
  Loader2,
  Lock,
  QrCode,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
} from "lucide-react";
import { scamlensApi } from "@/lib/scamlens-api";
import type { ExtractedUpiDetails, UpiInspectionResult, UpiWarning } from "@/lib/scamlens-types";
import { Badge, Button, Card, Input, cn } from "./ui";

const KNOWN_PSP_HANDLES: Record<string, string> = {
  okaxis: "Google Pay (Axis Bank)",
  okhdfcbank: "Google Pay (HDFC Bank)",
  okicici: "Google Pay (ICICI Bank)",
  oksbi: "Google Pay (SBI)",
  ybl: "PhonePe (Yes Bank)",
  ibl: "PhonePe (ICICI Bank)",
  axl: "PhonePe (Axis Bank)",
  paytm: "Paytm Payments Bank",
  ptyes: "Paytm (Yes Bank)",
  ptaxis: "Paytm (Axis Bank)",
  pthdfc: "Paytm (HDFC Bank)",
  ptsbi: "Paytm (SBI)",
  apl: "Amazon Pay",
  yapl: "Amazon Pay (Yes Bank)",
  rapl: "Amazon Pay (RBL Bank)",
  upi: "BHIM / NPCI Default",
  sbi: "State Bank of India",
  hdfcbank: "HDFC Bank",
  icici: "ICICI Bank",
  axisbank: "Axis Bank",
  kotak: "Kotak Mahindra Bank",
};

const SAMPLE_UPI_SCENARIOS = [
  {
    label: "Fake 'Scan to Receive Refund' QR URI",
    sourceType: "qr" as const,
    payload:
      "upi://pay?pa=refund.claim.desk@ybl&pn=Customer%20Cashback%20Refund&am=4999.00&cu=INR&tn=Scan%20and%20enter%20PIN%20to%20receive%20Rs%204999%20refund",
  },
  {
    label: "Recurring Auto-Debit Mandate Trap",
    sourceType: "qr" as const,
    payload:
      "upi://mandate?pa=prize.verification@okaxis&pn=Reward%20Processing%20Hub&am=9999.00&cu=INR&tn=Approve%20KYC%20verification%20mandate",
  },
  {
    label: "Typo Handle & KYC Lure VPA",
    sourceType: "manual" as const,
    payload: "sbi.kyc.helpline.officer@0ksbi",
  },
  {
    label: "Standard Merchant VPA (Syntactically Valid)",
    sourceType: "manual" as const,
    payload: "bookshop.counter12@okicici",
  },
];

/**
 * Extracts UPI payment details locally in the browser BEFORE the user triggers analysis,
 * so the user can inspect Payee VPA, Payee Name, Amount, and Note upfront.
 */
export function extractUpiDetailsPreview(rawInput: string): ExtractedUpiDetails {
  const raw = rawInput.trim();
  const lower = raw.toLowerCase();

  if (lower.startsWith("upi://")) {
    const isMandate = lower.startsWith("upi://mandate");
    const qIndex = raw.indexOf("?");
    const queryStr = qIndex >= 0 ? raw.slice(qIndex + 1) : "";
    const params = new URLSearchParams(queryStr);

    const getParam = (key: string): string | null => {
      for (const [k, v] of params.entries()) {
        if (k.toLowerCase() === key.toLowerCase() && v.trim()) {
          return v.trim();
        }
      }
      return null;
    };

    const upiId = getParam("pa");
    const handle = upiId && upiId.includes("@") ? (upiId.split("@")[1]?.toLowerCase() ?? null) : null;

    return {
      raw_payload: raw,
      payload_type: isMandate ? "upi_mandate_uri" : "upi_pay_uri",
      upi_id: upiId,
      payee_name: getParam("pn"),
      amount: getParam("am"),
      currency: getParam("cu") || "INR",
      note: getParam("tn"),
      merchant_code: getParam("mc"),
      transaction_ref: getParam("tr"),
      psp_handle: handle,
      psp_provider: handle ? (KNOWN_PSP_HANDLES[handle] ?? null) : null,
      is_mandate: isMandate,
      mode: getParam("mode"),
    };
  }

  if (lower.startsWith("http://") || lower.startsWith("https://")) {
    return {
      raw_payload: raw,
      payload_type: "web_url_in_qr",
      upi_id: null,
      payee_name: null,
      amount: null,
      currency: null,
      note: null,
      merchant_code: null,
      transaction_ref: null,
      psp_handle: null,
      psp_provider: null,
      is_mandate: false,
      mode: null,
    };
  }

  const handle = raw.includes("@") ? (raw.split("@")[1]?.toLowerCase() ?? null) : null;
  return {
    raw_payload: raw,
    payload_type: "raw_vpa",
    upi_id: raw,
    payee_name: null,
    amount: null,
    currency: "INR",
    note: null,
    merchant_code: null,
    transaction_ref: null,
    psp_handle: handle,
    psp_provider: handle ? (KNOWN_PSP_HANDLES[handle] ?? null) : null,
    is_mandate: false,
    mode: null,
  };
}

/**
 * Deterministic client-side fallback analyzer matching `backend/services/upi_service.py`
 * in case the backend is waking up or unreachable.
 */
function fallbackClientUpiInspection(rawInput: string, sourceType: string): UpiInspectionResult {
  const details = extractUpiDetailsPreview(rawInput);
  const warnings: UpiWarning[] = [];
  let riskPoints = 0;

  if (details.payload_type === "web_url_in_qr") {
    riskPoints += 55;
    warnings.push({
      code: "QR_WEB_URL_INSTEAD_OF_UPI",
      severity: "high",
      title: "QR Code Opens a External Website Instead of a UPI Payment Screen",
      explanation:
        "This QR code contains a web link rather than a standard 'upi://pay' payment instruction. Scammers use web-link QR codes to open fake login or credential-harvesting pages.",
    });
  } else {
    const vpa = details.upi_id || "";
    const vpaValid = /^[a-zA-Z0-9._-]{2,256}@[a-zA-Z][a-zA-Z0-9]{1,63}$/.test(vpa);
    if (!vpaValid) {
      riskPoints += 65;
      warnings.push({
        code: "MALFORMED_UPI_ID",
        severity: "high",
        title: "Malformed or Invalid UPI ID (VPA) Format",
        explanation: `The UPI ID '${vpa || rawInput}' does not follow the valid 'username@bankhandle' format (e.g. 'merchant@okicici') or contains substituted digits in the bank handle.`,
      });
    } else {
      const [userPart = "", handlePart = ""] = vpa.toLowerCase().split("@");
      if (handlePart && !KNOWN_PSP_HANDLES[handlePart]) {
        riskPoints += 25;
        warnings.push({
          code: "UNRECOGNIZED_PSP_HANDLE",
          severity: "medium",
          title: `Unrecognized UPI Bank Handle '@${handlePart}'`,
          explanation: `The handle '@${handlePart}' is not in the standard registry of major NPCI/UPI bank handles (such as @oksbi, @ybl, @paytm, @icici). Verify carefully for typos.`,
        });
      }
      if (/(refund|cashback|reward|prize|lottery|winner|kyc|block|helpline|support|customercare|pmcare|officer)/i.test(userPart)) {
        riskPoints += 50;
        warnings.push({
          code: "DECEPTIVE_VPA_IDENTITY",
          severity: "high",
          title: "Suspicious Lure or Support Keyword Inside UPI ID",
          explanation: `The UPI address '${vpa}' contains high-risk lure words (such as refund, cashback, prize, KYC, or helpline) commonly registered by scammers to impersonate official desks.`,
        });
      }
    }

    if (details.is_mandate) {
      riskPoints += 55;
      warnings.push({
        code: "UPI_AUTODEBIT_MANDATE",
        severity: "high",
        title: "Recurring Auto-Debit Mandate ('upi://mandate') Detected",
        explanation:
          "This QR payload sets up a recurring or delayed automatic debit mandate from your bank account rather than a one-time payment.",
      });
    }

    if (details.amount) {
      const amtNum = Number(details.amount);
      if (!Number.isNaN(amtNum) && amtNum > 0) {
        riskPoints += amtNum >= 2000 ? 25 : 10;
        warnings.push({
          code: "PREFILLED_DEBIT_AMOUNT",
          severity: amtNum >= 2000 ? "medium" : "low",
          title: `Pre-Filled Outgoing Debit Amount (INR ${amtNum.toLocaleString("en-IN")})`,
          explanation: `Scanning this QR code pre-fills an outgoing transfer of INR ${amtNum.toLocaleString("en-IN")} FROM your account. Remember: you NEVER scan a QR code or enter a UPI PIN to receive money.`,
        });
      }
    }

    const combinedText = `${details.payee_name || ""} ${details.note || ""}`;
    if (/(receive|claim|refund|cashback|reward|won|prize|lottery|unlock|verify|kyc)/i.test(combinedText)) {
      riskPoints += 55;
      warnings.push({
        code: "RECEIVE_MONEY_PIN_SCAM_LURE",
        severity: "high",
        title: "Deceptive 'Scan to Receive / Claim Refund' Lure Detected",
        explanation:
          "The payment note or payee name claims you will 'receive', 'claim', or 'get a refund/reward'. In UPI, scanning a QR code and entering your UPI PIN ALWAYS SENDS money out of your account.",
      });
    }
  }

  const score = Math.min(100, riskPoints);
  const riskLevel = score >= 80 ? "Very High" : score >= 60 ? "High" : score >= 30 ? "Suspicious" : "Low";
  const prediction = score >= 30 ? "Scam/Phishing" : "Legitimate";

  return {
    valid: true,
    source_type: sourceType,
    extracted_details: details,
    prediction,
    risk_level: riskLevel,
    risk_score: score,
    warnings,
    indicators:
      warnings.length > 0
        ? warnings.map((w) => `${w.title}: ${w.explanation}`)
        : ["Valid VPA syntax structure; no explicit refund/reward scam keywords detected in payment parameters."],
    guidance:
      score >= 30
        ? "DO NOT scan this QR code or enter your UPI PIN. Remember: entering a UPI PIN always deducts money from your bank account."
        : "No obvious lexical scam lure was found in the payment string, but syntax validation CANNOT verify the real-world honesty of the recipient.",
    safety_disclaimers: [
      "A syntactically valid UPI ID or QR code does NOT guarantee that the recipient is trustworthy or verified.",
      "You NEVER need to scan a QR code or enter your UPI PIN to receive money, refunds, or cashback.",
      "SCAMLENS AI inspects payment strings statically and never initiates payments or connects to your bank account.",
    ],
  };
}

export function QrUpiSafetyChecker() {
  const [inputMode, setInputMode] = React.useState<"qr" | "manual">("qr");
  const [rawPayload, setRawPayload] = React.useState<string>("");
  const [qrPreviewUrl, setQrPreviewUrl] = React.useState<string | null>(null);
  const [qrFileName, setQrFileName] = React.useState<string | null>(null);
  const [decodingQr, setDecodingQr] = React.useState<boolean>(false);
  const [decodeError, setDecodeError] = React.useState<string | null>(null);
  const [analyzing, setAnalyzing] = React.useState<boolean>(false);
  const [inspectionResult, setInspectionResult] = React.useState<UpiInspectionResult | null>(null);

  const fileInputRef = React.useState<React.RefObject<HTMLInputElement | null>>(() => React.createRef())[0];

  React.useEffect(() => {
    return () => {
      if (qrPreviewUrl) URL.revokeObjectURL(qrPreviewUrl);
    };
  }, [qrPreviewUrl]);

  // Pre-analysis extracted fields preview (always shown before analysis whenever rawPayload is non-empty)
  const extractedPreview = React.useMemo(
    () => (rawPayload.trim() ? extractUpiDetailsPreview(rawPayload) : null),
    [rawPayload]
  );

  const decodeQrImageFile = async (file: File) => {
    setDecodingQr(true);
    setDecodeError(null);
    setInspectionResult(null);

    if (!/\.(png|jpe?g)$/i.test(file.name) && !["image/png", "image/jpeg", "image/jpg"].includes(file.type)) {
      setDecodingQr(false);
      setDecodeError("Unsupported file format. Please upload a PNG, JPG, or JPEG QR code image.");
      return;
    }

    if (file.size > 5 * 1024 * 1024) {
      setDecodingQr(false);
      setDecodeError("Image exceeds the 5 MB limit. Please upload a smaller QR code image.");
      return;
    }

    if (qrPreviewUrl) URL.revokeObjectURL(qrPreviewUrl);
    const objUrl = URL.createObjectURL(file);
    setQrPreviewUrl(objUrl);
    setQrFileName(file.name);

    try {
      const img = new Image();
      img.src = objUrl;
      await new Promise<void>((resolve, reject) => {
        img.onload = () => resolve();
        img.onerror = () => reject(new Error("Could not load image file"));
      });

      const canvas = document.createElement("canvas");
      canvas.width = img.naturalWidth || img.width || 400;
      canvas.height = img.naturalHeight || img.height || 400;
      const ctx = canvas.getContext("2d");
      if (!ctx) throw new Error("Canvas 2D context unavailable");
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

      const jsQRModule = await import("jsqr");
      const jsQR = jsQRModule.default ?? (jsQRModule as unknown as typeof jsQRModule.default);
      const code = jsQR(imageData.data, imageData.width, imageData.height);

      if (code && code.data && code.data.trim()) {
        setRawPayload(code.data.trim());
      } else {
        setDecodeError(
          "No valid QR code pattern could be decoded from this image. Try a clearer image or enter the UPI ID manually."
        );
      }
    } catch (err) {
      setDecodeError(
        err instanceof Error
          ? `QR decoding failed: ${err.message}. You can also enter the UPI ID manually.`
          : "Could not decode QR code from this image."
      );
    } finally {
      setDecodingQr(false);
    }
  };

  /**
   * Generates a real QR code PNG image in the browser using `qrcode` and decodes it via `jsqr`
   * so users can test the full QR upload + decode + pre-analysis extraction flow in one click.
   */
  const handleLoadSampleQrImage = async () => {
    try {
      setInputMode("qr");
      setDecodeError(null);
      const sampleUri = SAMPLE_UPI_SCENARIOS[0]!.payload;
      const QRCode = await import("qrcode");
      const toDataURL =
        QRCode.toDataURL ?? (QRCode.default as { toDataURL?: typeof QRCode.toDataURL } | undefined)?.toDataURL;
      if (!toDataURL) {
        setRawPayload(sampleUri);
        return;
      }
      const dataUrl = await toDataURL(sampleUri, {
        width: 340,
        margin: 2,
        color: { dark: "#000000", light: "#ffffff" },
      });
      const res = await fetch(dataUrl);
      const blob = await res.blob();
      const sampleFile = new File([blob], "sample-refund-scam-upi-qr.png", { type: "image/png" });
      await decodeQrImageFile(sampleFile);
    } catch {
      setRawPayload(SAMPLE_UPI_SCENARIOS[0]!.payload);
    }
  };

  const handleRunUpiAnalysis = async () => {
    if (!rawPayload.trim()) return;
    setAnalyzing(true);
    try {
      const res = await scamlensApi.inspectUpi(rawPayload.trim(), inputMode);
      setInspectionResult(res);
    } catch {
      // Safe deterministic client-side fallback if backend is sleeping or offline
      setInspectionResult(fallbackClientUpiInspection(rawPayload.trim(), inputMode));
    } finally {
      setAnalyzing(false);
    }
  };

  const resetChecker = () => {
    if (qrPreviewUrl) URL.revokeObjectURL(qrPreviewUrl);
    setQrPreviewUrl(null);
    setQrFileName(null);
    setRawPayload("");
    setDecodeError(null);
    setInspectionResult(null);
  };

  return (
    <div className="space-y-5" data-testid="qr-upi-safety-checker">
      <Card className="p-5 space-y-5 border-cyan-500/25 bg-slate-900/80">
        {/* Header & Mode Switcher */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
          <div className="flex items-start gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-cyan-500/35 bg-cyan-500/10 text-cyan-300">
              <QrCode className="h-5 w-5" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="text-base font-bold text-white">QR Code & UPI Payment Safety Checker</h2>
                <Badge tone="info">Local QR Decode + VPA Inspector</Badge>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Inspect a QR code image or UPI ID (`username@handle`) to reveal hidden payment amounts, notes, and scam lures before you pay.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              data-testid="upi-mode-qr-btn"
              onClick={() => setInputMode("qr")}
              className={cn(
                "inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-semibold transition",
                inputMode === "qr"
                  ? "border-cyan-400/50 bg-cyan-500/15 text-cyan-200"
                  : "border-slate-800 bg-slate-950 text-slate-400 hover:text-slate-200"
              )}
            >
              <QrCode className="h-3.5 w-3.5" />
              <span>Upload QR Image</span>
            </button>
            <button
              type="button"
              data-testid="upi-mode-manual-btn"
              onClick={() => setInputMode("manual")}
              className={cn(
                "inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-semibold transition",
                inputMode === "manual"
                  ? "border-cyan-400/50 bg-cyan-500/15 text-cyan-200"
                  : "border-slate-800 bg-slate-950 text-slate-400 hover:text-slate-200"
              )}
            >
              <CreditCard className="h-3.5 w-3.5" />
              <span>Enter UPI ID / URI</span>
            </button>
          </div>
        </div>

        {/* Core UPI Golden Rule Banner */}
        <div className="flex items-start gap-2.5 rounded-xl border border-amber-500/30 bg-amber-950/20 px-3.5 py-2.5 text-xs text-amber-200">
          <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
          <div>
            <strong>Golden Rule of UPI Safety:</strong> Scanning a QR code and entering your UPI PIN{" "}
            <span className="underline font-semibold">ALWAYS SENDS MONEY</span> out of your bank account. You never need to scan a QR code or enter a PIN to receive money, cashback, or a refund.
          </div>
        </div>

        {/* Quick Sample Scenarios */}
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 mr-1">
            Try Sample Scenarios:
          </span>
          <button
            type="button"
            data-testid="upi-sample-qr-image-btn"
            onClick={() => void handleLoadSampleQrImage()}
            className="inline-flex items-center gap-1.5 rounded-md border border-cyan-500/40 bg-cyan-500/10 px-2.5 py-1 text-[11px] font-medium text-cyan-200 hover:bg-cyan-500/20 transition"
          >
            <Sparkles className="h-3 w-3 text-cyan-400" />
            <span>Generate & Decode Sample Scam QR Image</span>
          </button>
          {SAMPLE_UPI_SCENARIOS.map((sc, idx) => (
            <button
              key={idx}
              type="button"
              data-testid={`upi-sample-scenario-${idx}`}
              onClick={() => {
                setInputMode(sc.sourceType);
                setRawPayload(sc.payload);
                setDecodeError(null);
                setInspectionResult(null);
              }}
              className="inline-flex items-center gap-1.5 rounded-md border border-slate-800 bg-slate-950/80 px-2.5 py-1 text-[11px] text-slate-300 hover:border-cyan-500/40 hover:text-cyan-200 transition"
            >
              <span>{sc.label}</span>
            </button>
          ))}
        </div>

        {/* Input Section: QR Upload vs Manual UPI ID */}
        {inputMode === "qr" ? (
          <div className="grid gap-4 md:grid-cols-12">
            <div className="md:col-span-7 flex flex-col justify-center rounded-xl border-2 border-dashed border-slate-700/80 bg-slate-950/60 p-5 text-center">
              <input
                ref={fileInputRef}
                type="file"
                accept=".png,.jpg,.jpeg,image/png,image/jpeg"
                data-testid="qr-file-input"
                className="hidden"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) void decodeQrImageFile(f);
                }}
              />
              <FileImage className="h-8 w-8 text-cyan-400 mx-auto mb-2" />
              <p className="text-xs font-medium text-slate-200">
                Upload a QR Code image (PNG, JPG, JPEG) to decode locally:{" "}
                <button
                  type="button"
                  data-testid="qr-browse-btn"
                  onClick={() => fileInputRef.current?.click()}
                  className="text-cyan-400 underline font-semibold hover:text-cyan-300"
                >
                  Browse QR Image
                </button>
              </p>
              <p className="text-[11px] text-slate-500 mt-1">
                Decoded 100% locally in your browser using jsQR — never initiates any payment.
              </p>
            </div>

            <div className="md:col-span-5 flex flex-col items-center justify-center rounded-xl border border-slate-800 bg-slate-950/80 p-3 min-h-[140px]">
              {decodingQr ? (
                <div className="flex items-center gap-2 text-xs text-cyan-300">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  <span>Decoding QR code locally...</span>
                </div>
              ) : qrPreviewUrl ? (
                <div className="space-y-1.5 text-center">
                  <img
                    src={qrPreviewUrl}
                    alt="Uploaded QR code preview"
                    data-testid="qr-image-preview"
                    className="h-28 w-28 object-contain mx-auto rounded-lg border border-slate-800 bg-white p-1"
                  />
                  <p className="text-[11px] text-slate-400 truncate max-w-[200px]">{qrFileName}</p>
                </div>
              ) : (
                <p className="text-xs text-slate-500 text-center">
                  QR code image preview will appear here after selecting a file or clicking &ldquo;Generate & Decode Sample Scam QR Image&rdquo;.
                </p>
              )}
            </div>
          </div>
        ) : null}

        {/* Manual / Decoded Payload Input Box */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <label htmlFor="upi-payload-input" className="text-xs font-mono uppercase tracking-wider text-slate-300">
              {inputMode === "qr"
                ? "Decoded QR Payload / UPI Payment String (Editable)"
                : "Enter UPI ID (e.g. name@oksbi) or UPI Payment URI (upi://pay?...)"}
            </label>
            {rawPayload && (
              <button
                type="button"
                onClick={resetChecker}
                className="text-xs text-slate-400 hover:text-rose-300 inline-flex items-center gap-1"
              >
                <Trash2 className="h-3 w-3" />
                <span>Clear</span>
              </button>
            )}
          </div>
          <Input
            id="upi-payload-input"
            data-testid="upi-payload-input"
            value={rawPayload}
            onChange={(e) => {
              setRawPayload(e.target.value);
              setInspectionResult(null);
            }}
            placeholder="e.g. refund.desk@ybl or upi://pay?pa=merchant@okicici&pn=Store&am=500&tn=Note"
          />
        </div>

        {decodeError && (
          <div
            className="flex items-start gap-2.5 rounded-xl border border-amber-500/35 bg-amber-950/25 p-3 text-xs text-amber-200"
            data-testid="qr-decode-error"
          >
            <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
            <span>{decodeError}</span>
          </div>
        )}

        {/* PRE-ANALYSIS EXTRACTED PAYMENT DETAILS CARD (Required BEFORE analysis) */}
        {extractedPreview && (
          <div
            className="rounded-xl border border-cyan-500/30 bg-slate-950/90 p-4 space-y-3"
            data-testid="upi-extracted-details-preview"
          >
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2.5">
              <div className="flex items-center gap-2">
                <Info className="h-4 w-4 text-cyan-400" />
                <span className="text-xs font-bold uppercase tracking-wider text-cyan-300">
                  Extracted Payment Details (Review Before Analysis)
                </span>
              </div>
              <Badge tone={extractedPreview.is_mandate ? "danger" : "info"}>
                {extractedPreview.payload_type === "upi_mandate_uri"
                  ? "Auto-Debit Mandate URI"
                  : extractedPreview.payload_type === "upi_pay_uri"
                    ? "UPI Payment QR URI"
                    : extractedPreview.payload_type === "web_url_in_qr"
                      ? "External Web URL in QR"
                      : "Direct UPI ID (VPA)"}
              </Badge>
            </div>

            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 text-xs">
              <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-2.5">
                <span className="text-[10px] font-mono uppercase text-slate-400 block">UPI ID / Payee Address (pa)</span>
                <span className="font-mono font-semibold text-white break-all mt-0.5 block" data-testid="extracted-upi-id">
                  {extractedPreview.upi_id || "Not Present (Web URL)"}
                </span>
                {extractedPreview.psp_provider && (
                  <span className="text-[11px] text-cyan-300 block mt-0.5">{extractedPreview.psp_provider}</span>
                )}
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-2.5">
                <span className="text-[10px] font-mono uppercase text-slate-400 block">Payee Name (pn)</span>
                <span className="font-semibold text-white break-words mt-0.5 block" data-testid="extracted-payee-name">
                  {extractedPreview.payee_name || "Not Specified in String"}
                </span>
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-2.5">
                <span className="text-[10px] font-mono uppercase text-slate-400 block">Requested Debit Amount (am)</span>
                <span
                  className={cn(
                    "font-mono font-bold mt-0.5 block",
                    extractedPreview.amount ? "text-amber-300" : "text-slate-300"
                  )}
                  data-testid="extracted-upi-amount"
                >
                  {extractedPreview.amount
                    ? `${extractedPreview.currency || "INR"} ${extractedPreview.amount}`
                    : "No Pre-Filled Amount"}
                </span>
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-2.5">
                <span className="text-[10px] font-mono uppercase text-slate-400 block">Payment Note / Remark (tn)</span>
                <span className="text-slate-200 break-words mt-0.5 block" data-testid="extracted-upi-note">
                  {extractedPreview.note || "No Payment Note"}
                </span>
              </div>
            </div>

            <div className="flex justify-end pt-1">
              <Button
                type="button"
                data-testid="analyze-upi-safety-btn"
                disabled={analyzing || !rawPayload.trim()}
                onClick={() => void handleRunUpiAnalysis()}
              >
                {analyzing ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    <span>Analyzing Payment Risk...</span>
                  </>
                ) : (
                  <>
                    <ShieldCheck className="h-4 w-4" />
                    <span>Analyze UPI / QR Payment Safety</span>
                  </>
                )}
              </Button>
            </div>
          </div>
        )}
      </Card>

      {/* UPI / QR Inspection Result Card */}
      {inspectionResult && (
        <Card
          className={cn(
            "p-5 space-y-4 border",
            inspectionResult.risk_score >= 60
              ? "border-rose-500/40 bg-rose-950/15"
              : inspectionResult.risk_score >= 30
                ? "border-amber-500/40 bg-amber-950/15"
                : "border-emerald-500/30 bg-slate-900/80"
          )}
          data-testid="upi-inspection-result-card"
        >
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3.5">
            <div className="flex items-center gap-3">
              {inspectionResult.risk_score >= 30 ? (
                <ShieldAlert className="h-7 w-7 text-rose-400 shrink-0" />
              ) : (
                <CheckCircle2 className="h-7 w-7 text-emerald-400 shrink-0" />
              )}
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <h3 className="text-base font-bold text-white">
                    {inspectionResult.risk_score >= 30
                      ? "Suspicious / High-Risk Payment Pattern Detected"
                      : "Syntactically Valid UPI Format (Unverified Recipient)"}
                  </h3>
                  <Badge
                    tone={
                      inspectionResult.risk_score >= 60
                        ? "danger"
                        : inspectionResult.risk_score >= 30
                          ? "warning"
                          : "success"
                    }
                  >
                    Risk Score: {inspectionResult.risk_score} / 100 ({inspectionResult.risk_level})
                  </Badge>
                </div>
                <p className="text-xs text-slate-300 mt-0.5">{inspectionResult.guidance}</p>
              </div>
            </div>
          </div>

          {/* Detailed Warnings */}
          {inspectionResult.warnings.length > 0 ? (
            <div className="space-y-2.5">
              <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
                Detected UPI / QR Security Warnings
              </span>
              {inspectionResult.warnings.map((w, idx) => (
                <div
                  key={idx}
                  data-testid={`upi-warning-${w.code}`}
                  className={cn(
                    "rounded-xl border p-3.5 space-y-1",
                    w.severity === "high"
                      ? "border-rose-500/35 bg-rose-950/25 text-rose-100"
                      : "border-amber-500/35 bg-amber-950/25 text-amber-100"
                  )}
                >
                  <div className="flex items-center justify-between gap-2 font-semibold text-xs">
                    <span>{w.title}</span>
                    <Badge tone={w.severity === "high" ? "danger" : "warning"}>{w.severity.toUpperCase()}</Badge>
                  </div>
                  <p className="text-xs text-slate-200 leading-relaxed">{w.explanation}</p>
                </div>
              ))}
            </div>
          ) : (
            <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-3.5 text-xs text-slate-300">
              No deceptive refund/cashback lure keywords, auto-debit mandates, or handle typos were detected in this payment string.
            </div>
          )}

          {/* Mandatory Non-Verification & Non-Payment Disclaimers */}
          <div
            className="rounded-xl border border-amber-500/30 bg-slate-950/90 p-3.5 space-y-1.5 text-[11px] text-slate-300"
            data-testid="upi-safety-disclaimers"
          >
            <div className="font-semibold text-amber-300 flex items-center gap-1.5">
              <Lock className="h-3.5 w-3.5" />
              <span>Important Verification & Safety Limitations</span>
            </div>
            <ul className="list-disc pl-5 space-y-1 text-slate-400">
              {inspectionResult.safety_disclaimers.map((d, i) => (
                <li key={i}>{d}</li>
              ))}
            </ul>
          </div>
        </Card>
      )}
    </div>
  );
}
