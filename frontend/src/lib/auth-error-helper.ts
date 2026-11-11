import type { EmailOtpType, SupabaseClient } from "@supabase/supabase-js";

export const PRODUCTION_SITE_URL = "https://scamlens-ai-seven.vercel.app";
export const AUTH_CALLBACK_ERROR_KEY = "scamlens_auth_callback_error";
export const AUTH_CALLBACK_SUCCESS_KEY = "scamlens_auth_callback_success";

const LOVABLE_DOMAINS = [
  "lovable.app",
  "lovable.dev",
  "lovableproject.com",
  "lovableproject-dev.com",
  "gpt-eng.com",
  "gptengineer.run",
];

/**
 * Returns a clean, canonical redirect URL for Supabase email confirmation and password recovery.
 * - Uses the current origin on localhost/127.0.0.1 for local development testing.
 * - Uses https://scamlens-ai-seven.vercel.app in production and explicitly blocks any Lovable domain.
 */
export function getAuthRedirectUrl(path: string = "/"): string {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;

  if (typeof window === "undefined") {
    return `${PRODUCTION_SITE_URL}${normalizedPath}`;
  }

  const host = window.location.hostname.toLowerCase();
  const isLocal = host === "localhost" || host === "127.0.0.1";
  const isLovable = LOVABLE_DOMAINS.some(
    (domain) => host === domain || host.endsWith(`.${domain}`)
  );

  if (isLovable) {
    return `${PRODUCTION_SITE_URL}${normalizedPath}`;
  }

  if (isLocal) {
    return `${window.location.origin}${normalizedPath}`;
  }

  return `${window.location.origin}${normalizedPath}`;
}

export interface AuthCallbackResolution {
  handled: boolean;
  authenticated: boolean;
  type: string | null;
  error: string | null;
}

const INITIAL_BROWSER_URL_SNAPSHOT =
  typeof window !== "undefined"
    ? {
        search: window.location.search,
        hash: window.location.hash,
        consumed: false,
      }
    : null;

/**
 * Inspects the current browser URL for Supabase email confirmation / recovery callback parameters:
 * - PKCE authorization code (?code=...)
 * - Token hash verification (?token_hash=...&type=signup|email|recovery|magiclink)
 * - Implicit grant hash fragment (#access_token=...&refresh_token=...)
 * - Callback error parameters (#error=...&error_description=...)
 *
 * Exchanges or sets the session, strips sensitive tokens from the URL bar, and returns the outcome.
 */
export async function resolveSupabaseAuthCallback(
  supabase: SupabaseClient<any, any, any>
): Promise<AuthCallbackResolution> {
  if (typeof window === "undefined") {
    return { handled: false, authenticated: false, type: null, error: null };
  }

  let rawSearch = window.location.search;
  let rawHashStr = window.location.hash;

  if (
    !rawSearch &&
    !rawHashStr &&
    INITIAL_BROWSER_URL_SNAPSHOT &&
    !INITIAL_BROWSER_URL_SNAPSHOT.consumed
  ) {
    rawSearch = INITIAL_BROWSER_URL_SNAPSHOT.search;
    rawHashStr = INITIAL_BROWSER_URL_SNAPSHOT.hash;
  }
  if (INITIAL_BROWSER_URL_SNAPSHOT) {
    INITIAL_BROWSER_URL_SNAPSHOT.consumed = true;
  }

  const searchParams = new URLSearchParams(rawSearch);
  const rawHash = rawHashStr.startsWith("#") ? rawHashStr.slice(1) : rawHashStr;
  const hashParams = new URLSearchParams(rawHash);

  const code = searchParams.get("code");
  const tokenHash = searchParams.get("token_hash") ?? hashParams.get("token_hash");
  const rawType = searchParams.get("type") ?? hashParams.get("type");
  const accessToken = hashParams.get("access_token");
  const refreshToken = hashParams.get("refresh_token");
  const errorParam =
    searchParams.get("error_description") ??
    hashParams.get("error_description") ??
    searchParams.get("error_code") ??
    hashParams.get("error_code") ??
    searchParams.get("error") ??
    hashParams.get("error");

  const hasCallbackParams = Boolean(
    code || tokenHash || accessToken || errorParam
  );

  if (!hasCallbackParams) {
    return { handled: false, authenticated: false, type: null, error: null };
  }

  const cleanUrl = () => {
    try {
      window.history.replaceState({}, document.title, window.location.pathname);
    } catch {
      // Ignore history API errors
    }
  };

  // 1. Handle explicit callback error from expired or already-used confirmation link
  if (errorParam && !code && !tokenHash && !accessToken) {
    const decodedError = decodeURIComponent(errorParam.replace(/\+/g, " "));
    const friendly = formatAuthError({ message: decodedError }, "verify");
    cleanUrl();
    try {
      sessionStorage.setItem(AUTH_CALLBACK_ERROR_KEY, friendly);
    } catch {
      // Ignore storage errors
    }
    return { handled: true, authenticated: false, type: rawType, error: friendly };
  }

  // 2. Handle ?token_hash=...&type=... (Email link OTP hash verification)
  if (tokenHash) {
    const otpType: EmailOtpType =
      rawType === "recovery" ||
      rawType === "invite" ||
      rawType === "magiclink" ||
      rawType === "email_change" ||
      rawType === "email"
        ? rawType
        : "signup";

    const { data, error } = await supabase.auth.verifyOtp({
      token_hash: tokenHash,
      type: otpType,
    });
    cleanUrl();

    if (error || !data.session) {
      const friendly = formatAuthError(
        error ?? { message: "Email confirmation link has expired or is invalid." },
        "verify"
      );
      try {
        sessionStorage.setItem(AUTH_CALLBACK_ERROR_KEY, friendly);
      } catch {
        // Ignore storage errors
      }
      return { handled: true, authenticated: false, type: otpType, error: friendly };
    }

    try {
      sessionStorage.setItem(
        AUTH_CALLBACK_SUCCESS_KEY,
        "Email verified! Welcome to SCAMLENS AI."
      );
    } catch {
      // Ignore storage errors
    }
    return { handled: true, authenticated: true, type: otpType, error: null };
  }

  // 3. Handle ?code=... (PKCE Code Exchange)
  if (code) {
    const { data, error } = await supabase.auth.exchangeCodeForSession(code);
    cleanUrl();

    if (error || !data.session) {
      // Check if auto-detection already exchanged the code moments earlier
      const { data: existing } = await supabase.auth.getSession();
      if (existing.session) {
        return { handled: true, authenticated: true, type: rawType, error: null };
      }
      const friendly = formatAuthError(
        error ?? { message: "Email confirmation link has expired or is invalid." },
        "verify"
      );
      try {
        sessionStorage.setItem(AUTH_CALLBACK_ERROR_KEY, friendly);
      } catch {
        // Ignore storage errors
      }
      return { handled: true, authenticated: false, type: rawType, error: friendly };
    }

    try {
      sessionStorage.setItem(
        AUTH_CALLBACK_SUCCESS_KEY,
        "Email verified! Welcome to SCAMLENS AI."
      );
    } catch {
      // Ignore storage errors
    }
    return { handled: true, authenticated: true, type: rawType, error: null };
  }

  // 4. Handle #access_token=...&refresh_token=... (Implicit Grant Hash Fragment)
  if (accessToken) {
    if (refreshToken) {
      const { data, error } = await supabase.auth.setSession({
        access_token: accessToken,
        refresh_token: refreshToken,
      });
      cleanUrl();

      if (!error && data.session) {
        try {
          sessionStorage.setItem(
            AUTH_CALLBACK_SUCCESS_KEY,
            "Email verified! Welcome to SCAMLENS AI."
          );
        } catch {
          // Ignore storage errors
        }
        return { handled: true, authenticated: true, type: rawType, error: null };
      }
    }

    const { data: sessionData } = await supabase.auth.getSession();
    cleanUrl();
    if (sessionData.session) {
      return { handled: true, authenticated: true, type: rawType, error: null };
    }

    const friendly = "Email confirmation link has expired or is invalid. Please sign in or request a new link.";
    try {
      sessionStorage.setItem(AUTH_CALLBACK_ERROR_KEY, friendly);
    } catch {
      // Ignore storage errors
    }
    return { handled: true, authenticated: false, type: rawType, error: friendly };
  }

  return { handled: false, authenticated: false, type: rawType, error: null };
}

/**
 * Maps Supabase authentication errors into clear, actionable, user-friendly messages.
 * Prevents generic or misleading "Wrong password" assumptions.
 */
export function formatAuthError(
  err: unknown,
  mode?: "signin" | "signup" | "forgot" | "verify" | "otp-signin" | "set-password"
): string {
  if (!err) return "An unexpected error occurred. Please try again.";

  const anyErr = err as {
    code?: unknown;
    status?: unknown;
    message?: unknown;
    error_description?: unknown;
    msg?: unknown;
  };

  const code = typeof anyErr.code === "string" ? anyErr.code.toLowerCase() : "";
  const status = typeof anyErr.status === "number" ? anyErr.status : undefined;
  const rawMsg =
    typeof anyErr.message === "string"
      ? anyErr.message
      : typeof anyErr.error_description === "string"
        ? anyErr.error_description
        : typeof anyErr.msg === "string"
          ? anyErr.msg
          : "";
  const msg = rawMsg.toLowerCase();

  // 1. Expired or invalid confirmation link / token
  if (
    code === "otp_expired" ||
    msg.includes("email link is invalid or has expired") ||
    msg.includes("token has expired") ||
    msg.includes("token is expired") ||
    msg.includes("otp expired")
  ) {
    return "This email confirmation or recovery link has expired or was already used. Please sign in with your email and password.";
  }

  if (
    code === "invalid_token" ||
    code === "token_not_found" ||
    code === "flow_state_not_found" ||
    code === "bad_code_verifier" ||
    msg.includes("invalid token") ||
    msg.includes("token is invalid") ||
    msg.includes("flow state") ||
    msg.includes("code verifier")
  ) {
    return "This verification link is invalid or was already used. Please try signing in with your email and password.";
  }

  // 2. Email not confirmed
  if (
    code === "email_not_confirmed" ||
    msg.includes("email not confirmed") ||
    msg.includes("not confirmed") ||
    msg.includes("not verified")
  ) {
    return "Your email address has not been confirmed yet. Please check your inbox for the confirmation link.";
  }

  // 3. Invalid credentials
  if (
    code === "invalid_credentials" ||
    code === "invalid_grant" ||
    msg.includes("invalid login credentials") ||
    msg.includes("invalid credentials")
  ) {
    return "Incorrect email or password. If you recently created your account, please check whether your email address requires confirmation.";
  }

  // 4. User already registered
  if (
    code === "user_already_exists" ||
    msg.includes("user already registered") ||
    msg.includes("already registered") ||
    msg.includes("already exists")
  ) {
    return "An account with this email address already exists. Please sign in with your password.";
  }

  // 5. Weak password
  if (code === "weak_password" || msg.includes("weak") || msg.includes("pwned")) {
    return "Password is too weak or commonly used. Please choose a stronger password with at least 8 characters.";
  }

  // 6. Rate limiting & cooldown
  if (
    status === 429 ||
    code === "over_request_rate_limit" ||
    code === "over_email_send_rate_limit" ||
    msg.includes("rate limit") ||
    msg.includes("too many requests") ||
    msg.includes("only request this after")
  ) {
    return "For security purposes, please wait 60 seconds before trying again.";
  }

  // 7. Email deliverability or domain restrictions
  if (
    msg.includes("email address is not allowed") ||
    msg.includes("could not be delivered") ||
    msg.includes("placeholder, reserved, or mistyped")
  ) {
    return rawMsg;
  }

  // 8. Network / connection errors
  if (
    status === 0 ||
    msg.includes("failed to fetch") ||
    msg.includes("network") ||
    msg.includes("connection refused")
  ) {
    return "Unable to connect to the authentication server. Please check your internet connection.";
  }

  if (rawMsg) return rawMsg;
  return "Something went wrong. Please try again.";
}
