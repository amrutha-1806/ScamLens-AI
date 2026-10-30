import { AuthError } from "@supabase/supabase-js";

/**
 * Maps Supabase authentication errors into clear, actionable, user-friendly messages.
 * Prevents generic or misleading "Wrong password" assumptions.
 */
export function formatAuthError(err: unknown, mode: "signin" | "signup" | "forgot"): string {
  if (!err) return "An unexpected error occurred. Please try again.";

  // Extract properties safely from AuthError, Error, or plain error objects
  const anyErr = err as {
    code?: unknown;
    status?: unknown;
    message?: unknown;
    error_description?: unknown;
    msg?: unknown;
  };

  const code = typeof anyErr.code === "string" ? anyErr.code.toLowerCase() : "";
  const status = typeof anyErr.status === "number" ? anyErr.status : undefined;
  const rawMsg = typeof anyErr.message === "string"
    ? anyErr.message
    : typeof anyErr.error_description === "string"
      ? anyErr.error_description
      : typeof anyErr.msg === "string"
        ? anyErr.msg
        : "";
  const msg = rawMsg.toLowerCase();

  // 1. Email not confirmed
  if (
    code === "email_not_confirmed" ||
    msg.includes("email not confirmed") ||
    msg.includes("not confirmed") ||
    msg.includes("not verified")
  ) {
    return "Your email address has not been confirmed yet. Please check your inbox for the confirmation email or reset your password.";
  }

  // 2. Invalid credentials (email doesn't exist OR password is wrong)
  if (
    code === "invalid_credentials" ||
    code === "invalid_grant" ||
    msg.includes("invalid login credentials") ||
    msg.includes("invalid credentials")
  ) {
    return "Incorrect email or password. If you recently created your account, please check whether your email address requires confirmation.";
  }

  // 3. User already registered
  if (
    code === "user_already_exists" ||
    msg.includes("user already registered") ||
    msg.includes("already registered") ||
    msg.includes("already exists")
  ) {
    return "An account with this email address already exists. Please sign in or use 'Forgot password'.";
  }

  // 4. Weak password
  if (code === "weak_password" || msg.includes("weak") || msg.includes("pwned")) {
    return "Password is too weak or commonly used. Please choose a stronger password with at least 8 characters.";
  }

  // 5. Rate limiting
  if (
    status === 429 ||
    code === "over_request_rate_limit" ||
    msg.includes("rate limit") ||
    msg.includes("too many requests")
  ) {
    return "Too many attempts in a short time. Please wait a few moments before trying again.";
  }

  // 6. Email deliverability or domain restrictions
  if (
    msg.includes("email address is not allowed") ||
    msg.includes("could not be delivered") ||
    msg.includes("placeholder, reserved, or mistyped")
  ) {
    return rawMsg;
  }

  // 7. Network / connection errors
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
