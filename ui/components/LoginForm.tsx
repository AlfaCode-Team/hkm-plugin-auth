import { useState, type FormEvent, type ReactNode } from "react";
import { Eye, EyeOff, KeyRound, Loader2, LogIn, Mail } from "lucide-react";
import { csrfHeaderName, csrfToken } from "@pageflow/core";
import { Button } from "@ui/button";
import { Input } from "@ui/input";
import { Label } from "@ui/label";
import { Checkbox } from "@ui/checkbox";
import { cn } from "@lib/utils";

/**
 * The platform's default sign-in form.
 *
 * It talks to the Auth plugin's own `POST /auth/login`
 * (`SessionAuthController@login`), which the plugin already ships — so this is
 * the front end of an endpoint that exists, not a new contract.
 *
 * Deliberately dependency-free: HKM 0.3's version pulled in `axios`,
 * `react-hook-form`, `@hookform/resolvers` and `zod` to post two fields. This
 * uses `fetch` plus Pageflow's CSRF helpers, so a project that ships nothing but
 * a login page installs nothing extra. The three-line client-side check exists
 * to save a round trip; the SERVER is the validator, and its 422 field errors
 * are rendered verbatim.
 *
 * Submitting with `Accept: application/json` is what makes the response
 * predictable: `Request::expectsJson()` is then true, so the controller answers
 * `{ data: { user, redirectTo } }` rather than a 302 the SPA cannot follow.
 * Navigation afterwards is a FULL document load, on purpose — see the note at
 * the call site.
 */

export interface LoginFormProps {
  /** Where to go after a successful sign-in. Overrides the server's choice. */
  redirectTo?: string;
  /** Prefill the identifier (e.g. from an invitation link). */
  defaultIdentifier?: string;
  /** Endpoint. Default `/auth/login`. */
  action?: string;
  /**
   * Password-reset PAGE. Omitted by default, which hides the link.
   *
   * The plugin ships `POST /auth/password/forgot` — the endpoint — but no GET
   * page for it, so there is no correct default to point at: linking to the POST
   * route would 405. Set `AUTH_FORGOT_PASSWORD_URL` once you have a page.
   */
  forgotPasswordUrl?: string;
  /** Rendered under the submit button — a register link, SSO buttons, … */
  footer?: ReactNode;
  /** Server-supplied errors (e.g. after a hard redirect back). */
  initialErrors?: FieldErrors;
  submitLabel?: string;
  className?: string;
  /** Called instead of navigating, when the host page wants to handle it. */
  onSuccess?: (result: { redirectTo: string; user: unknown }) => void;
}

type FieldErrors = Partial<Record<"identifier" | "password" | "form", string>>;

interface LoginOkBody {
  data?: { redirectTo?: string; user?: unknown };
  redirectTo?: string;
  user?: unknown;
}

interface LoginErrorBody {
  error?: { message?: string; fields?: Record<string, string | string[]> };
  message?: string;
  errors?: Record<string, string | string[]>;
}

function firstMessage(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) return value.find((v) => typeof v === "string" && v !== "");
  return value || undefined;
}

export function LoginForm({
  redirectTo,
  defaultIdentifier = "",
  action = "/auth/login",
  forgotPasswordUrl,
  footer,
  initialErrors,
  submitLabel = "Sign in",
  className,
  onSuccess,
}: LoginFormProps) {
  const [identifier, setIdentifier] = useState(defaultIdentifier);
  const [password, setPassword] = useState("");
  const [remember, setRemember] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [errors, setErrors] = useState<FieldErrors>(initialErrors ?? {});

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (submitting) return;

    // Save a round trip on the obvious cases; the server still validates.
    const local: FieldErrors = {};
    if (!identifier.trim()) local.identifier = "Enter your email or username.";
    if (!password) local.password = "Enter your password.";
    if (Object.keys(local).length > 0) {
      setErrors(local);
      return;
    }

    setErrors({});
    setSubmitting(true);

    try {
      const token = csrfToken();
      const response = await fetch(action, {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          "X-Requested-With": "XMLHttpRequest",
          ...(token ? { [csrfHeaderName()]: token } : {}),
        },
        body: JSON.stringify({
          identifier: identifier.trim(),
          password,
          remember,
          ...(redirectTo ? { redirectTo } : {}),
        }),
      });

      const body: unknown = await response.json().catch(() => ({}));

      if (response.ok) {
        const ok = body as LoginOkBody;
        const target = ok.data?.redirectTo ?? ok.redirectTo ?? redirectTo ?? "/";
        const user = ok.data?.user ?? ok.user;

        if (onSuccess) {
          onSuccess({ redirectTo: target, user });
          return;
        }

        // A FULL document navigation, deliberately — not `router.visit`.
        //
        // Sign-in is a privilege transition: the session cookie, the CSRF token
        // bound to it, and every shared prop derived from `Identity` (the whole
        // `adminShell` object) are now stale in this document. A Pageflow visit
        // would carry the old shell state and the old token forward. It would
        // also assume the target renders through Pageflow, which a plain `/`
        // need not.
        window.location.assign(target);
        return;
      }

      const failure = body as LoginErrorBody;
      const fields = failure.error?.fields ?? failure.errors;

      if (response.status === 422 && fields) {
        setErrors({
          identifier: firstMessage(fields.identifier ?? fields.email),
          password: firstMessage(fields.password),
        });
        return;
      }

      setErrors({
        form:
          response.status === 401
            ? (failure.error?.message ?? "That email or password is not correct.")
            : response.status === 429
              ? "Too many attempts. Wait a moment and try again."
              : (failure.error?.message ??
                failure.message ??
                "Sign-in failed. Please try again."),
      });
    } catch {
      setErrors({ form: "Could not reach the server. Check your connection." });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form onSubmit={submit} className={cn("space-y-4", className)} noValidate>
      {errors.form && (
        <div
          role="alert"
          className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive"
        >
          {errors.form}
        </div>
      )}

      <div className="space-y-1.5">
        <Label htmlFor="login-identifier">Email or username</Label>
        <div className="relative">
          <Mail
            className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground"
            aria-hidden="true"
          />
          <Input
            id="login-identifier"
            name="identifier"
            autoComplete="username"
            autoFocus
            className="pl-10"
            placeholder="you@example.com"
            disabled={submitting}
            aria-invalid={!!errors.identifier}
            aria-describedby={errors.identifier ? "login-identifier-error" : undefined}
            value={identifier}
            onChange={(e) => setIdentifier(e.target.value)}
          />
        </div>
        {errors.identifier && (
          <p id="login-identifier-error" className="text-xs text-destructive">
            {errors.identifier}
          </p>
        )}
      </div>

      <div className="space-y-1.5">
        <div className="flex items-center justify-between">
          <Label htmlFor="login-password">Password</Label>
          {forgotPasswordUrl && (
            <a
              href={forgotPasswordUrl}
              className="text-xs text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
            >
              Forgot password?
            </a>
          )}
        </div>
        <div className="relative">
          <KeyRound
            className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground"
            aria-hidden="true"
          />
          <Input
            id="login-password"
            name="password"
            type={showPassword ? "text" : "password"}
            autoComplete="current-password"
            className="pl-10 pr-10"
            placeholder="••••••••"
            disabled={submitting}
            aria-invalid={!!errors.password}
            aria-describedby={errors.password ? "login-password-error" : undefined}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <button
            type="button"
            onClick={() => setShowPassword((v) => !v)}
            aria-label={showPassword ? "Hide password" : "Show password"}
            aria-pressed={showPassword}
            className="absolute right-0 top-0 flex h-full items-center px-3 text-muted-foreground hover:text-foreground"
          >
            {showPassword ? (
              <EyeOff className="h-4 w-4" aria-hidden="true" />
            ) : (
              <Eye className="h-4 w-4" aria-hidden="true" />
            )}
          </button>
        </div>
        {errors.password && (
          <p id="login-password-error" className="text-xs text-destructive">
            {errors.password}
          </p>
        )}
      </div>

      <div className="flex items-center gap-2">
        <Checkbox
          id="login-remember"
          checked={remember}
          disabled={submitting}
          onCheckedChange={(checked) => setRemember(checked === true)}
        />
        <Label htmlFor="login-remember" className="text-sm font-normal">
          Keep me signed in
        </Label>
      </div>

      <Button type="submit" className="w-full" disabled={submitting}>
        {submitting ? (
          <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" />
        ) : (
          <LogIn className="mr-2 h-4 w-4" aria-hidden="true" />
        )}
        {submitting ? "Signing in…" : submitLabel}
      </Button>

      {footer}
    </form>
  );
}

export default LoginForm;
