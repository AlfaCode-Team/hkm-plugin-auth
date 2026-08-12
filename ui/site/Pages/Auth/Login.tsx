import type { ReactNode } from "react";
import { Link, usePage } from "@pageflow/react";
import { AuthLayout } from "@pageflow/admin";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@ui/card";
import { LoginForm } from "@auth";

/**
 * The platform's DEFAULT sign-in page — component `"Auth/Login"`.
 *
 * Server: `AuthPageController@loginPage` (`GET /auth/login`). A project that
 * wants its own look declares `Pages/Auth/Login.tsx` in its own surface, which
 * the surface entry spreads FIRST and therefore wins; or it keeps this page and
 * passes different props. Either way it does not have to reimplement the form.
 *
 * The title comes from the server's `seoHead` prop, so this page sets no
 * `<Head title>` — the client syncs the tab title on every navigation.
 */
interface LoginProps extends Record<string, unknown> {
  /** Post-login target, propagated from `?redirectTo=`. */
  redirectTo?: string;
  /** Prefilled identifier, e.g. from an invitation link. */
  identifier?: string;
  /** Shown above the form — "Your session expired", "Please sign in", … */
  notice?: string;
  /** Product name in the heading. */
  appName?: string;
  /** Sign-up link. Omit to hide it (private/invite-only deployments). */
  registerUrl?: string;
  forgotPasswordUrl?: string;
}

export default function Login() {
  const { props } = usePage<LoginProps>();
  const appName = props.appName ?? "your account";

  return (
    <Card className="w-full max-w-md">
      <CardHeader className="space-y-1">
        <CardTitle className="text-2xl">Sign in</CardTitle>
        <CardDescription>Enter your details to continue to {appName}.</CardDescription>
      </CardHeader>

      <CardContent>
        {props.notice && (
          <p className="mb-4 rounded-md border border-border bg-muted/50 px-3 py-2 text-sm text-muted-foreground">
            {props.notice}
          </p>
        )}

        <LoginForm
          redirectTo={props.redirectTo}
          defaultIdentifier={props.identifier}
          forgotPasswordUrl={props.forgotPasswordUrl}
          footer={
            props.registerUrl ? (
              <p className="pt-2 text-center text-sm text-muted-foreground">
                Don&rsquo;t have an account?{" "}
                <Link href={props.registerUrl} className="text-foreground hover:underline">
                  Create one
                </Link>
              </p>
            ) : null
          }
        />
      </CardContent>
    </Card>
  );
}

Login.layout = (page: ReactNode) => <AuthLayout>{page}</AuthLayout>;
