# Auth plugin UI — the platform's default sign-in

The Auth plugin owns authentication, so it also owns the default sign-in screen.
Enable the plugin and `GET /auth/login` renders a working, CSRF-correct login
page **with no project code at all**.

```
plugins/hkm-plugin-auth/ui/
├─ ui.json                        alias "@auth", surfaces { admin, site }
├─ index.ts                       barrel — exports LoginForm as @auth
├─ components/LoginForm.tsx       the form (reusable on any page)
└─ site/Pages/Auth/Login.tsx      component "Auth/Login" — the default page
```

| Method · Path | Component | Handler |
|---|---|---|
| GET `/auth/login` | `Auth/Login` | `AuthPageController@loginPage` |
| POST `/auth/login` | — | `SessionAuthController@login` (already existed) |

The GET route declares `requires: ["http.pageflow"]`; the page renders through
the same `PageflowResponder` every other plugin page uses.

## Why it is not `react-hook-form` + `zod` + `axios`

HKM 0.3's login form pulled in four dependencies to post two fields. This one
uses `fetch` plus Pageflow's own CSRF helpers, so a deployment that ships nothing
but a login page installs nothing extra. The three-line client-side check exists
only to save a round trip — **the server is the validator**, and its 422 field
errors are rendered verbatim next to the inputs.

Submitting with `Accept: application/json` is what makes the response
predictable: `Request::expectsJson()` is then true, so the controller answers
`{ data: { user, redirectTo } }` instead of a 302 the SPA cannot follow.

Navigation afterwards is a **full document load**, not a Pageflow visit. Sign-in
is a privilege transition: the session cookie, the CSRF token bound to it, and
every shared prop derived from `Identity` (the whole `adminShell` object) are
stale in the login document the moment the POST succeeds. A `router.visit` would
carry the old shell state and the old token forward, and would also assume the
redirect target renders through Pageflow — which a plain `/` need not.

What the form handles, so a custom page does not have to re-derive it:

| Status | Behaviour |
|---|---|
| 200 | reads `redirectTo` (server-chosen or explicit) and visits it |
| 422 | maps `error.fields` / `errors` onto the identifier and password inputs |
| 401 | one neutral message — never reveals whether the account exists |
| 429 | "Too many attempts", matching the route's `throttle:10,1` filter |
| network | "Could not reach the server" |

## Redirect safety

`?redirectTo=` is attacker-controlled on a public page. `AuthPageController`
passes through **relative paths only** — absolute URLs, scheme-relative
`//evil.test` and anything containing a backslash are dropped before reaching the
client. `SessionAuthController@login` applies its own guard again; this one just
keeps a bad value from ever being rendered.

## Customising

Three levels, cheapest first.

**1. Props.** The page reads `redirectTo`, `identifier`, `notice`, `appName`,
`registerUrl` and `forgotPasswordUrl`. `?reason=expired|unauthorized|logged_out`
becomes the `notice` line. `AUTH_REGISTER_URL` and `AUTH_FORGOT_PASSWORD_URL`
move the links.

**2. Your own page, our form.** Declare `Pages/Auth/Login.tsx` in your project
surface — project pages are spread first in the surface glob, so yours wins — and
keep the behaviour:

```tsx
import { LoginForm } from "@auth";
import { AuthLayout } from "@pageflow/admin";

export default function Login() {
  return (
    <div className="grid lg:grid-cols-2">
      <Brand />
      <LoginForm redirectTo="/admin" forgotPasswordUrl="/help/password" />
    </div>
  );
}
Login.layout = (page: ReactNode) => <AuthLayout>{page}</AuthLayout>;
```

`LoginForm` also takes `action`, `defaultIdentifier`, `submitLabel`, `footer`,
`initialErrors` and `onSuccess` (called instead of navigating, when the host page
wants to handle it — a modal login, for instance).

**3. Neither.** Disable the route in `proj.json`:

```jsonc
{ "routePolicy": { "disable": ["GET /auth/login"] } }
```

…then declare your own route on the freed path. Disable runs before project
routes, so there is no duplicate-route boot failure.

## Config

| Var | Default | Purpose |
|---|---|---|
| `APP_NAME` | `''` | product name in the heading |
| `AUTH_REGISTER_URL` | `/register` | sign-up link (the User plugin's page); hidden if empty |
| `AUTH_FORGOT_PASSWORD_URL` | `''` — **link hidden** | password-reset PAGE |

All three are declared in `module.json` `config[]`, as the kernel requires.

`AUTH_FORGOT_PASSWORD_URL` has no default on purpose. The plugin ships
`POST /auth/password/forgot` — the *endpoint* — but no GET page for it, so there
is nothing correct to point an `<a href>` at; the obvious-looking default would
have linked users straight into a 405. Point it at your own page once you have
one, and the link appears.

## Notes

- The page sets **no** `<Head title>` — the tab title is server-driven through
  the reserved `seoHead` prop. A sign-in screen always gets `seoPrivate()`
  (correct title + `noindex,nofollow`), never the indexable head.
- `Auth/Login` lives under `site/Pages`, but the **admin** surface globs both
  faces, so `/admin`-hosted logins resolve it too.
- Sign-out is a `POST` from `@pageflow/admin`'s sidebar to `logoutUrl`
  (default `/auth/logout`). It is deliberately not a link: log-out is a state
  change, and a GET is CSRF-reachable from any page that can embed an image.
