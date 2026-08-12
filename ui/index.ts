/**
 * `@auth` — the Auth plugin's shared UI.
 *
 * The pages under `site/Pages` are federated automatically by `hkm ui sync`;
 * this barrel is for the pieces a PROJECT or another plugin reuses — chiefly the
 * login form, so a custom sign-in page keeps the platform's behaviour (CSRF,
 * 422 field errors, 429 handling, redirect resolution) without reimplementing it.
 */
export { LoginForm } from "./components/LoginForm";
export type { LoginFormProps } from "./components/LoginForm";
