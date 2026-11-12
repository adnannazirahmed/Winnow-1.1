# Winnow public release

The supplied Open Design pages are in `website/`. The GitHub Pages build packages them with the real workbench from `frontend/` at `app/`. `request-access.html` redirects to open GitHub sign-in. The light/dark choice is saved in the browser.

## Hosting

- **GitHub Pages:** marketing, account pages, and static workbench. The `pages` CI job runs only after a `WINNOW_API_ORIGIN` repository variable is set to a real HTTPS Render API origin.
- **Supabase:** open GitHub OAuth authentication and `public.analysis_runs`. The table is protected with row-level security so each user can access only their own saved analysis. Migration: `supabase/migrations/202611110001_analysis_runs.sql`.
- **Render:** Python analysis API. It is stateless in hosted mode: analysis history goes to Supabase, and each API call validates the Supabase user token. Set `WINNOW_PUBLIC_MODE=1`, `SUPABASE_URL`, `SUPABASE_ANON_KEY`, and `WINNOW_PUBLIC_ORIGIN=https://adnannazirahmed.github.io`.

The Supabase key committed in `supabase-config.js` is publishable. Never put a secret or service-role key in the site or its GitHub Actions build.

## Launch work still required

1. Create a GitHub OAuth app in the repository owner's GitHub account. Set its homepage to `https://adnannazirahmed.github.io/Winnow-1.1/` and callback to `https://vfdfldezujsncttfrgvg.supabase.co/auth/v1/callback`. Put its client ID and secret in the Supabase GitHub provider settings, enable GitHub, allow new user sign-ups, and disable the email/password provider. Keep the site URL and redirect allowlist pointed at the GitHub Pages `app/` path. The `github.io` address requires no mail sending domain for GitHub OAuth.
2. Deploy the updated Python API to Render, set its environment variables, and set the GitHub repository's `WINNOW_API_ORIGIN` to its HTTPS URL. The current Render account has no service.
3. Implement account-specific AWS and AI connections if those features are part of launch. Hosted mode currently disables the shared local settings and AWS scans; uploaded and pasted policy analysis remains available.
4. Test the deployed GitHub sign-in, new account creation, sign-out, analysis, and cross-account flows before enabling Pages deployment.
