---
status: Accepted
---

# ADR-0027: Enforce CSRF unconditionally on the login endpoint

**Deciders**: Timothy Cline

## Status

Accepted

## Context

`/login` (and its scoped `<basePath>/login` variants) was one of two paths
(`/login`, `/logout`) always exempted from CSRF protection in
`SecurityFilterChainSupport#csrfAllowedPaths`, regardless of session state. The
generic CSRF rule for everything else already only requires a token once a
browser holds a session (`CsrfProtectionRequestMatcher#matches`: safe methods
and allowed paths aside, protection kicks in only when
`request.getSession(false) != null`) — the reasoning was that a browser with
no session yet has nothing a forged cross-site request could ride on.

That reasoning does not hold for `/login` itself. An external penetration test
(NATO NCSC; tracked as camunda/security-testing-findings#281) demonstrated
that a victim who already has an authenticated browser session can be sent to
an attacker-controlled page that auto-submits a cross-site
`POST /login?username=attacker&password=...` form. Because `/login` was
unconditionally exempt, Spring Security's `UsernamePasswordAuthenticationFilter`
processed the forged credentials with no CSRF check, silently replacing the
victim's session with one authenticated as the attacker. `SameSite=Lax` on the
session cookie (CSL's default) does not stop this: a top-level form-POST
navigation is exactly what `Lax` permits.

This is login CSRF (CWE-352): the attack's whole premise is that the victim
*already has a session* by the time the forged request lands, which is
precisely the case the existing "protect once a session exists" rule was
never applied to for this one path. What is the smallest change to
`CsrfProtectionRequestMatcher`/`SecurityFilterChainSupport` that closes this
gap without breaking a legitimate, pre-session first login?

## Decision

`/login` now requires a valid CSRF token unconditionally — including on a
browser that holds no session yet, not only once a session already exists.

- `CsrfProtectionRequestMatcher` gains a second, independent path set,
  `enforcedPaths`, checked immediately after the safe-methods check — ahead of
  `allowedPaths` and the Swagger-UI carve-out, not after them: a match there
  returns `true` immediately, regardless of session state, `allowedPaths`, or
  the Swagger-UI referer. The single-arg constructor is preserved (delegating
  to an empty `enforcedPaths` set) so existing callers are unaffected.
- `SecurityFilterChainSupport#csrfAllowedPaths` no longer adds `LOGIN_URL` (or
  its scoped variant); a new `csrfEnforcedPaths` computes exactly the login
  path(s) and is passed to `CsrfProtectionRequestMatcher` alongside the
  (login-free) allowed-paths set. `/logout` keeps its unconditional exemption
  — logging a session out has no meaningful impact if forged cross-site,
  unlike logging one in.
- `csrfTokenResponseHeaderFilter`'s `writeCsrfTokenHeaderIfApplicable` is
  special-cased for the login path: both webapp chains call
  `.anonymous(AbstractHttpConfigurer::disable)`, so an unauthenticated visitor
  has no `Authentication` at all to gate the existing "authenticated GET"
  rule on. A `GET` (or any method) to the login path now writes the
  `X-CSRF-TOKEN` response header regardless of authentication state, so a
  first-time, anonymous visit to the login page still receives a token to
  echo back on the subsequent `POST /login` — otherwise no login, forged or
  legitimate, could ever succeed.

### Why these particular boundaries

- **A second path set, checked ahead of `allowedPaths`, not a removal +
  `else` branch on the existing one.** An earlier version of this change
  checked `enforcedPaths` last, after `allowedPaths` and the Swagger-UI
  carve-out — which meant a host's `camunda.security.csrf.ignored-path-patterns`
  (or an over-broad `SecurityPathPort` unprotected path) could still match
  `/login` and silently reopen the exact gap this ADR closes, since either
  carve-out short-circuited to "no protection required" before enforcement
  was ever considered. Caught in review on the PR implementing this ADR.
  Enforcement is therefore checked first: nothing in `allowedPaths`, in
  host-supplied `ignored-path-patterns`, or the Swagger-UI referer carve-out
  can exempt an enforced path — only the safe-HTTP-methods check (GET, HEAD,
  TRACE, OPTIONS) can, since those never mutate state regardless of path.
- **`/logout` is left alone.** Forcing a logout cross-site has no
  confidentiality/integrity impact worth the added complexity of finding
  another token-issuance path for it; the reported finding and its impact
  are specific to *login* CSRF.
- **Token issuance on an anonymous `GET /login` is safe.** The CSRF token has
  no meaning by itself and is not a secret to protect from an anonymous
  visitor — the double-submit design this repository already uses
  (`CookieCsrfTokenRepository`, `cookie-http-only=false`) assumes the
  browser that will submit the next request holds it. This does not
  introduce a new capability; it only extends token issuance to a state
  (anonymous, page not yet authenticated) the response-header filter
  previously didn't cover.

## Consequences

**Positive**

- Closes camunda/security-testing-findings#281: a cross-site `POST /login`
  is now rejected exactly like any other unauthenticated, forged
  state-changing request.
- The fix is scoped to CSRF wiring already owned by CSL; no host-side
  change is required once a host upgrades to the version carrying this
  ADR.

**Negative / accepted trade-offs**

- Any client that logs in without first obtaining a CSRF token (a `GET` to
  the login endpoint, or reading the `X-CSRF-TOKEN` cookie/header from an
  earlier page load) will now get `401`/`403` instead of `204` on
  `POST /login`. This is a deliberate, breaking change to the login
  contract — hosts and any script/tool driving login programmatically must
  fetch a token first. `DefaultAndScopedSessionRegressionTest#logIn` in
  this repository was updated to do exactly that as the reference shape.
- Login CSRF protection still relies on the client reading and echoing a
  cookie/header value; it is not a substitute for `Origin`/`Sec-Fetch-Site`
  validation, which remains a documented but unimplemented hardening option
  (see the security-filter-chains adopter doc).

## Alternatives Considered

- **Only enforce CSRF on `/login` once a session already exists** (i.e. let
  the existing generic "session exists" rule apply to `/login` by simply
  removing it from `allowedPaths`, with no `enforcedPaths` concept). This
  closes the exact scenario the reporter demonstrated (attacker overwrites
  an *existing* session) with a smaller diff, but leaves the very first,
  pre-session login POST forgeable — a narrower fix than the one chosen.
  Rejected in favor of enforcing CSRF on `/login` unconditionally.
- **`SameSite=Strict` on the session cookie.** Rejected as a login-CSRF fix:
  the attack forges a request that *sets* a new session cookie via
  `Set-Cookie`, so an existing cookie's `SameSite` attribute does not gate
  the forged request that creates the replacement session in the first
  place. Remains a candidate for separate, additional hardening.
- **Reject `/login` POSTs by `Origin`/`Sec-Fetch-Site` instead of (or beside)
  a CSRF token.** Cheaper for clients (no token round trip) but weaker on
  its own — some proxies and older clients omit these headers — and would
  be a materially different, additive mechanism. Left as a documented,
  separate hardening option rather than folded into this change.
