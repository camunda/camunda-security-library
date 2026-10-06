---
status: Accepted
---

# ADR-0032: Scope the login CSRF guard to state-changing requests

**Deciders**: Patrick Wunderlich

## Status

Accepted

## Context

[ADR-0027](0027-enforce-csrf-on-login-unconditionally.md) made CSRF protection on `/login` (and its
scoped `<basePath>/login` variants) unconditional, and failed startup whenever an unprotected pattern
matched a login path. It claimed no host-side change was required; that did not hold for Hub, whose
`unprotectedPaths()` covers `/login` ([#710](https://github.com/camunda/camunda-security-library/issues/710),
camunda/camunda-hub#29491).

This ADR refines ADR-0027; it does not supersede it. A state-changing request to the login endpoint
still always needs a valid CSRF token. For the unscoped `/login`, the startup fail-fast becomes
method-aware routing, because the attack ADR-0027 closes (a cross-site `POST /login`) needs a
state-changing method, while serving `GET /login` unauthenticated is what the login page needs anyway.

Scoped login paths differ: scoped chains use a per-scope CSRF cookie name and path, so the
unprotected chain cannot issue a token that a scoped `POST <basePath>/login` would accept.

The question this ADR answers: how can safe-method requests to an unscoped `/login` covered by
`unprotectedPaths()` be served unauthenticated while every state-changing login request still
requires a valid CSRF token?

## Decision

The `unprotectedPathsSecurityFilterChain` (order 0, `BaseSecurityConfiguration`) matches
`unprotectedPaths() AND NOT (state-changing request to /login)`. Safe methods are GET, HEAD, TRACE
and OPTIONS, via `CsrfProtectionRequestMatcher.isSafeMethod`.

- Safe-method requests to `/login` are served by the unprotected chain without authentication.
- State-changing requests to `/login` are excluded from that chain and fall through to the API or
  webapp chain, which still enforces CSRF on `/login` unconditionally (ADR-0027), or to the
  catch-all deny chain, which rejects them.
- With CSRF enabled the unprotected chain always installs token issuance, never enforcement; it
  writes the token only on a login-path request it serves (with the host's path builder), using
  the same cookie repository as the unscoped chains. The overlap check only drives startup
  logging.
- `SecurityFilterChainSupport#rejectScopedLoginOverlap` replaces the unscoped fail-fast. When
  `camunda.security.csrf.enabled` is true, a pattern in `unprotectedPaths()` that matches a scoped
  `<basePath>/login` still fails startup with an `IllegalStateException` citing this ADR.

### Why these particular boundaries

- **Method, not path.** The path-level exemption was the vulnerability; the safe-method read is not.
  Tying the carve-out to the same safe-method predicate the CSRF matcher uses keeps the two from
  drifting.
- **Routing instead of exempting.** The unprotected chain never sees a state-changing login, so no
  chain other than the CSRF-enforcing one can accept it.
- **Scoped overlaps still fail fast (with CSRF enabled).** The failure mode of routing them is a
  login page that can never be submitted, which is worse than a startup error naming the pattern.

## Consequences

**Positive**

- Hub (and any host with a broad unprotected pattern) starts again with no host-side change.
- Login CSRF protection from ADR-0027 is unchanged for every state-changing request.
- Hosts that moved `/login` into `unprotectedApiPaths()` to get past the 1.1.0 startup failure can
  move it back to `unprotectedPaths()`.

**Negative / accepted trade-offs**

- `unprotectedPaths()` is method-dependent for `/login`: a host reading its own config sees `/login`
  listed as unprotected, but only its safe methods are. This is the declared-versus-actual
  difference ADR-0027 wanted to avoid; it is accepted here because it is documented on the port
  and logged at startup.
- An OIDC host that lists `/login` as unprotected shadows `CamundaLoginPickerFilter`, because
  `GET /login` never reaches the webapp chain.
- With the catch-all chain disabled and no chain claiming `POST /login`, that request is unsecured.
- With CSRF enabled, scoped overlaps still fail fast, so a host with scoped chains must keep its
  unprotected patterns off every `<basePath>/login`. With CSRF disabled the check does not run.
- Under a servlet path (a host `PathPatternRequestMatcher.Builder` with a basePath), the downstream
  `CsrfProtectionRequestMatcher` and the webapp/API chains' token response filter still match with
  `PathPatternRequestMatcher.withDefaults()`. This gap predates this ADR (it exists on main for all
  hosts) and is out of its scope, so the unconditional login guard does not yet hold for
  `<servlet-path>/login`. Only the unprotected chain's token issuance honours the builder.

## Alternatives Considered

- **Document `unprotectedApiPaths()` as the workaround.** Rejected: it requires the pattern to be a
  subset of `apiPaths()`, which breaks hosts with a narrow `apiPaths()`.
- **A new `unprotectedReadOnlyPaths()` port method.** Rejected: it adds API surface for something
  the existing declaration can already express.
- **Route scoped overlaps too.** Rejected: no scoped token can be issued by the unprotected chain
  (see Context), so scoped `GET /login` would succeed while `POST` is always rejected.
- **Keep ADR-0027's unscoped fail-fast.** Rejected: it broke Hub (#710) for a pattern that is safe
  to serve for read-only methods.
