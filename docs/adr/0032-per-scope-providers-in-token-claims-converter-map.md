---
status: Accepted
---

# ADR-0032: Include per-scope OIDC providers in the per-issuer bearer-token claim-converter map

**Deciders**: Tim Cline

## Status

Accepted. This ADR delivers the per-scope follow-up
([#668](https://github.com/camunda/camunda-security-library/issues/668)) that
[ADR-0024](0024-per-issuer-token-claims-converter-map.md) deferred; ADR-0024 itself remains in
force. The shared-issuer gap it surfaces (below) is tracked onward as
[#714](https://github.com/camunda/camunda-security-library/issues/714).

## Context

[ADR-0024](0024-per-issuer-token-claims-converter-map.md) introduced
`TokenClaimsConvertersByIssuer`, an issuer-keyed lookup of `LazyTokenClaimsConverter`s that lets
`OidcTokenAuthenticationConverter` resolve a bearer token's principal with the claim configuration
(`username-claim` / `client-id-claim` / `prefer-username-claim`) of the provider that actually issued
it. `OidcBeansConfiguration#tokenClaimsConvertersByIssuer` built that map from
`OidcProviderConfigurationPort#getOidcAuthenticationConfigurations()` only — the cluster-level flat
`oidc.*` block plus `providers.oidc.*`.

ADR-0024 explicitly accepted, as a tracked follow-up ([#668](https://github.com/camunda/camunda-security-library/issues/668)),
that providers declared *only* through a per-scope `CamundaSecurityScopeProvider` descriptor
([ADR-0013](0013-camunda-security-scope-provider-spi.md)) were absent from the map, so their bearer
tokens fell back to the cluster-default converter.

That gap is the root cause of [camunda/camunda#64685](https://github.com/camunda/camunda/issues/64685):
on an Orchestration Cluster with physical tenants, a tenant's own identity provider lives only inside
that tenant's scope descriptor (the host unifies the cluster-level config to the default tenant's
providers). A bearer token issued by `tenanta`'s provider is verified by the scope's own
`JwtDecoder` but then converted with the *default* tenant's claim settings, finds neither configured
claim, and is rejected with `401 invalid_token`. gRPC, which resolves claims per scope, accepts the
same token — so REST and gRPC disagree on identical tokens.

The scope descriptors' providers are already available to CSL (every descriptor carries its own
`AuthenticationConfiguration`, flattened by `ScopedClientRegistrationFactory#flatten` exactly as the
root config port flattens the cluster config). The question this ADR answers: how should the global
per-issuer claim-converter map incorporate scope-only providers so REST resolves their tokens with
the issuing provider's own claims, without changing behaviour for deployments that use no scopes?

## Decision

`OidcBeansConfiguration#tokenClaimsConvertersByIssuer` now builds its `byIssuer` map from two
sources, in order:

1. the root-level providers (`getOidcAuthenticationConfigurations()`), exactly as before; then
2. every provider contributed by any `CamundaSecurityScopeProvider` bean — each descriptor's
   `AuthenticationConfiguration` is flattened with the injected `ScopedClientRegistrationFactory` and
   its issuer-owning providers are added.

The per-provider converter-building logic (reuse the shared default `LazyTokenClaimsConverter` bean
for the flat block by reference identity; build a dedicated converter from every other provider's
claim settings; skip providers with no `issuer-uri`; dedup per issuer via `IssuerOwnership`) is
unchanged and shared between both sources through a private helper.

### Why these particular boundaries

- **Root-level providers win a shared issuer; scopes are additive.** The root source is processed
  first and a later source never overwrites an issuer already present. A deployment with no scope
  providers is therefore byte-for-byte unchanged, and the common case where the same issuer recurs
  across scopes (the default tenant appears both at root and as its own scope) keeps the existing
  root/default converter rather than rebuilding it.
- **Cross-source issuer overlap warns only when the dropped claim settings differ.** When a scope
  repeats an issuer an earlier source already owns, the owning source keeps it. If the two sources'
  `username-claim` / `client-id-claim` / `prefer-username-claim` are *identical* (the default tenant
  appearing both at root and as its own scope) the overlap is benign and logged at `DEBUG`. If they
  *differ*, a token from the dropped source can be misresolved, so it is logged at `WARN` naming both
  sources and linking the follow-up
  [#714](https://github.com/camunda/camunda-security-library/issues/714). Both diagnostics name the
  owning source and redact the issuer URI (the issuer-uri check is warn-only, so a credential-bearing
  value can reach them). The within-source duplicate-issuer `WARN` from `IssuerOwnership` is
  preserved for each source, now carrying the scope's `basePath`. The map is a startup singleton, so
  each diagnostic fires at most once per overlapping issuer at context build, not per request.
- **Scope providers injected via `ObjectProvider`.** Zero scope-provider beans (Hub, single-tenant
  OC) resolves to an empty stream, so the map is identical to the pre-change output. Its iteration
  order is not guaranteed to match `ScopedSecurityChainRegistrar`'s bean-name order; that only
  affects which of two scopes *sharing one issuer* wins, which is exactly the case #714 resolves, so
  until then "first scope wins" is best-effort for that overlap and exact for every distinct issuer.
  The `get()` results are null-checked here with the same messages the registrar uses, so a provider
  contract violation fails with a clear error rather than an anonymous `NullPointerException`.

## Consequences

**Positive**

- REST and gRPC now resolve a physical tenant's bearer tokens with the same per-provider claim
  configuration **when each tenant has a distinct issuer** (the motivating case); the `401` of
  camunda/camunda#64685 is fixed server-side, with no client release. Tenants that share one issuer
  with differing claims remain unresolved — see the trade-off below and #714.
- Purely additive: closes the trade-off ADR-0024 recorded without changing any existing wiring or
  requiring a new SPI — the fix extends the data the existing bean is built from.

**Negative / accepted trade-offs**

- The map remains keyed by issuer alone, so two sources sharing one issuer with *different* claim
  settings cannot both be honoured — the first-processed source wins and the other is dropped. This
  is not only the benign default-tenant overlap: a single Microsoft Entra issuer can serve multiple
  app registrations whose claims differ (`preferred_username` vs `upn`, `azp` vs `appid`, v1 vs v2
  tokens), so two physical tenants backed by one Entra tenant hit it. This change surfaces the
  collision with a `WARN` but does not yet resolve it; a genuinely per-scope converter (giving each
  scoped chain its own converter) is tracked as
  [#714](https://github.com/camunda/camunda-security-library/issues/714). A deployment that gives
  each tenant a distinct issuer — the motivating case — is unaffected.
- A scope whose issuer a root-level provider already owns keeps the root converter; a scope cannot
  override the cluster default's claim configuration for a shared issuer through this path (also
  #714).

## Alternatives Considered

- **Give each scoped API chain its own `OidcTokenAuthenticationConverter` / `TokenClaimsConvertersByIssuer`.**
  Deferred, not rejected — it would disambiguate scopes that share an issuer with different claims,
  but the scoped API chain delegates `CamundaAuthentication` conversion to the single global
  converter today, so this is a larger restructuring than the bug needs. #668 scoped it out, and the
  motivating deployment uses distinct issuers per tenant; it is now tracked as
  [#714](https://github.com/camunda/camunda-security-library/issues/714).
- **Feed scope providers into `OidcProviderConfigurationPort#getOidcAuthenticationConfigurations()`
  instead.** Rejected — that port backs the cluster-level decoder, client-registration, and
  validation wiring; merging scope-only providers into it would change those unrelated surfaces and
  the cluster's primary chain, well beyond the claim-converter map this bug concerns.
- **Warn on every cross-source issuer overlap, mirroring the root duplicate-issuer `WARN`.**
  Rejected — the default tenant legitimately recurs at root and as a scope with *identical* claim
  settings, so warning on every overlap would fire a spurious startup `WARN` for the most common
  physical-tenant layout. Warning only when the claim settings actually differ keeps the signal
  meaningful while staying quiet for the benign case.
- **Say nothing when the dropped claim settings differ (keep the original `DEBUG`-only overlap).**
  Rejected after review — the Entra single-issuer / multiple-app-registration case makes a differing
  overlap a realistic misconfiguration, not a corner case, so it warrants a `WARN` and a tracked
  follow-up ([#714](https://github.com/camunda/camunda-security-library/issues/714)) rather than a
  silent `DEBUG` line.
