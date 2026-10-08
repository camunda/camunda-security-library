---
status: Accepted
---

# ADR-0032: Include per-scope OIDC providers in the per-issuer bearer-token claim-converter map

**Deciders**: Tim Cline

## Status

Accepted

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
- **Cross-source issuer overlap is logged at `DEBUG`, not `WARN`.** Unlike two root registrations
  colliding on an issuer — which ADR-0024 deliberately warns about on every collision because it can
  silently misattribute a principal — the same issuer legitimately recurring across scopes is an
  expected shape of a physical-tenant deployment. Warning on it would be noise, so the overlap is
  recorded at `DEBUG`. The within-source duplicate-issuer `WARN` from `IssuerOwnership` is preserved
  for each source.
- **Scope providers injected via `ObjectProvider`.** Zero scope-provider beans (Hub, single-tenant
  OC) resolves to an empty stream, so the map is identical to the pre-change output.

## Consequences

**Positive**

- REST and gRPC now resolve a physical tenant's bearer tokens with the same per-provider claim
  configuration; the `401` of camunda/camunda#64685 is fixed server-side, with no client release.
- Purely additive: closes the trade-off ADR-0024 recorded without changing any existing wiring or
  requiring a new SPI — the fix extends the data the existing bean is built from.

**Negative / accepted trade-offs**

- The map remains keyed by issuer alone. If two scopes share one issuer but configure *different*
  claims, the first-contributed scope's converter wins for that issuer; a genuinely
  per-scope-and-per-issuer converter (giving each scoped chain its own converter) is out of scope
  here, as it was in #668. The physical-tenant motivating case uses a distinct issuer per tenant, so
  this does not affect it.
- A scope whose issuer a root-level provider already owns keeps the root converter; a scope cannot
  override the cluster default's claim configuration for a shared issuer through this path.

## Alternatives Considered

- **Give each scoped API chain its own `OidcTokenAuthenticationConverter` / `TokenClaimsConvertersByIssuer`.**
  Rejected for this fix — it would disambiguate scopes that share an issuer with different claims,
  but the scoped API chain delegates `CamundaAuthentication` conversion to the single global
  converter today, so this is a larger restructuring than the bug needs. #668 scoped it out, and the
  motivating deployment uses distinct issuers per tenant.
- **Feed scope providers into `OidcProviderConfigurationPort#getOidcAuthenticationConfigurations()`
  instead.** Rejected — that port backs the cluster-level decoder, client-registration, and
  validation wiring; merging scope-only providers into it would change those unrelated surfaces and
  the cluster's primary chain, well beyond the claim-converter map this bug concerns.
- **Warn on every cross-source issuer overlap, mirroring the root duplicate-issuer `WARN`.**
  Rejected — the overlap is an expected, benign shape of physical-tenant deployments (the default
  tenant recurs at root and as a scope), so a `WARN` per request-chain build would be alarming noise.
