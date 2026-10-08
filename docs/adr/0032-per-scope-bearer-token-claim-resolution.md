---
status: Accepted
---

# ADR-0032: Resolve bearer-token claims per scope for path-scoped OIDC API chains

**Deciders**: Tim Cline

## Status

Accepted. Builds on [ADR-0024](0024-per-issuer-token-claims-converter-map.md) (the issuer-keyed
map), [ADR-0013](0013-camunda-security-scope-provider-spi.md) (the scope SPI), and
[ADR-0016](0016-cors-and-https-redirect-host-hooks.md) (the per-chain JWT-converter hook). Delivers
[#668](https://github.com/camunda/camunda-security-library/issues/668) /
[#714](https://github.com/camunda/camunda-security-library/issues/714).

## Context

A bearer token's principal is resolved in two decoupled stages. The OAuth2 resource server decodes
the token into a plain `JwtAuthenticationToken`; later, on first access, the global
`CamundaAuthenticationProvider` runs that token through the host-registered
`OidcTokenAuthenticationConverter`, which maps claims to a `CamundaAuthentication` using the
`TokenClaimsConvertersByIssuer` map keyed by the token's `iss` (ADR-0024).

That map is **keyed by issuer alone and is global** — it has no notion of which scope a request hit.
On an Orchestration Cluster with physical tenants (the [ADR-0013](0013-camunda-security-scope-provider-spi.md)
`CamundaSecurityScopeProvider` use case), two tenants can share one OIDC issuer yet configure
different claims — a single Microsoft Entra issuer serving two app registrations whose
`username-claim` differs (`preferred_username` vs `upn`), for example. The global map can hold only
one converter per issuer, so one tenant's tokens are resolved with the other's claim configuration:
either the `401 invalid_token` of [camunda/camunda#64685](https://github.com/camunda/camunda/issues/64685),
or, worse, a silently misattributed principal.

An earlier in-review approach added scope providers to that global map. It fixes the distinct-issuer
case but is structurally unable to fix the shared-issuer case, because the only discriminator
available at the global resolution point is the issuer. The gRPC path does not have this problem: it
resolves per scope.

The scope is known at exactly one place on the REST path: inside the scope's own filter chain, where
the request path is matched. The question this ADR answers: how can a bearer token be resolved with
its scope's own claim configuration, given that the global converter is path-unaware and
host-registered?

## Decision

Resolve the principal **inside each scope's API filter chain** and carry the result, rather than
recomputing it later globally. Three pieces, all in `spring-boot-starter`:

1. **`ScopedOidcTokenAuthenticationConverterFactory`** (`spring/oidc`) builds a per-scope
   `Converter<Jwt, Authentication>` from a scope's `AuthenticationConfiguration`. It assembles the
   scope's own `OidcTokenAuthenticationConverter` — the scope's per-issuer claim map (built from the
   scope's providers exactly as `OidcBeansConfiguration` builds the cluster's), its default
   converter, and its claims provider (`ScopedOidcClaimsProviderFactory`) — runs it, and wraps the
   resulting `CamundaAuthentication` in a carrier token. It sits alongside the existing
   `ScopedJwtDecoderFactory` and `ScopedOidcClaimsProviderFactory`.

2. **`ScopedCamundaAuthenticationToken`** (`spring/scope`) is the carrier: an `Authentication` that
   holds the already-resolved `CamundaAuthentication` (and the raw `Jwt`). **`ScopedCamundaAuthenticationConverter`**
   is a `CamundaAuthenticationConverter` bean that unwraps it.

3. **`ScopedSecurityChainRegistrar`** passes the per-scope converter into
   `ScopedApiSecurityChainBuilder.buildScopedApiChain(...)` via the `oidcAuthenticationConverterSupplier`
   hook (ADR-0016), so the scope's bearer filter produces the carrier token directly.

The factory bean is registered in `ScopedOidcInfrastructureConfiguration`, gated on `MembershipPort`
(which the per-scope `LazyTokenClaimsConverter`s need). When it is absent the registrar supplies no
converter and the scope falls back to the global path — a deployment without `MembershipPort` does
no CSL OIDC principal resolution anyway.

### Why these particular boundaries

- **Resolve in the chain, carry the result — don't re-key the global map.** The scope is only known
  where the path is matched. Resolving there and carrying the principal is the single point that has
  the information issuer-keying lacks; it is also what the gRPC path effectively does.
- **A sibling token type, not a `JwtAuthenticationToken` subtype.** The host's global
  `OidcTokenAuthenticationConverter` opts in to `JwtAuthenticationToken`. Making the carrier a
  *sibling* of that type (both extend `AbstractAuthenticationToken`) means the global converter's
  `supports(...)` returns `false` for it, so a scoped principal is never silently re-resolved with
  the global map — and no bean-ordering contract is needed between a CSL bean and a host bean.
- **Reuse the ADR-0016 hook, don't invent a new one.** `buildScopedApiChain` already accepts a
  per-scope `Converter<Jwt, Authentication>` for precisely "multiple simultaneous chains, each with a
  different converter." The registrar simply stops passing `() -> null`.
- **Gate on `MembershipPort`, fall back gracefully.** The per-scope converter is additive: absent its
  prerequisites, behaviour is exactly today's global resolution.

## Consequences

**Positive**

- Two scopes sharing one issuer with different claims each resolve their own principal correctly;
  the shared-issuer variant of camunda/camunda#64685 is fixed server-side, closing #668/#714.
- REST and gRPC now agree on the same tokens for scoped surfaces, including same-issuer tenants.
- No new host SPI: the fix rides the existing scope-provider SPI and the ADR-0016 converter hook, so
  a host already contributing `CamundaSecurityScopeProvider` descriptors gets it by upgrading.

**Negative / accepted trade-offs**

- Scoped API requests now resolve their `CamundaAuthentication` **eagerly** in the filter chain
  rather than lazily on first access, as the primary chain still does. Resolution is cheap
  (membership stays lazy), but it is a behavioural difference between the scoped and primary chains.
- A new `Authentication` type flows on scoped chains. Code that assumed every bearer request yields a
  `JwtAuthenticationToken` would not match a scoped request; CSL's own authorization path reads
  `CamundaAuthentication`, so it is unaffected, and the raw `Jwt` is still carried for callers.
- The carrier's `CamundaAuthentication`/`Jwt` fields are `transient`: the scoped API chain is
  stateless (`SessionCreationPolicy.NEVER`), so the token is never serialized into a session, but a
  host that forced session persistence of it would lose the carried principal.

## Alternatives Considered

- **Extend the global issuer-keyed map to scope providers.** Tried first in review; rejected — it
  fixes only distinct issuers, the shared-issuer case is unsolvable with an issuer-only key, and it
  left a `WARN`-and-move-on gap. Replaced by this approach before merge.
- **Key the global map by issuer + audience / client-id.** Rejected — the distinguishing claim is
  provider-specific (the very thing being configured), so there is no reliable general discriminator
  in the token, and it still cannot see the scope; it also would not cover the interactive login
  path.
- **Pre-populate the `CamundaAuthenticationHolder` from the scoped filter.** Rejected — relies on
  request/holder internals and ordering against the lazy provider, fragile compared with a typed
  carrier the delegating converter routes by `supports(...)`.
