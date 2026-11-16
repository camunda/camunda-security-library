# ADR-0044: CSL sends PKCE through the default of Spring Security

**DRI**: Joaquín Felici (joaquinfelici)

**Deciders**: Joaquín Felici (joaquinfelici), Bojan Mudric (bmudric)

**Status**: Accepted (1.2.2)

**Purpose**: Record how the OIDC login of CSL sends PKCE, and why CSL adds no code for it.

**Audience**: CSL maintainers.

## Context

[ADR-0042](0042-oidc-client-type-and-client-authentication-method-none.md) lets an operator declare
a public client. A public client holds no secret. The authorization code is then the only thing
that stands between an attacker and a session, and an attacker who steals the code from the
redirect can exchange it. PKCE (RFC 7636) closes that hole. The client sends a challenge with the
authorization request and the matching verifier with the token request, and the provider refuses an
exchange that does not match.

Task [#809](https://github.com/camunda/camunda-security-library/issues/809) asked whether CSL must
apply PKCE itself, or can rely on Spring Security. These facts come from Spring Security 7.1.2,
which Spring Boot 4.1.2 brings in:

- `ClientSettings#requireProofKey` defaults to true, and `ClientRegistration.Builder` gives that
  default to every registration it builds.
- `DefaultOAuth2AuthorizationRequestResolver` applies PKCE when that setting is on, or when the
  client authentication method is `none`. A public client meets both conditions.
- `CamundaOidcAuthorizationRequestResolver` wraps that resolver. Its customizer runs after Spring
  fills the builder, and it only adds parameters. It cannot remove PKCE.
- `DefaultOAuth2TokenRequestParametersConverter` puts `code_verifier` in the token request, and
  `client_id` for every method but `client_secret_basic`.

CSL therefore sends PKCE today, for every client type. A confidential client has sent it since the
upgrade to Spring Security 7.

## Decision

**D1. CSL applies no PKCE of its own. It relies on the default of Spring Security, and tests hold
that default in place.**

Code that applies PKCE in the customizer of CSL changes no request, because Spring has applied it
before the customizer runs. The risk that such code answers is a Spring upgrade that drops the
default. A test answers that risk at the same point, and it also covers the paths that no CSL code
can reach, such as the `code_verifier` in the token request.

`CamundaOidcAuthorizationRequestResolverTest` asserts the challenge, the method `S256` and the
verifier on the authorization request of a public and of a confidential client.
`OidcPublicClientTokenExchangeTest` asserts the token request and the refresh request of both
types. An upgrade that changes any of this fails the build, and not the login of a customer.

**D2. CSL sends PKCE for every client type, and not for public clients alone.**

The task proposed PKCE for public registrations only. That restriction now means switching PKCE off
for confidential clients, because they send it today. The OAuth 2.0 Security Best Current Practice
recommends PKCE for every client that uses the authorization code flow, so the restriction would
lower the security of a confidential login for no gain. One path for all three types is also one
path to test and to explain.

## Alternatives considered

The team considered these alternatives and rejected each one:

- Apply PKCE in the customizer for public registrations only. It adds no parameter that Spring does
  not already add. It also tells a reader that a confidential client sends no PKCE, which is wrong.
- Set `ClientSettings#requireProofKey` on each registration that CSL builds. This states the intent
  of CSL in its own code, but it repeats the default of the framework at every build, and it needs
  the same tests, because the resolver and not the setting writes the parameters.
- Switch PKCE off for confidential clients, to restore the requests they sent before Spring
  Security 7. This removes a protection that costs nothing and that the provider ignores when it
  does not support it.

## Consequences

These results are positive:

- A public client login is protected against a stolen authorization code, and CSL has no PKCE code
  to maintain.
- A confidential client keeps the requests it sends today, so this work changes nothing for an
  existing deployment.
- All three client types follow one path through the resolver and the token client.

The team accepts these trade-offs:

- CSL depends on a default of the framework. An upgrade can change it, and the tests named in D1
  are the only guard. A change that removes them removes the guard.
- Those tests assert the behavior of Spring, and not of code in this repository. This is
  deliberate. The behavior is what CSL promises an operator, whichever library produces it.

## Source

- Task: [#809](https://github.com/camunda/camunda-security-library/issues/809).
- Epic: [#800](https://github.com/camunda/camunda-security-library/issues/800).
- The Engineering DRI agreed to this decision on 2026-11-13, in
  [comment 6857652176](https://github.com/camunda/camunda-security-library/issues/809#issuecomment-6857652176).
- Related records: [ADR-0042](0042-oidc-client-type-and-client-authentication-method-none.md), and
  [ADR-0045](0045-integration-tests-in-the-verify-phase.md) for decision 2 of #809.
