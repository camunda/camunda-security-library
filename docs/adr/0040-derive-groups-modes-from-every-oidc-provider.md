# ADR-0040: Derive the groups modes from every OIDC provider

**DRI**: Timothy Cline (timcline)

**Deciders**: Timothy Cline (timcline)

**Status**: Accepted (1.3.0)

**Purpose**: Defines how CSL tells a host where its users get their groups from.

**Audience**: Developers of host applications that manage or assign groups, and CSL maintainers.

## Context

A host decides if it offers the group management of Camunda, and if an assigned group must exist
in Camunda. CSL answered both with one value, read from the default OIDC configuration only. With
several providers, the answers can differ. Users of a provider without a groups claim need the
group management of Camunda. Groups of a provider with a claim exist only in its identity provider.

## Decision

**D1. CSL gives two groups modes, derived from the OIDC providers.**
One mode tells if some users get their groups from Camunda. The other tells if some users get
their groups from a claim. Both can be true. The groups claim of each provider gives the answer,
so CSL adds no setting. Every provider counts, because a user can log in with any of them.

**D2. CSL reads the groups of a login with the claim of the provider that handles it.**
For a browser login, this is the provider that the user picked. For a bearer token, this is the
provider that verifies the token, found by the issuer of the token.

**D3. For a bearer token, only the first provider of an issuer counts.**
That provider verifies all tokens of the issuer. A trailing slash does not make a different issuer
([ADR-0038](0038-verified-token-carries-its-provider-claims.md)).

**D4. A provider without a groups claim uses the claim of the default OIDC configuration.**
Named providers get the principal claims in the same way
([ADR-0034](0034-named-providers-inherit-principal-claims.md)).

## Alternatives considered

- **Keep one mode.** With mixed providers, the two decisions need different answers.
- **Decide per provider.** A Camunda group can have members from any provider, and an assignment
  such as "group engineering gets role Developer" names no provider.
- **Add a setting for the groups mode.** The groups claims already give the answer, and a
  separate setting can contradict them.

## Consequences

- If only the default OIDC configuration has a groups claim, the result does not change. With one
  provider, the two modes are always opposites.
- With mixed providers, a host does not check that an assigned group exists. It cannot find a typo.
- A host looks up the claim by provider for a browser login, and by issuer for a bearer token.
- A configuration with mixed providers needs a default OIDC configuration without a groups claim.
- The condition that activates the group management of Camunda now also reads the authentication
  method. With basic authentication and a groups claim, it activates.

## Source

- [The groups mode does not consider several identity providers
  (camunda/camunda#44274)](https://github.com/camunda/camunda/issues/44274) (internal)
