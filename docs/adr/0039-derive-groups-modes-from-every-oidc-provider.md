---
status: Accepted
---

# ADR-0039: Derive the groups modes from every OIDC provider

**Deciders**: Tim Cline

## Status

Accepted.

## Context

`AuthenticationConfiguration.isCamundaGroupsEnabled()` read only the `groups-claim` of the `camunda.security.authentication.oidc` block. A deployment with named providers under `providers.oidc.<name>` got a value that ignored them ([camunda/camunda#44274](https://github.com/camunda/camunda/issues/44274)). `@ConditionalOnCamundaGroupsEnabled` had the same gap.

Hosts use the one flag for two decisions:

1. Whether to offer Camunda's group management, where admins create groups and add members.
2. Whether a group assigned to a role, tenant or authorization must exist in Camunda.

With one provider both decisions have the same answer. With a provider that has a groups claim and one that does not, they diverge:

- Users of the provider without a claim need Camunda's group management (decision 1 must be "yes").
- Groups of the provider with a claim exist only in the IdP, so they can't be required to exist in Camunda (decision 2 must be "no").

No single value covers both. Neither decision can be made per provider either. A Camunda group can have members from any provider. An assignment like "group `engineering` gets role Developer" names no provider.

## Decision

`AuthenticationConfiguration` derives two cluster-wide flags from all OIDC providers. No setting is added.

- `isCamundaGroupsEnabled()`: some users get their groups from Camunda. It is true when the method is not OIDC, or an OIDC provider has no groups claim. This answers decision 1.
- `isExternalGroupsEnabled()`: some users get their groups from a claim. It is true when the method is OIDC and an OIDC provider has a groups claim. This answers decision 2: when it is true, a host must not require a group to exist in Camunda.

A third method, `getGroupsClaim(String issuer)`, gives the groups claim for a token of that issuer, so a host can resolve each login's groups with the claim of the provider that issued the token:

- The issuer belongs to the first provider with that `issuer-uri`, with the `oidc` block first. This is the rule `IssuerOwnership` applies. A trailing slash is ignored.
- It returns `null` when that provider's users get their groups from Camunda.

The OIDC providers are the `oidc` block when it has a `client-id`, then the named providers. With none, the `oidc` block alone, so a configuration without named providers keeps today's result. A provider without its own `groups-claim` uses the one of the `oidc` block, as hosts already do for the principal claims. A token of no known issuer also uses the claim of the `oidc` block.

`@ConditionalOnCamundaGroupsEnabled` binds `camunda.security.authentication` and returns `isCamundaGroupsEnabled()`.

## Consequences

**Positive**

- The flags reflect every provider. A configuration where only the `oidc` block sets a groups claim gets the same values as before.
- With one provider the two flags are always opposites, so a host that switches its existence check to `!isExternalGroupsEnabled()` behaves exactly as before for that configuration.

**Negative / accepted trade-offs**

- In a mixed setup a host no longer checks that an assigned group exists, even for a group meant for Camunda. A typo is accepted silently, because the host can't tell it from a group of the IdP.
- A provider can't opt out of the `oidc` block's groups claim, so a mixed setup needs the `oidc` block to have none.
- `getGroupsClaim` matches a provider by its `issuer-uri`. A provider configured without one is found only through the `oidc` block's fallback.
- `@ConditionalOnCamundaGroupsEnabled` now also considers the method, as its documentation always said. With basic authentication and a groups claim set, it matches.
