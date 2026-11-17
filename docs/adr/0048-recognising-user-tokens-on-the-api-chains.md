# ADR-0048: The existing claim settings recognise user tokens on the API chains

**DRI**: Joaquín Felici (joaquinfelici)

**Deciders**: Joaquín Felici (joaquinfelici), Bojan Mudric (bmudric)

**Status**: Accepted (1.2.3)

**Purpose**: Record which settings of `username-claim`, `client-id-claim` and
`prefer-username-claim` tell a user token from a machine token for each identity provider in scope,
whether this is compatible with Hub, and where the existing settings are enough.

**Audience**: CSL maintainers, and operators who configure an identity provider.

## Context

A Camunda client application such as c8ctl or Desktop Modeler signs a user in itself. It is a
public client, it uses the authorization code flow with PKCE, and it calls the API of the host
application with the access token it receives. No session exists. A machine client calls the same
API with a token of the client credentials flow. Both tokens arrive as `Authorization: Bearer
<token>` on an API path.

The API chains of CSL came from machine tokens. Nobody had shown that a user token is handled
correctly on them.

CSL already has a rule for this. `LazyTokenClaimsConverter` reads the claims of the token:

1. If the claim named by `client-id-claim` is present, the caller is a client.
2. Else, if the claim named by `username-claim` is present, the caller is a user.
3. With `prefer-username-claim: true`, steps 1 and 2 change places.
4. If neither claim is present, CSL refuses the token.

The Engineering DRI stated on issue
[#800](https://github.com/camunda/camunda-security-library/issues/800#issuecomment-6772644555) that
this rule stays, that the public client flow must obey it, and that the result must be compatible
with Hub. Two questions followed. Which settings make the rule work for each identity provider in
scope? And does any provider need a new property?

The rule reads the token, not the registration. A `public` or `hybrid` registration gives CSL no
information about the token that arrives, because the registration only says which client CSL knows
about, and the same identity provider application can issue both kinds of token.

## Decision

**D1. The existing settings are sufficient for four of the five providers. CSL adds no property.**

For Keycloak, Auth0, Okta and PingFederate there is a combination of the three settings that
classifies a user token of a public or hybrid client and a client credentials token correctly, and
that keys identity on a stable claim. Where a provider emits no claim that only a user carries,
the fix is a configuration change at the provider, not in CSL. Microsoft Entra ID is the
exception; D1a states it.

| Identity provider | `username-claim` | `client-id-claim` | `prefer-username-claim` | Evidence |
|---|---|---|---|---|
| Keycloak | `sub` (the default) | `client_id` | `false` | Measured against Keycloak 26.4, in this repository |
| Microsoft Entra ID | `preferred_username`, with the caveat in D1a | `azp` | `true` | Already shipped by Camunda, plus a deployment playbook and the provider pages |
| Auth0 | a user-only claim from an Action, holding the `user_id` | `azp`, or `client_id` on the RFC 9068 profile | `true` | Measured on the Camunda Auth0 dev tenant, plus the provider pages |
| Okta (custom authorization server) | `uid` | `cid` | `true` | Provider pages only, and Camunda documentation disagrees |
| PingFederate | the user attribute of the access token manager contract | `client_id` | `true` | Provider pages only, pattern rather than a token shape |

The rows do not rest on the same quality of evidence, so each one says what backs it. Sources
below gives the exact pages.

- **Keycloak** is measured in this repository, against a container, on every build.
- **Entra** is not new. Camunda already ships exactly these three settings in the Helm guide for
  an external Entra tenant, for 8.8 and later, and an internal Entra deployment playbook explains
  why: a delegated token carries `preferred_username`, and a machine token from Connectors does
  not, so `azp` catches the machine caller without touching the user. This row records what is
  already deployed. It does not propose it.
- **Auth0** is measured, although not by this repository. The Engineering DRI tested the Camunda
  Auth0 dev tenant on 2026-11-03 and recorded the result. A user token of a native public client
  with PKCE carries the organization claim that a post-login action adds, and no `clusterId`
  claim; a machine-to-machine token carries `clusterId`. That is the shape this row describes: a
  claim that an Action adds for user flows only.
- **Okta** rests on the provider reference alone, and Camunda's own JWT claims reference
  disagrees with it. Okta states that an access token carries `cid` for the client and `uid` for
  the user, and that `uid` is left out when no user is bound. Camunda's reference page names
  `email` and `client_id` instead. One of the two is loose. This is the weakest row, and
  [#811](https://github.com/camunda/camunda-security-library/issues/811) must settle it.
- **PingFederate** rests on the provider reference alone, and is a pattern rather than a token
  shape. Every claim comes from the attribute contract the operator defines, so the product
  prescribes no claim names beyond the configurable client ID claim. The row says what to map,
  not what to expect. Camunda's reference page names `sub` and `client_id`, which is one such
  mapping.

The reason for each row:

- **Keycloak** adds `client_id` to a service account token only, through the `service_account`
  client scope. That claim alone separates the two kinds, so the user name claim does not have to
  separate anything and stays on the stable `sub`, which is also the default of CSL. `azp` must
  not be the client ID claim, because a user token carries it as well. `prefer-username-claim`
  must stay false, because a service account token carries `preferred_username` of the form
  `service-account-<client>`.
- **Entra** puts `azp`, `sub` and `oid` in a user token and in an app-only token alike, so no
  stable claim separates them. `preferred_username` reaches an access token through the `profile`
  scope, or because the operator added it as an optional claim in the token configuration of the
  application, which is what the Camunda Entra guide instructs. A client credentials request may
  only ask for `<resource>/.default` and has no user behind it, so an app-only token carries it in
  neither way. `prefer-username-claim: true` with that username claim therefore classifies both kinds
  correctly, at the cost D1a names. CSL already refuses an Entra token that is not v2.0.
- **Auth0** emits the client ID and `sub` in both flows and no claim that only a user has. `sub`
  is `auth0|<id>` for a user and `<client>@clients` for a machine, and `gty` is
  `client-credentials` for a machine, but the rule reads neither shape nor `gty`. An Auth0 Action
  must add a namespaced claim for user flows, holding the stable `user_id`. The name of the client
  ID claim follows the token profile of the API: the Auth0 profile emits `azp` and no `client_id`,
  and the RFC 9068 profile emits `client_id` and no `azp`. Both profiles put that claim in a user
  token too, so the profile changes the claim name and nothing else.
- **Okta** emits `cid`, the client that requested the token, in both flows. `uid` is the stable
  identifier of the user, and Okta states that it is not included when no user is bound to the
  token, which is every client credentials token.
- **PingFederate** gives an access token manager instance one attribute contract, and access
  token mappings per context: an IdP adapter, a password credential validator or an
  authentication policy contract for a user flow, and the client credentials grant type for a
  machine flow. At runtime the mapping whose context matches the grant fills the contract, and a
  default mapping serves a grant that matches none. An operator therefore fills the user attribute
  in the user mapping and leaves it empty in the client credentials mapping. The client ID claim
  has a configurable name on the Instance Configuration tab of the instance, `client_id` by
  default.

**D1a. Microsoft Entra ID cannot do both at once, and this ADR does not hide it.**

This is not a new risk that the pull request introduces. Camunda already ships
`usernameClaim: preferred_username`, `clientIdClaim: azp` and `preferUsernameClaim: true` as the
Entra configuration of the Helm chart, so every Entra deployment that follows the guide already
keys identity on a mutable claim. What is new here is that it is written down.

The principal that the rule produces is the key of every membership and every authorization, so it
must be stable. On Entra the stable identifiers of a person, `sub` and `oid`, appear in an
app-only token as well, where they name the service principal. The only user-only claims are
`preferred_username`, `upn` and `name`, and Microsoft states that each is mutable and must not
drive authorization decisions.

A rename is the mild case. The serious one is reuse: if Entra later gives the former value of
`preferred_username` to another account, that account resolves to the same principal here and
inherits every membership and every authorization still keyed to it, while the audit trail keeps
naming the person who left. An Entra deployment that follows the row above must therefore remove
the grants of a person before their user principal name can be reassigned, or prevent reuse at
the provider. This is a property of any mutable user name claim, on any provider, and it is the
reason the other four rows name a claim the provider never reassigns.

An Entra deployment therefore picks one of two, and the adopter documentation says so:

- Recognise machine tokens, with the row above, and accept that a rename at the identity provider
  gives the person a new identity in Camunda.
- Keep a stable principal, with `username-claim: oid` and no `client-id-claim`, and accept that
  the chain cannot tell a machine token from a user token. This is the behaviour of every release
  before this ADR.

A deployment that needs both on the same chain is not served today. This is the one finding that
could justify the extension that this ADR otherwise rejects. It is left open deliberately: the
verification sub-issue
([#811](https://github.com/camunda/camunda-security-library/issues/811)) measures real Entra
tokens, and the decision should be taken with real deployments behind it rather than on this
analysis alone.

**D2. The defaults keep working, and change nothing for an existing deployment.**

The defaults are `username-claim: sub`, no `client-id-claim` and `prefer-username-claim: false`.
With no `client-id-claim`, step 1 never fires and every token resolves to a user. A user Bearer
token therefore works on a deployment that configures nothing new, and a deployment that configures
nothing new behaves exactly as before. Nothing in this task writes a new default or changes an
existing one.

**D3. Hub is unaffected.**

Checked against `camunda/camunda-hub` on 2026-11-16:

- Hub's Public API has its own filter chains. `PublicApiSecurityConfiguration` declares them at
  `@Order(1)` over the public API base paths, and gives them Hub's own converter. In Self-Managed
  that is `SelfManagedPublicApiJwtAuthenticationConverter`, which checks the audience and then
  makes every token a `ServiceClientJwtAuthenticationToken`. `ServiceClientAuthenticationConverter`
  turns that into a client principal. None of the three CSL settings is read on that path.
- Everything else, Hub's internal API included, runs on CSL's OIDC API chain, because
  `HubSecurityPathAdapter.apiPaths()` returns `/**` and the public API chains win by order for
  their own paths.
- On that chain Hub sets `username-claim` only.
  `LegacyAuthConfigEnvironmentPostProcessor` translates Hub's legacy
  `camunda.hub.oauth2.token.user-id-claim` onto
  `camunda.security.authentication.oidc.username-claim`, and translates no claim onto
  `client-id-claim`. Hub therefore runs with `client-id-claim` unset, every token on that chain
  resolves to a user, and D2 applies.

Hub-side changes are out of scope. A later Hub change that wants user tokens on its Public API can
use this table.

**D4. The token checks stay as they are.**

The validators check the time, the issuer, and the audience when `audiences` is configured. They do
not look at the client ID of a token, and this task adds no check that refuses a token because of
its client ID. Such a check would break the shared public client in SaaS, which asks for the
audience `cloud.<stage>` and which neither Hub nor the Orchestration Cluster checks `azp` for.

**D5. A Bearer token stays accepted on API paths only.**

Unchanged from [ADR-0011](0011-oidc-bearer-tokens-on-api-chain-only.md). A Bearer token on a webapp
path gets HTTP 401. A host that wants Bearer access on a path declares that path under
`apiPaths()`.

## Consequences

**Positive**

- A user Bearer token works on the API chains with the settings that already exist, and the table
  says which settings to use for each provider.
- No new property, so no new way to configure the same thing twice, and no migration.
- The m2m path is untouched. A client credentials token of a `hybrid` registration still resolves
  to a client, which an integration test shows against a real Keycloak.

**Negative / accepted trade-offs**

- Entra cannot do both at once (D1a). A deployment there recognises machine tokens or keeps a
  stable principal, not both. This is the one gap the three settings do not close.
- Auth0 and PingFederate need a configuration change at the identity provider before a deployment
  can recognise both kinds of token. CSL can do nothing about this: the rule needs a claim that
  only one kind of token carries, and these providers emit none by default.
- A deployment that wants both user tokens and machine tokens must set `client-id-claim`. Setting
  it wrongly, for example to `azp` on Keycloak, silently turns users into clients. The adopter
  documentation names the trap per provider.
- The rows for Entra, Auth0, Okta and PingFederate come from documentation, not from measurement.
  Issue [#811](https://github.com/camunda/camunda-security-library/issues/811) re-checks them with
  real tokens and reports any difference back. The Entra row matters most there, because D1a rests
  on it.

## Alternatives Considered

### A rule driven by the registration type

A token verified by a `public` registration would always be a user, because a public client holds
no secret and cannot run the client credentials flow. Rejected. It helps `hybrid` not at all, which
is the registration shape the epic expects a customer to use for one Entra application that serves
both the host login and c8ctl. It also adds a second, hidden way to decide the principal next to
the three settings, which the Engineering DRI asked to keep as the one rule.

### A new property that names a claim and a value identifying a user token

For example `user-token-claim: idtyp` with the value `app` marking a machine token. Not taken now,
but not ruled out. Four of the five providers are covered by the three settings, with a
provider-side configuration change where needed, and a fourth setting would make the same decision
reachable two ways for them. Entra is the case that would justify it: `idtyp` is exactly the claim
Microsoft provides to tell an app token from a user token, and reading it would let an Entra
deployment keep `oid` as a stable principal and still recognise machine tokens, which D1a says is
impossible today. The decision waits for the real Entra tokens of
[#811](https://github.com/camunda/camunda-security-library/issues/811).

A JSONPath expression in `username-claim` cannot stand in for it. The expression must return a
string, and a JSONPath filter returns a list, so "the `oid`, unless `idtyp` is present" is not
expressible.

### Documentation only

Chosen, together with tests. The settings exist, they are not obvious, and nothing recorded which
ones to use.

## Verification

- `IdpTokenShapePrincipalResolutionTest` encodes the table above, one test per provider for the
  recommended settings and one for the settings next to it that fail. The failing tests are the
  reason each row reads as it does.
- `OidcApiUserBearerTokenTest` drives the real OIDC API chain: a user Bearer token authenticates as
  a user, its memberships give mapping rules, groups, roles and tenants, an allowed call passes and
  a denied call fails, a client credentials token of a `hybrid` registration stays a client, a
  Bearer token on a webapp path gets 401, and a token the decoder refuses gets 401 with a reason.
- `KeycloakUserBearerTokenIT` measures the Keycloak row against Keycloak 26.4, with the settings
  the table recommends: a user token of the public client and of the hybrid client, both from a
  real authorization code flow with PKCE, and a client credentials token of the hybrid client. The
  two user tokens resolve to the same principal, which shows that `sub` names the person and not
  the client they signed in through. It also shows that a token of another audience, a token of
  another issuer, and an expired token each fail with a reason.

## Sources

Read on 2026-11-17.

Inside Camunda:

- Entra, already shipped: the Helm guide [Set up the Helm chart with an external Microsoft Entra
  tenant](https://docs.camunda.io/docs/self-managed/deployment/helm/configure/authentication-and-authorization/microsoft-entra/)
  configures `usernameClaim: preferred_username`, `clientIdClaim: azp` and
  `preferUsernameClaim: true`, and instructs the operator to add `preferred_username` as an
  optional claim to the access token and the ID token.
- Entra, why it works: the internal Entra ID playbook states that a delegated token is v2.0 and
  carries `preferred_username`, that the Orchestration Cluster reads it first and falls back to
  the client ID claim only when it is absent, which is the machine-to-machine case, and that
  `clientIdClaim: azp` therefore identifies machine callers without affecting users.
- Auth0, measured: [findings-shared-public-client.md](https://github.com/camunda/pdp-initiative-ea-identity--access-at-scale/blob/main/user-based-auth-for-camunda-envs/findings-shared-public-client.md),
  tested on the Camunda Auth0 dev tenant on 2026-11-03. A post-login action adds the organization
  claim and the email to the ID token and the access token of a user login; a user token has no
  `clusterId` claim and a machine-to-machine token has one.
- The disagreement on Okta and PingFederate: [JWT token claims
  reference](https://docs.camunda.io/docs/self-managed/deployment/helm/configure/authentication-and-authorization/jwt-token-claims/)
  names `email` and `client_id` for Okta, and `sub` and `client_id` for PingFederate.

Provider reference pages:

- Microsoft Entra ID: [access token claims
  reference](https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference)
  for `azp`, `sub`, `oid`, `preferred_username` and `scp`; [optional claims
  reference](https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims-reference)
  for `idtyp`; [client credentials
  flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow)
  for the rule that such a request may only ask for `<resource>/.default`, which is why an
  app-only token can never carry `preferred_username`.
- Auth0: [access token
  profiles](https://auth0.com/docs/secure/tokens/access-tokens/access-token-profiles) for the
  claim set of each profile, for `azp` against `client_id`, and for the shape of `sub` in each
  flow.
- Okta: [access token payload
  claims](https://developer.okta.com/docs/api/openapi/okta-oauth/guides/overview/) for `uid`,
  `cid` and `scp`, including the statement that `uid` is left out when no user is bound to the
  token.
- PingFederate: [defining the access token attribute
  contract](https://docs.pingidentity.com/pingfederate/13.1/administrators_reference_guide/pf_defining_access_token_attribute_contract.html)
  for the contract and the client ID claim name, and [managing access token
  mappings](https://docs.pingidentity.com/pingfederate/13.1/administrators_reference_guide/pf_managing_access_token_mappings.html)
  for the mapping per context, the client credentials grant type among them.

## Notes

The expiry test has to register its own `TokenValidatorFactory` with no clock skew. CSL builds
every `TokenValidatorFactory` with `OidcConfiguration.DEFAULT_CLOCK_SKEW`, so the configured
`camunda.security.authentication.oidc.clock-skew` reaches no validator today. That is a separate
defect, outside this task.
