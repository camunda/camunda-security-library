# ADR-0042: An OIDC client type, and `none` as a client authentication method

**DRI**: Joaquín Felici (joaquinfelici)

**Deciders**: Bojan Mudric (bmudric), Joaquín Felici (joaquinfelici)

**Status**: Accepted (1.2.2)

**Purpose**: Record how CSL describes an OIDC client that holds no client secret, and what CSL does with a provider block that contradicts itself.

**Audience**: CSL maintainers, and the host application teams that configure OIDC providers.

## Context

CSL accepts only confidential OIDC clients today. A confidential client authenticates at the token endpoint with a client secret or with a signed assertion. CSL reads `client-secret` and makes no check on it. `client-authentication-method` defaults to `client_secret_basic`. The constant `CLIENT_AUTHENTICATION_METHODS` lists the supported values, but no code compares a configured value against that list.

Two needs change this. Hub logs its users in with a public client, and Hub moves that login to CSL. A public client holds no client secret and sends no client authentication. An existing Hub installation therefore breaks on upgrade unless CSL can describe such a client.

Camunda client applications, c8ctl and Desktop Modeler, sign a user in with PKCE. They then call the API of the host application with the token they received. The host application can check that token only if it holds a registration for that client.

The configuration must say which kind of client a registration describes. The validation must follow from that kind. Epic [#800](https://github.com/camunda/camunda-security-library/issues/800) leaves three questions open, and this record answers them. It also records the pass over each OIDC property that the Engineering DRI of the epic asked for.

Two accepted decisions constrain every answer. [ADR-0029](0029-warn-instead-of-block-on-provider-block-validation.md) says that provider-block validation never stops the application from starting. [ADR-0025](0025-deferred-oidc-resolution.md) defers each resolution step that needs the network to its first use, and then retries that step. A contradictory configuration is deterministic, so a retry gives the same answer. CSL must not treat the two failures in the same way.

## Decision

**D1. The `type` property names the kind of client. It has three values, and `confidential` is the default.**

`confidential` authenticates at the token endpoint with a secret or with a signed assertion. Every registration that an operator wrote before this property is a confidential client. `public` holds no secret and sends no client authentication. `hybrid` is a confidential client whose identity provider also permits PKCE for the same client. One `hybrid` registration therefore serves both the login of the host application and a Camunda client application. The property binds on the flat `camunda.security.authentication.oidc.*` block, and on each `camunda.security.authentication.providers.oidc.<id>.*` entry.

**D2. `type` binds as a string, and CSL reads it case-insensitively.**

The Spring binder rejects an unknown value for an enum property, and the application never starts. ADR-0029 forbids that result for a provider block. A string lets CSL read the value itself, and treat an unknown one as a contradictory configuration. See D5. Hand-authored configuration metadata hints give the three values to an IDE, so the operator keeps completion without the binder. [ADR-0021](0021-hand-authored-spring-configuration-metadata.md) covers those hints.

**D3. `none` joins `CLIENT_AUTHENTICATION_METHODS`. CSL warns about a value outside the list, and then uses that value.**

The list becomes `client_secret_basic`, `private_key_jwt` and `none`. A value outside the list that Spring accepts logs a `WARN` that says CSL does not support the value. CSL then builds the registration and uses the value as configured.

Spring's `ClientAuthenticationMethod` rejects only a blank value. A literal such as `client_secret_post` therefore works end to end today. `RefreshTokenRevocationLogoutHandler` in this repository already sends a `client_secret` parameter for it. A reject on upgrade stops a deployment that works, which the epic rules out. A blank value keeps the behavior it has today. CSL warns about it, and the builder of Spring refuses it.

**D4. A `public` registration forbids three properties. No property is required by any type.**

`client-secret` must be empty. `client-authentication-method` must be `none`, or the operator must leave it unset. `assertion.keystore.*` must be unset, because that key material signs a `private_key_jwt` assertion, and `none` rules such an assertion out.

CSL compares the method against `none` case-sensitively. The value reaches Spring unchanged, and `NONE` builds a `ClientAuthenticationMethod` that does not equal the `NONE` of Spring. A case-insensitive match therefore promises a public-client token exchange that Spring does not perform.

`none` is valid only with `type: public`. A `confidential` or a `hybrid` registration that asks for `none` is contradictory in the same way. CSL validates `hybrid` exactly as it validates `confidential`. CSL has never checked that a confidential client holds a secret, and this record adds no such check.

No property is required, for any type. A `public` registration has two uses. It serves the PKCE login of the host application, or it validates tokens that a Camunda client application obtained for itself. `type` cannot tell the two uses apart. A property that only a login reads therefore cannot be required by type, and `redirect-uri` is the clearest case.

`resource` stays optional for every type. Identity providers request an audience in three different ways, and Hub checks the audience on its resource server instead of sending `resource`. A requirement on `resource` therefore makes existing installations invalid. CSL allows every property that this record does not name.

**D5. CSL warns once about a contradictory provider block, and then drops that block.**

The validation pass in `ScopedClientRegistrationFactory` logs one `WARN`. The message names the provider and the property that the operator must change. `ScopedClientRegistrationFactory#withoutUnusableRegistrations` then removes the registration from every consumer of the provider map. CSL behaves as if the operator never configured that provider. `findByRegistrationId` answers `null`, no login link appears, and CSL builds no token decoder, no token validator and no claims provider from it. The application starts, and the other providers of the deployment keep working.

One exception applies. A scope that enables UserInfo augmentation needs at least one provider that can map an issuer to a UserInfo endpoint. ADR-0029 leaves that requirement in `CachingOidcClaimsProvider` throwing. A rejection that removes the last such provider therefore stops the start of that scope. Only a configuration that names a client type can reach this result, so no deployment that predates the property is affected.

The diagnostic needs the dropped entries, and the filtered map no longer holds them. `LazyClientRegistrationRepository#configuredProviders` therefore keeps the configuration before the filter, and only the decoder diagnostic reads it. Every other caller reads `providers()`.

A check that would stop the start makes the same test. `CamundaSecurityLibraryProperties` validates the assertion configuration of each block in `@PostConstruct`, where a throw stops the application. It skips that check for a dropped block, so a block that CSL does not use cannot stop a deployment whose other blocks are valid. A usable block keeps the check.

The filter sits where the blank-registration-id filter already sits. It runs in the constructor of `LazyClientRegistrationRepository`, and at each other consumer of the map. It does not run in `OidcProviderConfigurationPort`, for two reasons. The port is `@ConditionalOnMissingBean`, and its `initializeProviders` method is `protected`, so a host override bypasses a filter in that place. `OidcWebappClientBeansConfiguration` also throws when the provider map is empty. A filter before that check turns a deployment whose only provider is contradictory into a failed start, and ADR-0029 exists to prevent that result.

`clientTypeVerdict` is the one implementation of the verdict. It has no side effects. The warning pass and the filter therefore cannot disagree, and a consumer can apply the filter as often as it needs without a repeated diagnostic.

**D6. A registration that has the registration ID of a dropped block gets nothing from that block. CSL refuses each token for such a registration, unless the registration describes itself.**

A host application can register its own `ClientRegistrationRepository`, and the repository of CSL then backs off. A registration in it that has the registration ID of a dropped block joins the provider map by that ID alone. `TokenValidatorFactory` holds no issuer and no audiences for such a registration, and both checks would disappear without a trace. A correctly signed token with a wrong issuer would then pass. CSL returns a validator that refuses each token for that registration instead, and writes one `WARN` with the registration ID at the first token decode.

A registration that carries its own `ClientRegistrationMetadata` keeps its own checks. CSL writes that metadata on each registration that it builds, and `TokenValidatorFactory` reads it before the provider map. Two cases need this. A scope whose own block under a registration ID is usable must keep working although the block of another scope with the same ID was dropped. A `LazyClientRegistrationRepository` that the host application wires itself builds registrations the same way, and those must keep working too. Neither case is the one that this decision protects, because both describe their own issuer.

`ScopedWebappSecurityChainBuilder` and `AssertionJwkProvider` also read a provider block by registration ID. A dropped block therefore gives no `post_logout_redirect_uri` to such a registration, and the handler of the logout applies the chain-wide default to it. `AssertionJwkProvider` refuses to load the assertion key of a dropped block, because key material of a block that CSL does not use must sign nothing.

That `WARN` is the only validation signal that a deployment with its own repository receives. Such a repository runs no provider-block validation pass at all, for this check or for any other provider-block check. This gap predates this record, and a change that closes it must cover every check and not the client type alone.

## Alternatives considered

The team considered these alternatives and rejected each one:

- Bind `type` as an enum. An unknown value fails the Spring binder before CSL can warn, which ADR-0029 forbids for a provider block. See D2.
- Reject any `client-authentication-method` outside the list. This makes a working `client_secret_post` deployment unusable on upgrade. See D3.
- Require `resource` for a public client. The public-client login of Hub does not send it, and identity providers request an audience in three different ways. See D4.
- Read `type: public` from `client-authentication-method: none`. This turns a registration that the operator declared confidential into a public one, and no configuration can undo the inference. A warning that names the fix costs the operator the same work, and it leaves the declaration with them.
- Filter contradictory registrations in `OidcProviderConfigurationPort`. A host override bypasses that filter, and the filter turns an all-rejected configuration into a failed start. See D5.
- Keep a contradictory registration, and let it fail at its first use. The failure is deterministic, so the retry model of ADR-0025 does not fit it. The resulting error also reads as a refused credential, and not as a wrong configuration.
- Stop the start on a contradictory block, as the solution proposal first described. The Engineering DRI replaced that statement on 2026-11-06 with a decision to follow ADR-0029.

## Consequences

These results are positive:

- An operator can describe a public client or a hybrid client. A contradictory block names the property to change, instead of failing at the first login.
- A registration that CSL cannot use is gone from every path, token validation included. It does not reach Spring and fail later in a way that reads as a refused credential.
- A configuration that sets no `type` behaves exactly as before. The default reproduces the validation of today, and `hybrid` reproduces it too.
- A deployment whose every provider is dropped starts, and then refuses to verify any token. The failure names the dropped providers and points at the startup warning for each one. CSL does not tell the operator to configure a provider that they already configured.

The team accepts these trade-offs:

- `client-authentication-method: none` was never a supported value, but Spring accepts the literal. CSL built and ran such a registration until now, without PKCE. The registration now needs `type: public`, and CSL drops it without that property. This is a behavior change on upgrade. The team accepts it, because the registration runs an authorization-code exchange with neither client authentication nor PKCE. The warning names `type: public` as the fix, and no CSL document ever named the value.
- A dropped registration is visible only in the startup log and in the first token decode. An operator who reads neither sees a provider that is simply absent. ADR-0029 already accepted this trade-off for this class of problem.
- `type` as a string accepts any value at bind time. A typo therefore surfaces as a warning at startup, and not as a binder error.
- A rejection can stop the start of a scope that enables UserInfo augmentation, as D5 describes. The team accepts this, because the requirement predates this record, and because a scope that can augment nothing would otherwise run without augmentation and give no signal.
- CSL refuses each token for a registration of the host application that has the registration ID of a dropped block, as D6 describes. This disables a registration that the host application built itself. The repository of CSL never hands over a dropped registration, so only that case reaches the trade-off. The team accepts it, because the alternative accepts a token that CSL can check against neither an issuer nor an audience, and because the operator configured the contradictory block under that same ID.

CSL reads none of these five properties today, so each one is allowed for all three types:

- `grant-type`
- `id-token-algorithm`
- `organization-id`
- `idp-logout-enabled`
- `clock-skew` for each provider

`grant-type` was a candidate for a restriction to `authorization_code` under `type: public`. The registration builder hardcodes that grant type, and no reader consults the property, so the restriction is already true. A per-type check validates a value that CSL ignores. If a change wires one of these five properties up, the restriction belongs with that change.

## Source

- Task: [#806](https://github.com/camunda/camunda-security-library/issues/806).
- Epic: [#800](https://github.com/camunda/camunda-security-library/issues/800). The Engineering DRI stated the rules for `hybrid` and the ADR-0029 constraint on 2026-11-06. The DRI asked for the property pass of D4 in [comment 6772644555](https://github.com/camunda/camunda-security-library/issues/800#issuecomment-6772644555).
- The `resource` proposal of D4: [comment 6741379582](https://github.com/camunda/camunda-security-library/issues/800#issuecomment-6741379582).
- Related records: [ADR-0025](0025-deferred-oidc-resolution.md), [ADR-0029](0029-warn-instead-of-block-on-provider-block-validation.md), [ADR-0021](0021-hand-authored-spring-configuration-metadata.md).
