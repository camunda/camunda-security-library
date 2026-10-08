/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import io.camunda.security.api.context.CamundaSecurityScopeProvider;
import io.camunda.security.api.context.MembershipResolutionContextPropagator;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import io.camunda.security.core.port.in.OidcProviderConfigurationPort;
import io.camunda.security.core.port.out.MembershipPort;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.converter.AdditionalJwkSetUrisByRegistrationId;
import io.camunda.security.spring.converter.TokenClaimsConvertersByIssuer;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.util.StringUtils;

/**
 * Provides default OIDC infrastructure beans not tied to client registration ({@link
 * OidcProviderConfigurationPort}-derived services) when {@code
 * camunda.security.authentication.method=oidc}. The client-registration-dependent beans ({@link
 * org.springframework.security.oauth2.jwt.JwtDecoder}, {@link
 * org.springframework.security.oauth2.client.registration.ClientRegistrationRepository}, and
 * related OAuth2 client beans) live in {@link OidcWebappClientBeansConfiguration}, additionally
 * gated on {@code camunda.security.authentication.webapp-enabled}. Hosts that need custom wiring
 * can override any bean via {@code @ConditionalOnMissingBean} back-off.
 *
 * <p>The per-scope OIDC factories ({@code JWSKeySelectorFactory}, {@code
 * ScopedClientRegistrationFactory}, {@code OidcAccessTokenDecoderFactory}, {@code
 * ScopedJwtDecoderFactory}) are declared in the unconditional {@link
 * ScopedOidcInfrastructureConfiguration} so they are available regardless of the global
 * authentication method. It is {@code @Import}ed so a host that opts in by importing only {@code
 * OidcBeansConfiguration} (the documented quickstart) still gets a working context. Its beans are
 * {@code @ConditionalOnMissingBean}, so importing it here and via the {@code
 * CamundaSecurityAutoConfiguration} umbrella is idempotent.
 */
@Configuration
@ConditionalOnProperty(name = "camunda.security.authentication.method", havingValue = "oidc")
@Import(ScopedOidcInfrastructureConfiguration.class)
public class OidcBeansConfiguration {

  private static final Logger LOG = LoggerFactory.getLogger(OidcBeansConfiguration.class);

  @Bean
  @ConditionalOnMissingBean
  public OidcProviderConfigurationPort oidcProviderConfigurationPort(
      final CamundaSecurityLibraryProperties properties,
      final ScopedClientRegistrationFactory scopedClientRegistrationFactory) {
    return new OidcAuthenticationConfigurationRepository(
        properties, scopedClientRegistrationFactory);
  }

  @Bean
  @ConditionalOnMissingBean
  public TokenValidatorFactory tokenValidatorFactory(
      final OidcProviderConfigurationPort oidcProviderConfigurationPort) {
    return new TokenValidatorFactory(
        oidcProviderConfigurationPort.getOidcAuthenticationConfigurations(),
        OidcConfiguration.DEFAULT_CLOCK_SKEW,
        List.of());
  }

  /**
   * Per-registration {@code additional-jwk-set-uris} lookup for {@code
   * OidcUserAuthenticationConverter}. Keyed by registration ID rather than by issuer URI so a
   * provider configured with explicit endpoints and no {@code issuer-uri} still contributes its
   * supplementary key sets; see <a
   * href="https://github.com/camunda/camunda-security-library/blob/main/docs/adr/0030-additional-jwk-set-uris-by-registration-id.md">ADR-0030</a>.
   *
   * <p>Registrations that declare no usable URI are left out, so the lookup answers {@code null}
   * for them and the decoder takes its single-URI path.
   */
  @Bean
  @ConditionalOnMissingBean
  public AdditionalJwkSetUrisByRegistrationId additionalJwkSetUrisByRegistrationId(
      final OidcProviderConfigurationPort oidcProviderConfigurationPort) {
    final Map<String, List<String>> byRegistrationId = new LinkedHashMap<>();
    // Blank ids are filtered for the same reason the claims-converter bean below filters them: a
    // blank key can never match a ClientRegistration's registrationId, so it would only ever be
    // dead weight in the lookup.
    ScopedClientRegistrationFactory.withoutBlankRegistrationIds(
            oidcProviderConfigurationPort.getOidcAuthenticationConfigurations())
        .forEach(
            (registrationId, config) -> {
              final var additionalUris = config.getAdditionalJwkSetUris();
              if (additionalUris != null
                  && additionalUris.stream().anyMatch(StringUtils::hasText)) {
                byRegistrationId.put(registrationId, additionalUris);
              }
            });
    LOG.debug("Additional JWK Set URIs by registration id: {}", byRegistrationId.keySet());
    return new AdditionalJwkSetUrisByRegistrationId(byRegistrationId);
  }

  @Bean
  @ConditionalOnMissingBean
  public AssertionJwkProvider assertionJwkProvider(
      final OidcProviderConfigurationPort oidcProviderConfigurationPort) {
    return new AssertionJwkProvider(oidcProviderConfigurationPort);
  }

  /**
   * Per-issuer {@link LazyTokenClaimsConverter} lookup for {@code
   * OidcTokenAuthenticationConverter}. Providers without an {@code issuer-uri} fall back to the
   * default converter.
   *
   * <p>The flat block's entry is identified by reference equality against {@code
   * properties.getAuthentication().getOidc()}, not by registration-ID key, since a custom {@code
   * registration-id} or a colliding {@code providers.oidc.*} key can each make the key unreliable.
   *
   * <p>Gated on {@link LazyTokenClaimsConverter} because the documented {@code @Import} quickstart
   * doesn't pull in {@code CamundaAuthenticationBeansConfiguration}, where that bean and {@link
   * MembershipResolutionContextPropagator} live; backing off avoids a fatal wiring failure when
   * they're absent.
   *
   * <p>Two registrations that share an issuer resolve by the order of {@code
   * getOidcAuthenticationConfigurations()}, which is the order of the configuration with the flat
   * block first. The decoder of the same deployment reads that order as well, so the converter of a
   * token comes from the provider that verified it.
   *
   * <p>Providers declared only through a per-scope {@link CamundaSecurityScopeProvider} descriptor
   * (ADR-0013) — for example a physical tenant's own identity provider — are included too, so a
   * bearer token issued by a scope-only provider resolves with that provider's own claim
   * configuration instead of the cluster default. The root-level providers are processed first and
   * own any issuer they share with a scope, so a deployment with no scope providers is unchanged
   * (ADR-0024 / issue #668, fixing camunda/camunda#64685). A scope whose issuer a root-level or
   * earlier scope provider already owns is skipped — the same issuer legitimately recurs across
   * scopes (e.g. the default tenant appears both at root and as its own scope), so that overlap is
   * logged at {@code DEBUG} rather than warned about.
   */
  @Bean
  @ConditionalOnBean({MembershipPort.class, LazyTokenClaimsConverter.class})
  @ConditionalOnMissingBean
  public TokenClaimsConvertersByIssuer tokenClaimsConvertersByIssuer(
      final CamundaSecurityLibraryProperties properties,
      final OidcProviderConfigurationPort oidcProviderConfigurationPort,
      final LazyTokenClaimsConverter lazyTokenClaimsConverter,
      final MembershipPort membershipPort,
      final ObjectProvider<MembershipResolutionContextPropagator> contextPropagatorProvider,
      final ScopedClientRegistrationFactory scopedClientRegistrationFactory,
      final ObjectProvider<CamundaSecurityScopeProvider> scopeProviders) {
    final var contextPropagator =
        contextPropagatorProvider.getIfAvailable(MembershipResolutionContextPropagator::identity);
    final var flatOidcConfiguration = properties.getAuthentication().getOidc();
    final Map<String, LazyTokenClaimsConverter> byIssuer = new LinkedHashMap<>();

    // Root-level providers (flat oidc.* block + providers.oidc.*) first, so they own any issuer a
    // scope provider shares with them and a deployment without scope providers is unchanged.
    addConvertersByIssuer(
        byIssuer,
        oidcProviderConfigurationPort.getOidcAuthenticationConfigurations(),
        flatOidcConfiguration,
        lazyTokenClaimsConverter,
        membershipPort,
        contextPropagator,
        "the claim configuration");

    // Then providers declared only through per-scope descriptors (ADR-0013). flatten() merges each
    // scope's own flat + providers.oidc.* block the same way the root config port does.
    scopeProviders.stream()
        .flatMap(provider -> provider.get().stream())
        .forEach(
            descriptor ->
                addConvertersByIssuer(
                    byIssuer,
                    scopedClientRegistrationFactory.flatten(descriptor.authentication()),
                    flatOidcConfiguration,
                    lazyTokenClaimsConverter,
                    membershipPort,
                    contextPropagator,
                    "the claim configuration of scope '" + descriptor.basePath() + "'"));

    return new TokenClaimsConvertersByIssuer(byIssuer);
  }

  /**
   * Adds one issuer-keyed {@link LazyTokenClaimsConverter} per provider in {@code configurations}
   * that declares an {@code issuer-uri}, skipping any issuer already present in {@code byIssuer} so
   * an earlier source (the root config, or an earlier scope) keeps ownership.
   *
   * <p>{@link IssuerOwnership} decides the winner per issuer and logs the duplicate-issuer warning
   * — the one place that warning is built, redacted and sanitized. Blank/null registrationIds are
   * filtered first: a blank id must not win ownership over a valid provider sharing its issuer, or
   * the claims converter is built from the wrong configuration while the decoder verifies the token
   * with the valid one.
   */
  private static void addConvertersByIssuer(
      final Map<String, LazyTokenClaimsConverter> byIssuer,
      final Map<String, OidcConfiguration> configurations,
      final OidcConfiguration flatOidcConfiguration,
      final LazyTokenClaimsConverter defaultConverter,
      final MembershipPort membershipPort,
      final MembershipResolutionContextPropagator contextPropagator,
      final String ownershipLabel) {
    final var winningRegistrationIdByIssuer =
        IssuerOwnership.registrationIdByIssuer(
            ScopedClientRegistrationFactory.withoutBlankRegistrationIds(configurations),
            LOG,
            ownershipLabel);
    winningRegistrationIdByIssuer.forEach(
        (issuerUri, registrationId) -> {
          if (byIssuer.containsKey(issuerUri)) {
            LOG.debug(
                "Issuer '{}' already has a claim converter from an earlier provider; keeping it and"
                    + " ignoring {}.",
                issuerUri,
                ownershipLabel);
            return;
          }
          final var config = configurations.get(registrationId);
          final var converter =
              config == flatOidcConfiguration
                  ? defaultConverter
                  : new LazyTokenClaimsConverter(
                      config.getUsernameClaim(),
                      config.getClientIdClaim(),
                      config.isPreferUsernameClaim(),
                      membershipPort,
                      contextPropagator);
          byIssuer.put(issuerUri, converter);
        });
  }
}
