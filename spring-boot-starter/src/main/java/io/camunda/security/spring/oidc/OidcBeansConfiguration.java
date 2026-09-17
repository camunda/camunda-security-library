/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import io.camunda.security.api.context.MembershipResolutionContextPropagator;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import io.camunda.security.core.port.in.OidcProviderConfigurationPort;
import io.camunda.security.core.port.out.MembershipPort;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
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
   */
  @Bean
  @ConditionalOnBean({MembershipPort.class, LazyTokenClaimsConverter.class})
  @ConditionalOnMissingBean
  public TokenClaimsConvertersByIssuer tokenClaimsConvertersByIssuer(
      final CamundaSecurityLibraryProperties properties,
      final OidcProviderConfigurationPort oidcProviderConfigurationPort,
      final LazyTokenClaimsConverter lazyTokenClaimsConverter,
      final MembershipPort membershipPort,
      final ObjectProvider<MembershipResolutionContextPropagator> contextPropagatorProvider) {
    final var contextPropagator =
        contextPropagatorProvider.getIfAvailable(MembershipResolutionContextPropagator::identity);
    final var flatOidcConfiguration = properties.getAuthentication().getOidc();
    final var configurations = oidcProviderConfigurationPort.getOidcAuthenticationConfigurations();
    final Map<String, LazyTokenClaimsConverter> byIssuer = new LinkedHashMap<>();
    final Map<String, String> winningRegistrationIdByIssuer = new LinkedHashMap<>();
    for (final var registrationId : configurations.keySet()) {
      final var config = configurations.get(registrationId);
      final var issuerUri = config.getIssuerUri();
      if (issuerUri == null || issuerUri.isBlank()) {
        continue;
      }
      final var converter =
          config == flatOidcConfiguration
              ? lazyTokenClaimsConverter
              : new LazyTokenClaimsConverter(
                  config.getUsernameClaim(),
                  config.getClientIdClaim(),
                  config.isPreferUsernameClaim(),
                  membershipPort,
                  contextPropagator);
      if (byIssuer.putIfAbsent(issuerUri, converter) != null) {
        LOG.warn(
            "Issuer '{}' is claimed by multiple OIDC registrations: '{}' wins, and the tokens of"
                + " that issuer ignore the claim configuration of '{}'.",
            issuerUri,
            winningRegistrationIdByIssuer.get(issuerUri),
            registrationId);
      } else {
        winningRegistrationIdByIssuer.put(issuerUri, registrationId);
      }
    }
    return new TokenClaimsConvertersByIssuer(byIssuer);
  }
}
