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
   * OidcTokenAuthenticationConverter}, covering every configured provider that declares a non-blank
   * {@code issuer-uri}. A provider without one (explicit endpoints, no discovery) can never be
   * represented here, so its tokens fall back to the default converter.
   *
   * <p>The default/primary provider's entry reuses the host-supplied {@code
   * CamundaAuthenticationBeansConfiguration#lazyTokenClaimsConverter} bean instance rather than
   * rebuilding an equivalent one, so the two can't drift out of sync.
   *
   * <p>If two registrations declare the same issuer, only one occupies that map entry (first one
   * encountered wins) and a WARN is logged.
   */
  @Bean
  @ConditionalOnBean(MembershipPort.class)
  @ConditionalOnMissingBean
  public TokenClaimsConvertersByIssuer tokenClaimsConvertersByIssuer(
      final OidcProviderConfigurationPort oidcProviderConfigurationPort,
      final LazyTokenClaimsConverter lazyTokenClaimsConverter,
      final MembershipPort membershipPort,
      final MembershipResolutionContextPropagator contextPropagator) {
    final Map<String, LazyTokenClaimsConverter> byIssuer = new LinkedHashMap<>();
    oidcProviderConfigurationPort
        .getOidcAuthenticationConfigurations()
        .forEach(
            (registrationId, config) -> {
              final var issuerUri = config.getIssuerUri();
              if (issuerUri == null || issuerUri.isBlank()) {
                return;
              }
              final var converter =
                  OidcConfiguration.DEFAULT_REGISTRATION_ID.equals(registrationId)
                      ? lazyTokenClaimsConverter
                      : new LazyTokenClaimsConverter(
                          config.getUsernameClaim(),
                          config.getClientIdClaim(),
                          config.isPreferUsernameClaim(),
                          membershipPort,
                          contextPropagator);
              if (byIssuer.putIfAbsent(issuerUri, converter) != null) {
                LOG.warn(
                    "Multiple OIDC registrations declare issuer '{}'; bearer tokens from this"
                        + " issuer will all be converted using the first-configured registration's"
                        + " claim config.",
                    issuerUri);
              }
            });
    return new TokenClaimsConvertersByIssuer(byIssuer);
  }
}
