/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.core.port.in.OidcProviderConfigurationPort;
import io.camunda.security.spring.security.ProtectedOidcWebappCondition;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.jwt.JwtDecoder;

/**
 * Provides the client-registration-dependent OIDC beans ({@link JwtDecoder}, {@link
 * ClientRegistrationRepository}, {@link OAuth2AuthorizedClientRepository}, {@link
 * OAuth2AuthorizedClientManager}, {@link OAuth2AuthorizationRequestResolver}) when {@code
 * camunda.security.authentication.method=oidc} AND {@code
 * camunda.security.authentication.webapp-enabled} is not {@code false}.
 *
 * <p>Split out from {@link OidcBeansConfiguration} (camunda-security-library#548) because these
 * beans are only meaningful for the session-based {@code oauth2Login} webapp chain — the bearer API
 * chain needs only a {@link JwtDecoder}, which a bearer-only host typically supplies directly
 * (built from {@code jwk-set-uri}/{@code issuer-uri}, no client registration) rather than relying
 * on this class's registration-derived default. Hosts that disable the webapp chain via {@code
 * webapp-enabled=false} without providing their own {@link JwtDecoder} bean will find the API chain
 * fails to build (no {@link JwtDecoder} bean available) — this is intentional: it is the same
 * pattern already used by hosts like camunda-hub's {@code SaasJwtConfiguration}/{@code
 * SelfManagedJwtConfiguration}.
 */
@Configuration
@Conditional(ProtectedOidcWebappCondition.class)
public class OidcWebappClientBeansConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public ClientRegistrationRepository clientRegistrationRepository(
      final OidcProviderConfigurationPort oidcProviderConfigurationPort,
      final ScopedClientRegistrationFactory factory) {
    final Map<String, OidcConfiguration> sources =
        oidcProviderConfigurationPort.getOidcAuthenticationConfigurations();

    if (sources.isEmpty()) {
      throw new IllegalStateException(
          "Cannot build ClientRegistrationRepository: set"
              + " camunda.security.authentication.oidc.client-id (with issuer-uri or explicit"
              + " endpoints), or one or more"
              + " camunda.security.authentication.providers.oidc.<id>.* entries.");
    }

    final var registrations = factory.createFromProviderMap(sources);
    return new InMemoryClientRegistrationRepository(registrations);
  }

  @Bean
  @ConditionalOnMissingBean
  public JwtDecoder jwtDecoder(
      final ClientRegistrationRepository clientRegistrationRepository,
      final OidcProviderConfigurationPort oidcProviderConfigurationPort,
      final OidcAccessTokenDecoderFactory oidcAccessTokenDecoderFactory) {
    final var registrations = iterableRegistrations(clientRegistrationRepository);
    final var providers = oidcProviderConfigurationPort.getOidcAuthenticationConfigurations();
    return oidcAccessTokenDecoderFactory.selectAccessTokenDecoder(registrations, providers);
  }

  @SuppressWarnings("unchecked")
  private static List<ClientRegistration> iterableRegistrations(
      final ClientRegistrationRepository repository) {
    if (!(repository instanceof Iterable)) {
      throw new IllegalStateException(
          "The library's default JwtDecoder requires ClientRegistrationRepository to implement"
              + " Iterable<ClientRegistration> so it can enumerate all providers. Register a"
              + " custom @Bean JwtDecoder if you are using a non-iterable repository.");
    }
    final var result = new ArrayList<ClientRegistration>();
    ((Iterable<ClientRegistration>) repository).forEach(result::add);
    return result;
  }

  /**
   * Default {@link OAuth2AuthorizationRequestResolver} for the OIDC webapp chain. Injects
   * per-provider {@code additional_parameters} and the RFC 8707 {@code resource} parameter from
   * {@link OidcConfiguration} into the outgoing {@link
   * org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest}. Backs off via
   * {@link ConditionalOnMissingBean} when the host registers its own resolver — e.g. OC's existing
   * {@code ClientAwareOAuth2AuthorizationRequestResolver}, until the monorepo cleanup PR removes
   * it.
   *
   * <p>The {@link OidcConfiguration} sources map is sourced from {@link
   * OidcProviderConfigurationPort} so registrationIds stay aligned with those in {@link
   * #clientRegistrationRepository(OidcProviderConfigurationPort, ScopedClientRegistrationFactory)}.
   */
  @Bean
  @ConditionalOnMissingBean(OAuth2AuthorizationRequestResolver.class)
  public OAuth2AuthorizationRequestResolver oauth2AuthorizationRequestResolver(
      final ClientRegistrationRepository clientRegistrationRepository,
      final OidcProviderConfigurationPort oidcProviderConfigurationPort) {
    return new CamundaOidcAuthorizationRequestResolver(
        clientRegistrationRepository,
        oidcProviderConfigurationPort.getOidcAuthenticationConfigurations());
  }

  @Bean
  @ConditionalOnMissingBean
  public OAuth2AuthorizedClientRepository authorizedClientRepository() {
    return new HttpSessionOAuth2AuthorizedClientRepository();
  }

  @Bean
  @ConditionalOnMissingBean
  public OAuth2AuthorizedClientManager authorizedClientManager(
      final ClientRegistrationRepository clientRegistrationRepository,
      final OAuth2AuthorizedClientRepository authorizedClientRepository) {
    final var provider =
        OAuth2AuthorizedClientProviderBuilder.builder()
            .authorizationCode()
            .refreshToken()
            .clientCredentials()
            .build();
    final var manager =
        new DefaultOAuth2AuthorizedClientManager(
            clientRegistrationRepository, authorizedClientRepository);
    manager.setAuthorizedClientProvider(provider);
    return manager;
  }
}
