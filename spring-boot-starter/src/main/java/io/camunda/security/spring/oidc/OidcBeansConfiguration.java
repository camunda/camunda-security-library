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
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.security.CamundaOidcLogoutSuccessHandler;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
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
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

/**
 * Provides default OIDC infrastructure beans ({@link JwtDecoder}, {@link
 * ClientRegistrationRepository}, {@link OAuth2AuthorizedClientRepository}, {@link
 * OAuth2AuthorizedClientManager}) when {@code camunda.security.authentication.method=oidc}. Hosts
 * that need custom wiring can override any bean via {@code @ConditionalOnMissingBean} back-off.
 *
 * <p>The per-scope OIDC factories ({@code JWSKeySelectorFactory}, {@code
 * ScopedClientRegistrationFactory}, {@code OidcAccessTokenDecoderFactory}, {@code
 * ScopedJwtDecoderFactory}) are declared in the unconditional {@link
 * ScopedOidcInfrastructureConfiguration} so they are available regardless of the global
 * authentication method. Because the {@link #jwtDecoder} and {@link #clientRegistrationRepository}
 * beans here consume {@code OidcAccessTokenDecoderFactory} / {@code
 * ScopedClientRegistrationFactory} from that configuration, it is {@code @Import}ed so a host that
 * opts in by importing only {@code OidcBeansConfiguration} (the documented quickstart) still gets a
 * working context. Its beans are {@code @ConditionalOnMissingBean}, so importing it here and via
 * the {@code CamundaSecurityAutoConfiguration} umbrella is idempotent.
 */
@Configuration
@ConditionalOnProperty(name = "camunda.security.authentication.method", havingValue = "oidc")
@Import(ScopedOidcInfrastructureConfiguration.class)
public class OidcBeansConfiguration {

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

  @Bean
  @ConditionalOnMissingBean
  public AssertionJwkProvider assertionJwkProvider(
      final OidcProviderConfigurationPort oidcProviderConfigurationPort) {
    return new AssertionJwkProvider(oidcProviderConfigurationPort);
  }

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

  /**
   * Default {@link LogoutSuccessHandler} for the OIDC webapp chain. Preserves OC's RP-initiated
   * logout behaviour: a same-origin {@code Referer} is stored as the post-logout redirect URI on
   * the session under {@link CamundaOidcLogoutSuccessHandler#POST_LOGOUT_REDIRECT_ATTRIBUTE}, and
   * the OIDC {@code login_hint} claim is forwarded as {@code logout_hint} to the IdP's end-session
   * endpoint. Backs off via {@link ConditionalOnMissingBean} when the host registers its own {@link
   * LogoutSuccessHandler}.
   */
  @Bean
  @ConditionalOnMissingBean(LogoutSuccessHandler.class)
  public LogoutSuccessHandler camundaOidcLogoutSuccessHandler(
      final ClientRegistrationRepository clientRegistrationRepository) {
    return new CamundaOidcLogoutSuccessHandler(clientRegistrationRepository);
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
