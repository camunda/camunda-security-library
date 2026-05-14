/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.security.CamundaOidcLogoutSuccessHandler;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

/**
 * Provides default OIDC infrastructure beans ({@link JwtDecoder}, {@link
 * ClientRegistrationRepository}, {@link OAuth2AuthorizedClientRepository}, {@link
 * OAuth2AuthorizedClientManager}) when {@code camunda.security.authentication.method=oidc}. Hosts
 * that need custom wiring can override any bean via {@code @ConditionalOnMissingBean} back-off.
 */
@Configuration
@ConditionalOnProperty(name = "camunda.security.authentication.method", havingValue = "oidc")
public class OidcBeansConfiguration {

  static final String DEPRECATION_BOTH_SHAPES_SET =
      "Both camunda.security.authentication.oidc.* and"
          + " camunda.security.authentication.providers.oidc.* are configured."
          + " The flat shape is deprecated and ignored when providers.oidc is non-empty;"
          + " remove the flat block once migration is complete.";

  private static final Logger LOG = LoggerFactory.getLogger(OidcBeansConfiguration.class);

  @Bean
  @ConditionalOnMissingBean
  public JwtDecoder jwtDecoder(final CamundaSecurityLibraryProperties properties) {
    final OidcConfiguration oidc = properties.getAuthentication().getOidc();
    if (oidc.getJwkSetUri() != null && !oidc.getJwkSetUri().isBlank()) {
      return NimbusJwtDecoder.withJwkSetUri(oidc.getJwkSetUri()).build();
    }
    if (oidc.getIssuerUri() != null && !oidc.getIssuerUri().isBlank()) {
      return NimbusJwtDecoder.withIssuerLocation(oidc.getIssuerUri()).build();
    }
    throw new IllegalStateException(
        "Cannot build JwtDecoder: set either"
            + " camunda.security.authentication.oidc.jwk-set-uri"
            + " or camunda.security.authentication.oidc.issuer-uri.");
  }

  @Bean
  @ConditionalOnMissingBean
  public ClientRegistrationRepository clientRegistrationRepository(
      final CamundaSecurityLibraryProperties properties) {
    final var authentication = properties.getAuthentication();
    final Map<String, OidcConfiguration> providers = authentication.getProviders().getOidc();
    final OidcConfiguration flat = authentication.getOidc();

    if (!providers.isEmpty()) {
      if (isFlatShapeConfigured(flat)) {
        LOG.warn(DEPRECATION_BOTH_SHAPES_SET);
      }
      final List<ClientRegistration> registrations = new ArrayList<>(providers.size());
      providers.forEach((id, oidc) -> registrations.add(buildClientRegistration(id, oidc)));
      return new InMemoryClientRegistrationRepository(registrations);
    }

    return new InMemoryClientRegistrationRepository(
        buildClientRegistration(flat.getRegistrationId(), flat));
  }

  /**
   * Builds a single {@link ClientRegistration} from {@link OidcConfiguration}. When {@code
   * issuer-uri} is set, OIDC discovery populates the authorization/token/user-info/jwk-set URIs
   * automatically. Otherwise the explicit endpoints must be configured. The {@code registrationId}
   * argument is the map key in the multi-provider shape and {@link
   * OidcConfiguration#getRegistrationId()} in the legacy flat shape.
   */
  private static ClientRegistration buildClientRegistration(
      final String registrationId, final OidcConfiguration oidc) {
    return clientRegistrationBuilder(oidc)
        .registrationId(registrationId)
        .clientId(oidc.getClientId())
        .clientSecret(oidc.getClientSecret())
        .clientAuthenticationMethod(
            new ClientAuthenticationMethod(oidc.getClientAuthenticationMethod()))
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri(oidc.getRedirectUri())
        .scope(oidc.getScope())
        .build();
  }

  private static ClientRegistration.Builder clientRegistrationBuilder(
      final OidcConfiguration oidc) {
    if (oidc.getIssuerUri() != null && !oidc.getIssuerUri().isBlank()) {
      return ClientRegistrations.fromIssuerLocation(oidc.getIssuerUri());
    }
    if (oidc.getAuthorizationUri() == null
        || oidc.getTokenUri() == null
        || oidc.getJwkSetUri() == null) {
      throw new IllegalStateException(
          "Cannot build ClientRegistrationRepository: set"
              + " camunda.security.authentication.oidc.issuer-uri,"
              + " or all of authorization-uri, token-uri, and jwk-set-uri.");
    }
    return ClientRegistration.withRegistrationId(oidc.getRegistrationId())
        .authorizationUri(oidc.getAuthorizationUri())
        .tokenUri(oidc.getTokenUri())
        .userInfoUri(oidc.getUserInfoUri())
        .jwkSetUri(oidc.getJwkSetUri());
  }

  private static boolean isFlatShapeConfigured(final OidcConfiguration flat) {
    return (flat.getIssuerUri() != null && !flat.getIssuerUri().isBlank())
        || flat.getAuthorizationUri() != null
        || flat.getTokenUri() != null
        || flat.getJwkSetUri() != null
        || flat.getClientId() != null;
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
