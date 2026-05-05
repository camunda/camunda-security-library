/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import io.camunda.security.api.model.config.OidcConfiguration;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
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

/**
 * Provides default OIDC infrastructure beans ({@link JwtDecoder}, {@link
 * ClientRegistrationRepository}, {@link OAuth2AuthorizedClientRepository}, {@link
 * OAuth2AuthorizedClientManager}) when {@code camunda.security.authentication.method=oidc}. Hosts
 * that need custom wiring can override any bean via {@code @ConditionalOnMissingBean} back-off.
 */
@AutoConfiguration
@ConditionalOnProperty(name = "camunda.security.authentication.method", havingValue = "oidc")
public class OidcBeansAutoConfiguration {

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
    final OidcConfiguration oidc = properties.getAuthentication().getOidc();
    final ClientRegistration.Builder builder = clientRegistrationBuilder(oidc);
    final ClientRegistration registration =
        builder
            .registrationId(oidc.getRegistrationId())
            .clientId(oidc.getClientId())
            .clientSecret(oidc.getClientSecret())
            .clientAuthenticationMethod(
                new ClientAuthenticationMethod(oidc.getClientAuthenticationMethod()))
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri(oidc.getRedirectUri())
            .scope(oidc.getScope())
            .build();
    return new InMemoryClientRegistrationRepository(registration);
  }

  /**
   * Builds the {@link ClientRegistration.Builder} from {@link OidcConfiguration}. When {@code
   * issuer-uri} is set, OIDC discovery populates the authorization/token/user-info/jwk-set URIs
   * automatically. Adopters who only have explicit endpoints fall through to the empty-builder path
   * and must set those URIs explicitly.
   */
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
