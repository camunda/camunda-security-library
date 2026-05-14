/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.security.CamundaOidcLogoutSuccessHandler;
import java.util.LinkedHashMap;
import java.util.Map;
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
import org.springframework.util.StringUtils;

/**
 * Provides default OIDC infrastructure beans ({@link JwtDecoder}, {@link
 * ClientRegistrationRepository}, {@link OAuth2AuthorizedClientRepository}, {@link
 * OAuth2AuthorizedClientManager}) when {@code camunda.security.authentication.method=oidc}. Hosts
 * that need custom wiring can override any bean via {@code @ConditionalOnMissingBean} back-off.
 */
@Configuration
@ConditionalOnProperty(name = "camunda.security.authentication.method", havingValue = "oidc")
public class OidcBeansConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public JwtDecoder jwtDecoder(final CamundaSecurityLibraryProperties properties) {
    // Single-decoder model: pick the flat block when configured, otherwise the sole providers entry
    // with a JWT source. When multiple providers are configured without a flat block, the host must
    // register their own JwtDecoder bean — a single decoder cannot correctly validate tokens from
    // multiple IdPs, so the library refuses to guess.
    final OidcConfiguration source = pickJwtDecoderSource(properties.getAuthentication());
    if (StringUtils.hasText(source.getJwkSetUri())) {
      return NimbusJwtDecoder.withJwkSetUri(source.getJwkSetUri()).build();
    }
    return NimbusJwtDecoder.withIssuerLocation(source.getIssuerUri()).build();
  }

  private static OidcConfiguration pickJwtDecoderSource(
      final AuthenticationConfiguration authentication) {
    final OidcConfiguration flat = authentication.getOidc();
    if (hasJwtSource(flat)) {
      return flat;
    }
    final var providerSources =
        authentication.getProviders().getOidc().values().stream()
            .filter(OidcBeansConfiguration::hasJwtSource)
            .toList();
    if (providerSources.size() == 1) {
      return providerSources.get(0);
    }
    if (providerSources.isEmpty()) {
      throw new IllegalStateException(
          "Cannot build JwtDecoder: set issuer-uri or jwk-set-uri under"
              + " camunda.security.authentication.oidc.* or under at least one"
              + " camunda.security.authentication.providers.oidc.<id>.* entry.");
    }
    throw new IllegalStateException(
        "Cannot build a single JwtDecoder when multiple providers are configured under"
            + " camunda.security.authentication.providers.oidc.* and the flat oidc block has no"
            + " issuer-uri or jwk-set-uri. Either configure the flat block to pin the resource-server"
            + " audience, or register a custom @Bean JwtDecoder in the host application.");
  }

  private static boolean hasJwtSource(final OidcConfiguration oidc) {
    return StringUtils.hasText(oidc.getJwkSetUri()) || StringUtils.hasText(oidc.getIssuerUri());
  }

  @Bean
  @ConditionalOnMissingBean
  public ClientRegistrationRepository clientRegistrationRepository(
      final CamundaSecurityLibraryProperties properties) {
    final var authentication = properties.getAuthentication();
    final OidcConfiguration flat = authentication.getOidc();
    final Map<String, OidcConfiguration> providers = authentication.getProviders().getOidc();

    // Mirrors OC's OidcAuthenticationConfigurationRepository: the flat block contributes a single
    // registration under its own registrationId when clientId is set; the providers map is merged
    // on top so a colliding provider id overwrites the flat entry.
    final Map<String, OidcConfiguration> sources = new LinkedHashMap<>();
    if (StringUtils.hasText(flat.getClientId())) {
      sources.put(flat.getRegistrationId(), flat);
    }
    sources.putAll(providers);

    if (sources.isEmpty()) {
      throw new IllegalStateException(
          "Cannot build ClientRegistrationRepository: set"
              + " camunda.security.authentication.oidc.client-id (with issuer-uri or explicit"
              + " endpoints), or one or more"
              + " camunda.security.authentication.providers.oidc.<id>.* entries.");
    }

    final var registrations =
        sources.entrySet().stream()
            .map(e -> buildClientRegistration(e.getKey(), e.getValue()))
            .toList();
    return new InMemoryClientRegistrationRepository(registrations);
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
    return clientRegistrationBuilder(registrationId, oidc)
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
      final String registrationId, final OidcConfiguration oidc) {
    if (StringUtils.hasText(oidc.getIssuerUri())) {
      return ClientRegistrations.fromIssuerLocation(oidc.getIssuerUri());
    }
    if (!StringUtils.hasText(oidc.getAuthorizationUri())
        || !StringUtils.hasText(oidc.getTokenUri())
        || !StringUtils.hasText(oidc.getJwkSetUri())) {
      throw new IllegalStateException(
          "Cannot build ClientRegistration '"
              + registrationId
              + "': set issuer-uri, or all of authorization-uri, token-uri, and jwk-set-uri,"
              + " under camunda.security.authentication.oidc.* (flat) or"
              + " camunda.security.authentication.providers.oidc."
              + registrationId
              + ".*");
    }
    return ClientRegistration.withRegistrationId(registrationId)
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
