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
import java.util.stream.Collectors;
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
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
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
  public OidcProviderConfigurationPort oidcProviderConfigurationPort(
      final CamundaSecurityLibraryProperties properties) {
    return new OidcAuthenticationConfigurationRepository(properties);
  }

  @Bean
  @ConditionalOnMissingBean
  public JWSKeySelectorFactory jwsKeySelectorFactory() {
    return new JWSKeySelectorFactory();
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
  public OidcAccessTokenDecoderFactory oidcAccessTokenDecoderFactory(
      final JWSKeySelectorFactory jwsKeySelectorFactory,
      final TokenValidatorFactory tokenValidatorFactory) {
    return new OidcAccessTokenDecoderFactory(jwsKeySelectorFactory, tokenValidatorFactory);
  }

  @Bean
  @ConditionalOnMissingBean
  public JwtDecoder jwtDecoder(
      final ClientRegistrationRepository clientRegistrationRepository,
      final OidcProviderConfigurationPort oidcProviderConfigurationPort,
      final OidcAccessTokenDecoderFactory oidcAccessTokenDecoderFactory) {
    final var registrations = iterableRegistrations(clientRegistrationRepository);
    final var providers = oidcProviderConfigurationPort.getOidcAuthenticationConfigurations();
    if (registrations.size() == 1) {
      final var reg = registrations.get(0);
      final var config = providers.get(reg.getRegistrationId());
      final var additional = config != null ? config.getAdditionalJwkSetUris() : null;
      return oidcAccessTokenDecoderFactory.createAccessTokenDecoder(reg, additional);
    }
    return oidcAccessTokenDecoderFactory.createIssuerAwareAccessTokenDecoder(
        registrations, buildAdditionalJwkSetUrisByIssuer(registrations, providers));
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

  private static Map<String, List<String>> buildAdditionalJwkSetUrisByIssuer(
      final List<ClientRegistration> registrations,
      final Map<String, OidcConfiguration> providers) {
    return registrations.stream()
        .filter(
            reg -> {
              final var config = providers.get(reg.getRegistrationId());
              return config != null
                  && config.getAdditionalJwkSetUris() != null
                  && config.getAdditionalJwkSetUris().stream().anyMatch(StringUtils::hasText)
                  && StringUtils.hasText(reg.getProviderDetails().getIssuerUri());
            })
        .collect(
            Collectors.toMap(
                reg -> reg.getProviderDetails().getIssuerUri(),
                reg -> providers.get(reg.getRegistrationId()).getAdditionalJwkSetUris(),
                (a, b) -> a));
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
      final OidcProviderConfigurationPort oidcProviderConfigurationPort) {
    final Map<String, OidcConfiguration> sources =
        oidcProviderConfigurationPort.getOidcAuthenticationConfigurations();

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
   * automatically; any explicitly-configured endpoint URI on {@link OidcConfiguration} then
   * overrides the discovered value. When {@code issuer-uri} is unset, all of authorization-uri,
   * token-uri, and jwk-set-uri must be configured explicitly. The {@code registrationId} argument
   * is the map key in the multi-provider shape and {@link OidcConfiguration#getRegistrationId()} in
   * the legacy flat shape.
   */
  private static ClientRegistration buildClientRegistration(
      final String registrationId, final OidcConfiguration oidc) {
    if (!StringUtils.hasText(registrationId)) {
      throw new IllegalStateException(
          "OIDC registrationId must be non-blank: set"
              + " camunda.security.authentication.oidc.registration-id (flat block)"
              + " or use a non-blank key under"
              + " camunda.security.authentication.providers.oidc.<id>.*");
    }
    final ClientRegistration.Builder builder =
        clientRegistrationBuilder(registrationId, oidc)
            .registrationId(registrationId)
            .clientId(oidc.getClientId())
            .clientSecret(oidc.getClientSecret())
            .clientAuthenticationMethod(
                new ClientAuthenticationMethod(oidc.getClientAuthenticationMethod()))
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri(oidc.getRedirectUri())
            .scope(oidc.getScope());
    if (StringUtils.hasText(oidc.getClientName())) {
      builder.clientName(oidc.getClientName());
    }
    if (!oidc.isUserInfoEnabled()) {
      builder.userInfoUri(null);
    }
    return builder.build();
  }

  /**
   * Builds the base {@link ClientRegistration.Builder}: discovery via {@code issuer-uri} when set,
   * otherwise an empty builder; in both cases any explicitly-configured endpoint URI on {@link
   * OidcConfiguration} overrides the discovered value. A non-blank value on the configuration
   * always wins; a null/blank value leaves the discovered value untouched.
   *
   * <p>Mirrors OC's previous {@code ClientRegistrationFactory} so that adopters can rely on
   * explicit overrides to plug gaps in incomplete IdP discovery metadata (older Keycloak realms,
   * custom STS endpoints, proxies that rewrite discovery documents). See
   * camunda/camunda-security-library#233.
   */
  private static ClientRegistration.Builder clientRegistrationBuilder(
      final String registrationId, final OidcConfiguration oidc) {
    final boolean hasIssuer = StringUtils.hasText(oidc.getIssuerUri());
    final ClientRegistration.Builder builder =
        hasIssuer
            ? ClientRegistrations.fromIssuerLocation(oidc.getIssuerUri())
                .registrationId(registrationId)
            : ClientRegistration.withRegistrationId(registrationId);

    if (!hasIssuer
        && (!StringUtils.hasText(oidc.getAuthorizationUri())
            || !StringUtils.hasText(oidc.getTokenUri())
            || !StringUtils.hasText(oidc.getJwkSetUri()))) {
      throw new IllegalStateException(
          "Cannot build ClientRegistration '"
              + registrationId
              + "': set issuer-uri, or all of authorization-uri, token-uri, and jwk-set-uri,"
              + " under camunda.security.authentication.oidc.* (flat) or"
              + " camunda.security.authentication.providers.oidc."
              + registrationId
              + ".*");
    }

    if (StringUtils.hasText(oidc.getAuthorizationUri())) {
      builder.authorizationUri(oidc.getAuthorizationUri());
    }
    if (StringUtils.hasText(oidc.getTokenUri())) {
      builder.tokenUri(oidc.getTokenUri());
    }
    if (StringUtils.hasText(oidc.getJwkSetUri())) {
      builder.jwkSetUri(oidc.getJwkSetUri());
    }
    if (StringUtils.hasText(oidc.getUserInfoUri())) {
      builder.userInfoUri(oidc.getUserInfoUri());
    }
    if (StringUtils.hasText(oidc.getEndSessionEndpointUri())) {
      // Spring's ClientRegistration carries end_session_endpoint via providerConfigurationMetadata.
      // Setting the map replaces the discovered metadata wholesale, so seed it with only the
      // explicit override; discovery already populated the builder's other endpoints individually.
      builder.providerConfigurationMetadata(
          Map.of("end_session_endpoint", oidc.getEndSessionEndpointUri()));
    }
    return builder;
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
   * #clientRegistrationRepository(OidcProviderConfigurationPort)}.
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
