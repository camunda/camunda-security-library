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
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.SupplierJwtDecoder;

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

    return new LazyClientRegistrationRepository(factory, sources);
  }

  /**
   * The default {@link JwtDecoder} of the OIDC chains. To read the repository is to resolve each
   * registration, which OIDC discovery resolves. {@link SupplierJwtDecoder} therefore builds the
   * decoder at the first token decode, and not while the application starts, because an identity
   * provider it cannot reach must not stop the application context. The issuer requirement that the
   * issuer-aware decoder makes on a deployment with several providers is checked against the
   * configuration here, so that such a configuration error still stops the start. The check runs on
   * the repository of the library only, because the configuration describes the registrations the
   * library built. A host repository can hold another set, and the decoder checks the registrations
   * of that set at the first token decode.
   */
  @Bean
  @ConditionalOnMissingBean
  public JwtDecoder jwtDecoder(
      final ClientRegistrationRepository clientRegistrationRepository,
      final OidcProviderConfigurationPort oidcProviderConfigurationPort,
      final OidcAccessTokenDecoderFactory oidcAccessTokenDecoderFactory) {
    final var providers = oidcProviderConfigurationPort.getOidcAuthenticationConfigurations();
    if (clientRegistrationRepository instanceof LazyClientRegistrationRepository) {
      oidcAccessTokenDecoderFactory.validateProvidersHaveIssuer(providers);
    }
    return new SupplierJwtDecoder(
        () ->
            DeferredOidcResolution.resolve(
                decoderSubject(clientRegistrationRepository, providers),
                () ->
                    oidcAccessTokenDecoderFactory.selectAccessTokenDecoder(
                        iterableRegistrations(clientRegistrationRepository), providers)));
  }

  /**
   * Names the decoder that a failure log reports, together with each provider the decoder covers. A
   * host repository holds a set of registrations that the configuration of the library does not
   * describe, so the subject names the host instead of naming providers the failure may not
   * concern.
   */
  private static String decoderSubject(
      final ClientRegistrationRepository repository,
      final Map<String, OidcConfiguration> providers) {
    return "the OIDC access-token decoder "
        + (repository instanceof LazyClientRegistrationRepository
            ? "for provider(s) " + DeferredOidcResolution.describeProviders(providers)
            : "of the ClientRegistrationRepository of the host application");
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
