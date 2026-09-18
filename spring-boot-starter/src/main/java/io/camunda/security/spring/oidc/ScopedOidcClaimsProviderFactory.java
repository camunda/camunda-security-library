/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.camunda.security.api.context.OidcClaimsProvider;
import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.micrometer.core.instrument.MeterRegistry;
import java.net.http.HttpClient;
import java.util.Map;
import java.util.Objects;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.util.StringUtils;

/**
 * Builds an {@link OidcClaimsProvider} from a single {@link AuthenticationConfiguration}, as {@link
 * ScopedJwtDecoderFactory} builds a decoder.
 *
 * <p>The per-scope configuration decides whether augmentation runs, through {@code
 * oidc.userInfoAugmentation}, and not the global {@link
 * io.camunda.security.spring.CamundaSecurityLibraryProperties}. Each scope therefore controls its
 * own augmentation, which a physical tenant needs.
 *
 * <p>Augmentation redirects no browser, so this factory builds its registrations with {@link
 * ScopedClientRegistrationFactory#createWithoutLoginRoutes}. Augmentation then also runs on a scope
 * that serves no login route.
 */
public final class ScopedOidcClaimsProviderFactory {

  private final ScopedClientRegistrationFactory clientRegistrationFactory;
  private final OidcUserInfoHttpClient userInfoHttpClient;
  private final MeterRegistry meterRegistry;

  /**
   * @param clientRegistrationFactory resolves a scope's OIDC {@link ClientRegistration}s
   * @param httpClient the HTTP client used to call IdP UserInfo endpoints
   * @param objectMapper used to parse UserInfo responses
   * @param meterRegistry metrics sink, may be {@code null}
   */
  public ScopedOidcClaimsProviderFactory(
      final ScopedClientRegistrationFactory clientRegistrationFactory,
      final HttpClient httpClient,
      final ObjectMapper objectMapper,
      final MeterRegistry meterRegistry) {
    this.clientRegistrationFactory =
        Objects.requireNonNull(
            clientRegistrationFactory, "clientRegistrationFactory must not be null");
    Objects.requireNonNull(httpClient, "httpClient must not be null");
    Objects.requireNonNull(objectMapper, "objectMapper must not be null");
    userInfoHttpClient = new OidcUserInfoHttpClient(httpClient, objectMapper);
    this.meterRegistry = meterRegistry;
  }

  /**
   * Builds an {@link OidcClaimsProvider} for one {@link AuthenticationConfiguration}. A
   * configuration that sets no {@code oidc.userInfoAugmentation}, or disables it, gets a {@link
   * NoopOidcClaimsProvider}.
   *
   * <p>The UserInfo endpoint of an issuer comes from a {@link ClientRegistration}, which OIDC
   * discovery resolves. The claims provider resolves the registration of one issuer at the first
   * claims lookup that carries that issuer. The application therefore makes no network request
   * while it builds the chain, and an identity provider that does not answer fails the tokens of
   * its own issuer only. See {@link IssuerRegistrations}.
   *
   * @throws IllegalStateException if augmentation is enabled and the configuration declares no OIDC
   *     provider, or a provider block is incomplete. Such a configuration would leave the scope
   *     without augmentation and report nothing.
   */
  public OidcClaimsProvider buildClaimsProvider(final AuthenticationConfiguration authentication) {
    return buildClaimsProvider(authentication, null);
  }

  /**
   * As {@link #buildClaimsProvider(AuthenticationConfiguration)}, but a failure log also names the
   * scope, and the rate limit of that log counts per scope.
   *
   * @param scopeDescription the name a log message gives to the scope (for example {@code
   *     basePath=/physical-tenants/t1}), or {@code null} for the unscoped text
   */
  public OidcClaimsProvider buildClaimsProvider(
      final AuthenticationConfiguration authentication, final String scopeDescription) {
    Objects.requireNonNull(authentication, "authentication must not be null");
    final var augmentation = authentication.getOidc().getUserInfoAugmentation();
    if (augmentation == null || !augmentation.isEnabled()) {
      return new NoopOidcClaimsProvider();
    }

    final var providers = clientRegistrationFactory.flatten(authentication);
    if (providers.isEmpty()) {
      throw new IllegalStateException(
          "UserInfo augmentation is enabled for the scope but its AuthenticationConfiguration"
              + " declares no OIDC provider, so a claims provider cannot be built. Either configure"
              + " an OIDC provider (oidc.client-id + issuer-uri / explicit endpoints, or one or more"
              + " providers.oidc.<id> entries) or disable userinfo augmentation for this scope.");
    }
    clientRegistrationFactory.validateWithoutLoginRoutes(providers);
    return new CachingOidcClaimsProvider(
        userInfoHttpClient,
        CachingOidcClaimsProvider.userInfoUriByIssuer(
            IssuerRegistrations.ofConfiguration(
                providers,
                registrationId -> resolve(providers, registrationId, scopeDescription),
                "the UserInfo endpoint"),
            providers),
        augmentation,
        meterRegistry);
  }

  /**
   * Resolves one provider of the scope. A failure log names the provider and the scope, so the rate
   * limit of the log counts per provider and per scope.
   */
  private ClientRegistration resolve(
      final Map<String, OidcConfiguration> providers,
      final String registrationId,
      final String scopeDescription) {
    final var config = providers.get(registrationId);
    return DeferredOidcResolution.resolve(
        claimsSubject(registrationId, config, scopeDescription),
        () ->
            clientRegistrationFactory
                .createWithoutLoginRoutes(Map.of(registrationId, config))
                .getFirst());
  }

  private static String claimsSubject(
      final String registrationId, final OidcConfiguration config, final String scopeDescription) {
    return "the UserInfo endpoint of provider "
        + DeferredOidcResolution.describeProvider(registrationId, config)
        + (StringUtils.hasText(scopeDescription) ? " for " + scopeDescription : "");
  }
}
