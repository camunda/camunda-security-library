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
import io.micrometer.core.instrument.MeterRegistry;
import java.net.http.HttpClient;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

/**
 * Entry point for building an {@link OidcClaimsProvider} from a single {@link
 * AuthenticationConfiguration}. Parallels {@link ScopedJwtDecoderFactory}: derives
 * issuer→userInfoUri from the config's {@link ClientRegistration}s via {@link
 * ScopedClientRegistrationFactory}. When augmentation is enabled on the config it builds a {@link
 * CachingOidcClaimsProvider}, failing fast if the config declares no OIDC provider or none exposes
 * a userInfoUri; when augmentation is disabled it returns a {@link NoopOidcClaimsProvider}.
 *
 * <p>Augmentation enabled-flag and cache settings are read from the per-scope {@link
 * AuthenticationConfiguration} (via {@code oidc.userInfoAugmentation}), not from the global {@link
 * io.camunda.security.spring.CamundaSecurityLibraryProperties}. This ensures that each scope's
 * augmentation behaviour is determined by its own configuration, enabling per-physical-tenant
 * control.
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
   * Builds an {@link OidcClaimsProvider} for the given {@link AuthenticationConfiguration}.
   *
   * <p>Returns a {@link CachingOidcClaimsProvider} when augmentation is enabled on the config —
   * that is, {@code authentication.getOidc().getUserInfoAugmentation()} is non-null and its {@code
   * isEnabled()} is {@code true} — with an issuer→userInfoUri map derived from the config's OIDC
   * providers. A null augmentation config is treated as disabled; in that case (or when not
   * enabled) returns a {@link NoopOidcClaimsProvider}.
   *
   * @param authentication the per-scope authentication configuration; must not be {@code null}
   * @return an {@link OidcClaimsProvider} appropriate for the given config
   * @throws IllegalStateException if augmentation is enabled but the config declares no OIDC
   *     provider, or declares providers none of which exposes a userInfoUri — both are config
   *     mismatches that would leave the scope silently un-augmented (the provider-less case mirrors
   *     {@link ScopedJwtDecoderFactory}, which also rejects a provider-less OIDC scope)
   */
  public OidcClaimsProvider buildClaimsProvider(final AuthenticationConfiguration authentication) {
    Objects.requireNonNull(authentication, "authentication must not be null");
    final var augmentation = authentication.getOidc().getUserInfoAugmentation();
    if (augmentation == null || !augmentation.isEnabled()) {
      return new NoopOidcClaimsProvider();
    }

    final List<ClientRegistration> registrations = clientRegistrationFactory.create(authentication);
    if (registrations.isEmpty()) {
      throw new IllegalStateException(
          "UserInfo augmentation is enabled for the scope but its AuthenticationConfiguration"
              + " declares no OIDC provider, so a claims provider cannot be built. Either configure"
              + " an OIDC provider (oidc.client-id + issuer-uri / explicit endpoints, or one or more"
              + " providers.oidc.<id> entries) or disable userinfo augmentation for this scope."
              + " This mirrors ScopedJwtDecoderFactory, which also rejects a provider-less OIDC"
              + " scope.");
    }
    final Map<String, String> uriByIssuer = buildUserInfoUriByIssuer(registrations);
    return CachingOidcClaimsProvider.forConfiguredMappings(
        userInfoHttpClient, uriByIssuer, augmentation, meterRegistry);
  }

  /**
   * Extracts the issuer→userInfoUri map from a list of {@link ClientRegistration}s. Registrations
   * without both an issuerUri and a userInfoUri are silently skipped.
   */
  static Map<String, String> buildUserInfoUriByIssuer(
      final List<ClientRegistration> registrations) {
    final Map<String, String> map = new HashMap<>();
    for (final ClientRegistration reg : registrations) {
      final String issuerUri = reg.getProviderDetails().getIssuerUri();
      final String userInfoUri = reg.getProviderDetails().getUserInfoEndpoint().getUri();
      if (issuerUri != null
          && !issuerUri.isBlank()
          && userInfoUri != null
          && !userInfoUri.isBlank()) {
        map.put(issuerUri, userInfoUri);
      }
    }
    return map;
  }
}
