/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import io.camunda.security.api.context.OidcClaimsProvider;
import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

/**
 * Entry point for building an {@link OidcClaimsProvider} from a single {@link
 * AuthenticationConfiguration}. Parallels {@link ScopedJwtDecoderFactory}: derives
 * issuer→userInfoUri from the config's {@link ClientRegistration}s via {@link
 * ScopedClientRegistrationFactory} and constructs either a {@link CachingOidcClaimsProvider} (when
 * augmentation is enabled on the config) or a {@link NoopOidcClaimsProvider} (otherwise).
 *
 * <p>Augmentation enabled-flag and cache settings are read from the per-scope {@link
 * AuthenticationConfiguration} (via {@code oidc.userInfoAugmentation}), not from the global {@link
 * io.camunda.security.spring.CamundaSecurityLibraryProperties}. This ensures that each scope's
 * augmentation behaviour is determined by its own configuration, enabling per-physical-tenant
 * control.
 */
public final class ScopedOidcClaimsProviderFactory {

  private static final Logger LOG = LoggerFactory.getLogger(ScopedOidcClaimsProviderFactory.class);

  private final ScopedClientRegistrationFactory clientRegistrationFactory;
  private final OidcUserInfoHttpClient userInfoHttpClient;
  private final MeterRegistry meterRegistry;

  public ScopedOidcClaimsProviderFactory(
      final ScopedClientRegistrationFactory clientRegistrationFactory,
      final OidcUserInfoHttpClient userInfoHttpClient,
      final MeterRegistry meterRegistry) {
    this.clientRegistrationFactory = clientRegistrationFactory;
    this.userInfoHttpClient = userInfoHttpClient;
    this.meterRegistry = meterRegistry;
  }

  /**
   * Builds an {@link OidcClaimsProvider} for the given {@link AuthenticationConfiguration}.
   *
   * <p>Returns a {@link CachingOidcClaimsProvider} when {@code
   * authentication.getOidc().getUserInfoAugmentation().isEnabled()} is {@code true}, with an
   * issuer→userInfoUri map derived from the config's OIDC providers. Returns a {@link
   * NoopOidcClaimsProvider} otherwise.
   *
   * @param authentication the per-scope authentication configuration; must not be {@code null}
   * @return an {@link OidcClaimsProvider} appropriate for the given config
   */
  public OidcClaimsProvider buildClaimsProvider(final AuthenticationConfiguration authentication) {
    final var augmentation = authentication.getOidc().getUserInfoAugmentation();
    if (!augmentation.isEnabled()) {
      return new NoopOidcClaimsProvider();
    }

    final List<ClientRegistration> registrations = clientRegistrationFactory.create(authentication);
    final Map<String, String> uriByIssuer = buildUserInfoUriByIssuer(registrations);
    if (uriByIssuer.isEmpty()) {
      LOG.warn(
          "UserInfo augmentation is enabled but no ClientRegistration has a userInfoUri;"
              + " augmentation will silently skip every request. Ensure"
              + " camunda.security.authentication.oidc.user-info-enabled=true (the default)"
              + " and that the IdP's discovery document includes a userinfo_endpoint.");
    }
    return new CachingOidcClaimsProvider(
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
