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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.util.StringUtils;

/**
 * Builds an {@link OidcClaimsProvider} from a single {@link AuthenticationConfiguration}. The
 * counterpart of {@link ScopedJwtDecoderFactory} for UserInfo claims: it derives the map from an
 * issuer to a userInfoUri from the {@link ClientRegistration}s of that configuration, through
 * {@link ScopedClientRegistrationFactory}.
 *
 * <p>The per-scope configuration decides whether augmentation runs, through {@code
 * oidc.userInfoAugmentation}, and not the global {@link
 * io.camunda.security.spring.CamundaSecurityLibraryProperties}. Each scope therefore controls its
 * own augmentation, which a physical tenant needs.
 *
 * <p>This factory builds its registrations with {@link
 * ScopedClientRegistrationFactory#createWithoutLoginRoutes}, as the sibling factory does.
 * Augmentation reads the issuer and the UserInfo endpoint of a registration for each request, and
 * it redirects no browser. It therefore also runs on a scope whose redirect-uri or registration id
 * serves no login route.
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
   * <p>The map from an issuer to a userInfoUri comes from resolved {@link ClientRegistration}s,
   * which OIDC discovery resolves. The provider builds the map at the first claims lookup, so the
   * application makes no network request while it builds the chain. See {@link
   * DeferredOidcClaimsProvider}.
   *
   * @throws IllegalStateException if augmentation is enabled and the configuration declares no OIDC
   *     provider, or a provider block is incomplete. Each of these configurations leaves the scope
   *     without augmentation and reports nothing. {@link ScopedJwtDecoderFactory} refuses such a
   *     scope as well.
   */
  public OidcClaimsProvider buildClaimsProvider(final AuthenticationConfiguration authentication) {
    return buildClaimsProvider(authentication, null);
  }

  /**
   * As {@link #buildClaimsProvider(AuthenticationConfiguration)}. A failure log of the claims
   * provider also names the scope the provider belongs to, and the rate limit of that log counts
   * per scope.
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
              + " providers.oidc.<id> entries) or disable userinfo augmentation for this scope."
              + " This mirrors ScopedJwtDecoderFactory, which also rejects a provider-less OIDC"
              + " scope.");
    }
    clientRegistrationFactory.validateWithoutLoginRoutes(providers);
    return new DeferredOidcClaimsProvider(
        claimsSubject(providers, scopeDescription),
        () ->
            CachingOidcClaimsProvider.forConfiguredMappings(
                userInfoHttpClient,
                buildUserInfoUriByIssuer(
                    clientRegistrationFactory.createWithoutLoginRoutes(providers)),
                augmentation,
                meterRegistry));
  }

  private static String claimsSubject(
      final Map<String, OidcConfiguration> providers, final String scopeDescription) {
    return "the per-issuer UserInfo endpoint mapping"
        + (StringUtils.hasText(scopeDescription) ? " for " + scopeDescription : "")
        + " with provider(s) "
        + DeferredOidcResolution.describeProviders(providers);
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
