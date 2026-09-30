/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import io.camunda.security.api.model.config.oidc.AuthorizeRequestConfiguration;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.spring.scope.BasePaths;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.function.Function;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest.Builder;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * CSL default {@link OAuth2AuthorizationRequestResolver} for the OIDC webapp chain. Lifts OC's
 * {@code ClientAwareOAuth2AuthorizationRequestResolver}: per-registrationId, wraps Spring
 * Security's {@link DefaultOAuth2AuthorizationRequestResolver} with a customizer that injects
 * {@code additional_parameters} and the {@code resource} (RFC 8707) parameter from {@link
 * OidcConfiguration} into the outgoing {@link OAuth2AuthorizationRequest}.
 *
 * <p>The resolver is constructed with an {@code authorizationRequestBaseUri} that determines where
 * authorization requests are matched. For the primary chain this is the unprefixed {@code
 * /oauth2/authorization}; for per-scope chains it is {@code <basePath>/oauth2/authorization}.
 * Authorization requests are then matched at {@code
 * <authorizationRequestBaseUri>/{registrationId}}. Per-registrationId delegating resolvers are
 * cached in a {@link ConcurrentHashMap} so the customizer is built once per id.
 *
 * <p>When constructed with a {@code maxAge}, every outgoing request also carries the OIDC {@code
 * max_age} parameter (OpenID Connect Core 1.0 §3.1.2.1), so the IdP re-authenticates the user
 * unless they authenticated at the IdP within that window. An explicit {@code max_age} in {@code
 * authorize-request.additional-parameters} takes precedence. See ADR-0031.
 *
 * <p>The {@code sourcesByRegistrationId} map MUST be built from the same flat-plus-providers merge
 * that produced the {@link ClientRegistrationRepository} so registrationIds stay aligned.
 */
public final class CamundaOidcAuthorizationRequestResolver
    implements OAuth2AuthorizationRequestResolver {

  static final String AUTHORIZATION_REQUEST_BASE_URI = "/oauth2/authorization";

  private static final String ERROR_INVALID_CLIENT_REGISTRATION_ID =
      "Invalid Client Registration with ID '%s'";
  private static final String REGISTRATION_ID = "registrationId";
  private static final String MAX_AGE = "max_age";

  private final ClientRegistrationRepository clientRegistrationRepository;
  private final Map<String, OidcConfiguration> sourcesByRegistrationId;
  private final Map<String, OAuth2AuthorizationRequestResolver> resolvers;
  private final String authorizationRequestBaseUri;
  private final RequestMatcher authorizationRequestMatcher;
  private final Long maxAgeSeconds;

  /** Uses the default unprefixed authorization base URI {@code /oauth2/authorization}. */
  public CamundaOidcAuthorizationRequestResolver(
      final ClientRegistrationRepository clientRegistrationRepository,
      final Map<String, OidcConfiguration> sourcesByRegistrationId) {
    this(clientRegistrationRepository, sourcesByRegistrationId, AUTHORIZATION_REQUEST_BASE_URI);
  }

  /**
   * @param authorizationRequestBaseUri the authorization endpoint base URI, e.g. {@code
   *     /oauth2/authorization} for the primary chain or {@code <basePath>/oauth2/authorization} for
   *     a per-scope chain. The {registrationId} segment is appended to it.
   */
  public CamundaOidcAuthorizationRequestResolver(
      final ClientRegistrationRepository clientRegistrationRepository,
      final Map<String, OidcConfiguration> sourcesByRegistrationId,
      final String authorizationRequestBaseUri) {
    this(clientRegistrationRepository, sourcesByRegistrationId, authorizationRequestBaseUri, null);
  }

  /**
   * @param maxAge when non-null, sent as {@code max_age} (whole seconds) on every authorization
   *     request that does not already configure one; {@code null} sends none
   */
  public CamundaOidcAuthorizationRequestResolver(
      final ClientRegistrationRepository clientRegistrationRepository,
      final Map<String, OidcConfiguration> sourcesByRegistrationId,
      final String authorizationRequestBaseUri,
      final Duration maxAge) {
    Objects.requireNonNull(
        clientRegistrationRepository, "clientRegistrationRepository must not be null");
    Objects.requireNonNull(sourcesByRegistrationId, "sourcesByRegistrationId must not be null");
    final var normalizedBaseUri =
        BasePaths.normalize(authorizationRequestBaseUri, "authorizationRequestBaseUri");
    if (normalizedBaseUri.isEmpty()) {
      throw new IllegalArgumentException(
          "authorizationRequestBaseUri must not be the root path '/' — it would configure an empty"
              + " OAuth2 authorization base and match arbitrary single-segment paths; was: "
              + authorizationRequestBaseUri);
    }
    this.clientRegistrationRepository = clientRegistrationRepository;
    // ScopedClientRegistrationFactory#withoutBlankRegistrationIds: Map.copyOf below rejects a
    // null key outright, and a blank registrationId is warn-only, not rejected, elsewhere.
    this.sourcesByRegistrationId =
        Map.copyOf(
            ScopedClientRegistrationFactory.withoutBlankRegistrationIds(sourcesByRegistrationId));
    this.authorizationRequestBaseUri = normalizedBaseUri;
    if (maxAge != null && maxAge.isNegative()) {
      throw new IllegalArgumentException("maxAge must not be negative: " + maxAge);
    }
    maxAgeSeconds = maxAge == null ? null : maxAge.toSeconds();
    resolvers = new ConcurrentHashMap<>();
    authorizationRequestMatcher =
        PathPatternRequestMatcher.withDefaults()
            .matcher("%s/{%s}".formatted(normalizedBaseUri, REGISTRATION_ID));
  }

  @Override
  public OAuth2AuthorizationRequest resolve(final HttpServletRequest request) {
    final var registrationId = resolveRegistrationId(request);
    return resolveInternal(registrationId, r -> r.resolve(request));
  }

  @Override
  public OAuth2AuthorizationRequest resolve(
      final HttpServletRequest request, final String registrationId) {
    return resolveInternal(registrationId, r -> r.resolve(request, registrationId));
  }

  private OAuth2AuthorizationRequest resolveInternal(
      final String registrationId,
      final Function<OAuth2AuthorizationRequestResolver, OAuth2AuthorizationRequest>
          requestSupplier) {
    if (registrationId == null || registrationId.isBlank()) {
      return null;
    }
    return Optional.of(getOrCreateResolver(registrationId)).map(requestSupplier).orElse(null);
  }

  /**
   * The resolver of a registration. {@code get} then {@code putIfAbsent}, not {@code
   * computeIfAbsent}: the latter locks part of the map while it builds the resolver, and that build
   * resolves the registration. An unreachable identity provider would hold that lock for the
   * complete discovery timeout, and the requests of the other registrations in the same bin would
   * wait for it. Two builds of the same registration therefore run at the same time, and the first
   * result wins.
   */
  private OAuth2AuthorizationRequestResolver getOrCreateResolver(final String registrationId) {
    final var cached = resolvers.get(registrationId);
    if (cached != null) {
      return cached;
    }
    final var resolver = createResolver(registrationId);
    final var winner = resolvers.putIfAbsent(registrationId, resolver);
    return winner != null ? winner : resolver;
  }

  private OAuth2AuthorizationRequestResolver createResolver(final String registrationId) {
    final var registration = clientRegistrationRepository.findByRegistrationId(registrationId);
    if (registration == null) {
      throw new IllegalArgumentException(
          ERROR_INVALID_CLIENT_REGISTRATION_ID.formatted(registrationId));
    }
    final var resolver =
        new DefaultOAuth2AuthorizationRequestResolver(
            clientRegistrationRepository, authorizationRequestBaseUri);
    final var source = sourcesByRegistrationId.get(registrationId);
    if (source != null || maxAgeSeconds != null) {
      resolver.setAuthorizationRequestCustomizer(createCustomizer(source));
    }
    return resolver;
  }

  private Consumer<Builder> createCustomizer(final OidcConfiguration source) {
    return builder -> {
      final AuthorizeRequestConfiguration authorize =
          source != null ? source.getAuthorizeRequest() : null;
      final Map<String, Object> additionalParameters =
          authorize != null ? authorize.getAdditionalParameters() : null;
      if (additionalParameters != null && !additionalParameters.isEmpty()) {
        builder.additionalParameters(additionalParameters);
      }
      final var resource = source != null ? source.getResource() : null;
      if (resource != null && !resource.isEmpty()) {
        builder.additionalParameters(Map.of(OAuth2ParameterNames.RESOURCE, resource));
      }
      final boolean maxAgeConfigured =
          additionalParameters != null && additionalParameters.containsKey(MAX_AGE);
      if (maxAgeSeconds != null && !maxAgeConfigured) {
        builder.additionalParameters(Map.of(MAX_AGE, maxAgeSeconds));
      }
    };
  }

  private String resolveRegistrationId(final HttpServletRequest request) {
    if (!authorizationRequestMatcher.matches(request)) {
      return null;
    }
    return authorizationRequestMatcher.matcher(request).getVariables().get(REGISTRATION_ID);
  }
}
