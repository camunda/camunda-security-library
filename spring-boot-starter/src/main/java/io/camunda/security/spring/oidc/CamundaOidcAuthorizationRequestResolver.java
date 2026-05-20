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
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
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
 * <p>Expected request path: {@code /oauth2/authorization/{registrationId}}. Per-registrationId
 * delegating resolvers are cached in a {@link ConcurrentHashMap} so the customizer is built once
 * per id.
 *
 * <p>The {@code sourcesByRegistrationId} map MUST be built from the same flat-plus-providers merge
 * that produced the {@link ClientRegistrationRepository} so registrationIds stay aligned.
 */
public final class CamundaOidcAuthorizationRequestResolver
    implements OAuth2AuthorizationRequestResolver {

  private static final String ERROR_INVALID_CLIENT_REGISTRATION_ID =
      "Invalid Client Registration with ID '%s'";
  private static final String AUTHORIZATION_REQUEST_BASE_URI = "/oauth2/authorization";
  private static final String REGISTRATION_ID = "registrationId";

  private final ClientRegistrationRepository clientRegistrationRepository;
  private final Map<String, OidcConfiguration> sourcesByRegistrationId;
  private final Map<String, OAuth2AuthorizationRequestResolver> resolvers;
  private final RequestMatcher authorizationRequestMatcher;

  public CamundaOidcAuthorizationRequestResolver(
      final ClientRegistrationRepository clientRegistrationRepository,
      final Map<String, OidcConfiguration> sourcesByRegistrationId) {
    this.clientRegistrationRepository = clientRegistrationRepository;
    this.sourcesByRegistrationId = Map.copyOf(sourcesByRegistrationId);
    resolvers = new ConcurrentHashMap<>();
    authorizationRequestMatcher =
        PathPatternRequestMatcher.withDefaults()
            .matcher("%s/{%s}".formatted(AUTHORIZATION_REQUEST_BASE_URI, REGISTRATION_ID));
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

  private OAuth2AuthorizationRequestResolver getOrCreateResolver(final String registrationId) {
    return resolvers.computeIfAbsent(registrationId, this::createResolver);
  }

  private OAuth2AuthorizationRequestResolver createResolver(final String registrationId) {
    final var registration = clientRegistrationRepository.findByRegistrationId(registrationId);
    if (registration == null) {
      throw new IllegalArgumentException(
          ERROR_INVALID_CLIENT_REGISTRATION_ID.formatted(registrationId));
    }
    final var resolver =
        new DefaultOAuth2AuthorizationRequestResolver(
            clientRegistrationRepository, AUTHORIZATION_REQUEST_BASE_URI);
    final var source = sourcesByRegistrationId.get(registrationId);
    if (source != null) {
      resolver.setAuthorizationRequestCustomizer(createCustomizer(source));
    }
    return resolver;
  }

  private static Consumer<Builder> createCustomizer(final OidcConfiguration source) {
    return builder -> {
      final AuthorizeRequestConfiguration authorize = source.getAuthorizeRequest();
      final Map<String, Object> additionalParameters =
          authorize != null ? authorize.getAdditionalParameters() : null;
      if (additionalParameters != null && !additionalParameters.isEmpty()) {
        builder.additionalParameters(additionalParameters);
      }
      final var resource = source.getResource();
      if (resource != null && !resource.isEmpty()) {
        builder.additionalParameters(Map.of(OAuth2ParameterNames.RESOURCE, resource));
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
