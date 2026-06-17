/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import io.camunda.security.spring.scope.BasePaths;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;

final class LoginLinksBuilder {

  private LoginLinksBuilder() {}

  static DefaultLoginPageGeneratingFilter defaultOauth2LoginPickerFilter(
      final ClientRegistrationRepository clientRegistrationRepository, final String loginPageUrl) {
    return defaultOauth2LoginPickerFilter(clientRegistrationRepository, loginPageUrl, "");
  }

  /**
   * Builds the login picker filter with authorization links prefixed by {@code
   * authorizationBaseUriPrefix}. Use this overload for per-scope chains where the authorization
   * endpoint lives under a basePath (e.g. {@code /physical-tenants/t1/oauth2/authorization/{id}}).
   */
  static DefaultLoginPageGeneratingFilter defaultOauth2LoginPickerFilter(
      final ClientRegistrationRepository clientRegistrationRepository,
      final String loginPageUrl,
      final String authorizationBaseUriPrefix) {
    final var picker = new DefaultLoginPageGeneratingFilter();
    picker.setLoginPageUrl(loginPageUrl);
    picker.setOauth2LoginEnabled(true);
    picker.setOauth2AuthenticationUrlToClientName(
        buildLoginLinks(clientRegistrationRepository, authorizationBaseUriPrefix));
    return picker;
  }

  /**
   * Builds the {@code /oauth2/authorization/{id}} -> client display name map consumed by {@link
   * DefaultLoginPageGeneratingFilter#setOauth2AuthenticationUrlToClientName(Map)}. Returns an empty
   * map when the repository is not iterable (host-supplied implementation that does not extend
   * {@link Iterable}); the picker then renders without OAuth2 links, which still beats a 404.
   */
  static Map<String, String> buildLoginLinks(
      final ClientRegistrationRepository clientRegistrationRepository) {
    return buildLoginLinks(clientRegistrationRepository, "");
  }

  /**
   * Builds the authorization URL -> client display name map with each URL prefixed by {@code
   * prefix}. An empty or null prefix yields unprefixed {@code /oauth2/authorization/{id}} links. A
   * root {@code /} prefix is valid and normalizes to the empty prefix, producing the same
   * unprefixed links. A non-empty, non-root prefix (e.g. {@code /physical-tenants/t1}) yields
   * {@code /physical-tenants/t1/oauth2/authorization/{id}}.
   */
  static Map<String, String> buildLoginLinks(
      final ClientRegistrationRepository clientRegistrationRepository, final String prefix) {
    final String normalizedPrefix;
    if (prefix == null || prefix.isBlank()) {
      normalizedPrefix = "";
    } else {
      normalizedPrefix = BasePaths.normalize(prefix, "prefix");
    }
    final var links = new LinkedHashMap<String, String>();
    if (!(clientRegistrationRepository instanceof final Iterable<?> iterable)) {
      return links;
    }
    for (final Object candidate : iterable) {
      if (candidate instanceof final ClientRegistration registration) {
        final var displayName =
            registration.getClientName() != null
                ? registration.getClientName()
                : registration.getRegistrationId();
        links.put(
            normalizedPrefix + "/oauth2/authorization/" + registration.getRegistrationId(),
            displayName);
      }
    }
    return links;
  }
}
