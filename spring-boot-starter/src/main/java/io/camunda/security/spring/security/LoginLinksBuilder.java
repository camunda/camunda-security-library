/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;

final class LoginLinksBuilder {

  private LoginLinksBuilder() {}

  static DefaultLoginPageGeneratingFilter defaultOauth2LoginPickerFilter(
      final ClientRegistrationRepository clientRegistrationRepository, final String loginPageUrl) {
    final var picker = new DefaultLoginPageGeneratingFilter();
    picker.setLoginPageUrl(loginPageUrl);
    picker.setOauth2LoginEnabled(true);
    picker.setOauth2AuthenticationUrlToClientName(buildLoginLinks(clientRegistrationRepository));
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
        links.put("/oauth2/authorization/" + registration.getRegistrationId(), displayName);
      }
    }
    return links;
  }
}
