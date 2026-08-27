/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import jakarta.servlet.FilterChain;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

/**
 * Unit coverage for {@link CamundaLoginPickerFilter} in isolation (no Spring Security filter
 * chain), complementing the filter-chain-level assertions in {@link OidcWebappLoginPickerTest} and
 * {@link ScopedWebappSecurityChainBuilderScopedTest}.
 */
@ExtendWith(MockitoExtension.class)
class CamundaLoginPickerFilterTest {

  @Mock private FilterChain filterChain;

  @Test
  void fallsThroughForNonLoginPaths() throws Exception {
    final var filter =
        new CamundaLoginPickerFilter(registrations("oidc", "oidc-secondary"), "/login");
    final var request = new MockHttpServletRequest("GET", "/some-other-path");
    final var response = new MockHttpServletResponse();

    filter.doFilter(request, response, filterChain);

    verify(filterChain).doFilter(request, response);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentAsString()).isEmpty();
  }

  @Test
  void fallsThroughForNonGetRequestsToTheLoginPath() throws Exception {
    final var filter =
        new CamundaLoginPickerFilter(registrations("oidc", "oidc-secondary"), "/login");
    final var request = new MockHttpServletRequest("POST", "/login");
    final var response = new MockHttpServletResponse();

    filter.doFilter(request, response, filterChain);

    verify(filterChain).doFilter(request, response);
  }

  @Test
  void fallsThroughWhenNoRegistrationsArePresent() throws Exception {
    // InMemoryClientRegistrationRepository rejects an empty collection, so an empty-but-iterable
    // repository is simulated directly — the same shape LoginLinksBuilder.buildLoginLinks handles.
    final ClientRegistrationRepository empty =
        new ClientRegistrationRepository() {
          @Override
          public ClientRegistration findByRegistrationId(final String registrationId) {
            return null;
          }
        };
    final var filter = new CamundaLoginPickerFilter(empty, "/login");
    final var request = new MockHttpServletRequest("GET", "/login");
    final var response = new MockHttpServletResponse();

    filter.doFilter(request, response, filterChain);

    verify(filterChain).doFilter(request, response);
  }

  @Test
  void redirectsStraightToTheSoleProviderInsteadOfRenderingAPicker() throws Exception {
    final var filter = new CamundaLoginPickerFilter(registrations("oidc"), "/login");
    final var request = new MockHttpServletRequest("GET", "/login");
    final var response = new MockHttpServletResponse();

    filter.doFilter(request, response, filterChain);

    verify(filterChain, never()).doFilter(request, response);
    assertThat(response.getStatus()).isEqualTo(302);
    assertThat(response.getRedirectedUrl()).isEqualTo("/oauth2/authorization/oidc");
  }

  @Test
  void rendersACamundaBrandedPickerForMultipleProviders() throws Exception {
    final var filter =
        new CamundaLoginPickerFilter(registrations("oidc", "oidc-secondary"), "/login");
    final var request = new MockHttpServletRequest("GET", "/login");
    final var response = new MockHttpServletResponse();

    filter.doFilter(request, response, filterChain);

    verify(filterChain, never()).doFilter(request, response);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentType()).startsWith("text/html");
    final var body = response.getContentAsString();
    assertThat(body)
        .contains("Sign in to Camunda")
        .contains("/oauth2/authorization/oidc\"")
        .contains("/oauth2/authorization/oidc-secondary\"")
        .contains("oidc")
        .contains("oidc-secondary");
  }

  @Test
  void escapesProviderDisplayNamesToPreventMarkupInjection() throws Exception {
    final var registration =
        ClientRegistration.withRegistrationId("oidc")
            .clientId("client")
            .clientName("<script>alert(1)</script>")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("{baseUrl}/sso-callback")
            .authorizationUri("https://idp/authorize")
            .tokenUri("https://idp/token")
            .build();
    final var registrationTwo =
        ClientRegistration.withRegistrationId("oidc-secondary")
            .clientId("client-2")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("{baseUrl}/sso-callback")
            .authorizationUri("https://idp2/authorize")
            .tokenUri("https://idp2/token")
            .build();
    final var filter =
        new CamundaLoginPickerFilter(
            new InMemoryClientRegistrationRepository(registration, registrationTwo), "/login");
    final var request = new MockHttpServletRequest("GET", "/login");
    final var response = new MockHttpServletResponse();

    filter.doFilter(request, response, filterChain);

    final var body = response.getContentAsString();
    assertThat(body)
        .as("a host-configured client name must never be written to the page unescaped")
        .doesNotContain("<script>alert(1)</script>")
        .contains("&lt;script&gt;");
  }

  private static ClientRegistrationRepository registrations(final String... registrationIds) {
    final var registrations =
        Arrays.stream(registrationIds).map(CamundaLoginPickerFilterTest::registration).toList();
    return new InMemoryClientRegistrationRepository(registrations);
  }

  private static ClientRegistration registration(final String id) {
    return ClientRegistration.withRegistrationId(id)
        .clientId(id + "-client")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/sso-callback")
        .authorizationUri("https://idp/" + id + "/authorize")
        .tokenUri("https://idp/" + id + "/token")
        .build();
  }
}
