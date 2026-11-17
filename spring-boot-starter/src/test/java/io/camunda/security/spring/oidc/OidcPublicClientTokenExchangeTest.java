/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.RestClientRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.RequestMatcher;
import org.springframework.web.client.RestClient;

/**
 * What a registration that CSL builds sends to the token endpoint, for the code exchange and for
 * the session refresh.
 *
 * <p>CSL writes no token request of its own. It builds the {@link ClientRegistration} and the
 * authorization request, and Spring derives the token request from both. These tests therefore run
 * the real Spring token response clients over the real CSL output, and assert the request on the
 * wire. A public client that sends a credential, or a confidential client that stops sending one,
 * fails here instead of at the identity provider of a customer.
 */
class OidcPublicClientTokenExchangeTest {

  private static final String REGISTRATION_ID = "oidc";
  private static final String CLIENT_ID = "client-id";
  private static final String CLIENT_SECRET = "client-secret";
  private static final String BASE = "https://idp.example.com";
  private static final String TOKEN_ENDPOINT = BASE + "/token";
  private static final String AUTHORIZATION_CODE = "the-authorization-code";
  private static final String REFRESH_TOKEN_VALUE = "the-refresh-token";

  private static final String TOKEN_RESPONSE =
      """
      {"access_token":"the-access-token","token_type":"Bearer","expires_in":300}""";

  private RestClient.Builder restClientBuilder;
  private MockRestServiceServer server;

  @BeforeEach
  void setUp() {
    restClientBuilder =
        RestClient.builder()
            .configureMessageConverters(
                messageConverters -> {
                  messageConverters.addCustomConverter(new FormHttpMessageConverter());
                  messageConverters.addCustomConverter(
                      new OAuth2AccessTokenResponseHttpMessageConverter());
                });
    server = MockRestServiceServer.bindTo(restClientBuilder).bufferContent().build();
  }

  @Test
  void shouldExchangeTheCodeOfAPublicClientWithoutClientAuthentication() {
    final var registration = registration("public", null);
    final var authorizationRequest = authorizationRequest(registration);
    server
        .expect(requestTo(TOKEN_ENDPOINT))
        .andExpect(post())
        .andExpect(
            headers(headers -> assertThat(headers.getFirst(HttpHeaders.AUTHORIZATION)).isNull()))
        .andExpect(
            formBody(
                fields ->
                    assertThat(fields)
                        .containsEntry("grant_type", "authorization_code")
                        .containsEntry("code", AUTHORIZATION_CODE)
                        .containsEntry("client_id", CLIENT_ID)
                        .containsEntry(
                            "code_verifier", authorizationRequest.getAttribute("code_verifier"))
                        .doesNotContainKey("client_secret")))
        .andRespond(withSuccess(TOKEN_RESPONSE, MediaType.APPLICATION_JSON));

    exchangeCode(registration, authorizationRequest);

    server.verify();
  }

  /**
   * A confidential client keeps the request it sends today: its secret in the {@code Authorization}
   * header, and never in the body.
   */
  @Test
  void shouldExchangeTheCodeOfAConfidentialClientWithItsSecret() {
    final var registration = registration("confidential", CLIENT_SECRET);
    final var authorizationRequest = authorizationRequest(registration);
    server
        .expect(requestTo(TOKEN_ENDPOINT))
        .andExpect(post())
        .andExpect(
            headers(
                headers ->
                    assertThat(headers.getFirst(HttpHeaders.AUTHORIZATION))
                        .isEqualTo(basicAuth(CLIENT_ID, CLIENT_SECRET))))
        .andExpect(
            formBody(
                fields ->
                    assertThat(fields)
                        .containsEntry("grant_type", "authorization_code")
                        .containsEntry("code", AUTHORIZATION_CODE)
                        .doesNotContainKeys("client_id", "client_secret")))
        .andRespond(withSuccess(TOKEN_RESPONSE, MediaType.APPLICATION_JSON));

    exchangeCode(registration, authorizationRequest);

    server.verify();
  }

  @Test
  void shouldRefreshTheSessionOfAPublicClientWithoutClientAuthentication() {
    final var registration = registration("public", null);
    server
        .expect(requestTo(TOKEN_ENDPOINT))
        .andExpect(post())
        .andExpect(
            headers(headers -> assertThat(headers.getFirst(HttpHeaders.AUTHORIZATION)).isNull()))
        .andExpect(
            formBody(
                fields ->
                    assertThat(fields)
                        .containsEntry("grant_type", "refresh_token")
                        .containsEntry("refresh_token", REFRESH_TOKEN_VALUE)
                        .containsEntry("client_id", CLIENT_ID)
                        .doesNotContainKey("client_secret")))
        .andRespond(withSuccess(TOKEN_RESPONSE, MediaType.APPLICATION_JSON));

    refresh(registration);

    server.verify();
  }

  @Test
  void shouldRefreshTheSessionOfAConfidentialClientWithItsSecret() {
    final var registration = registration("confidential", CLIENT_SECRET);
    server
        .expect(requestTo(TOKEN_ENDPOINT))
        .andExpect(post())
        .andExpect(
            headers(
                headers ->
                    assertThat(headers.getFirst(HttpHeaders.AUTHORIZATION))
                        .isEqualTo(basicAuth(CLIENT_ID, CLIENT_SECRET))))
        .andExpect(
            formBody(
                fields ->
                    assertThat(fields)
                        .containsEntry("grant_type", "refresh_token")
                        .containsEntry("refresh_token", REFRESH_TOKEN_VALUE)
                        .doesNotContainKeys("client_id", "client_secret")))
        .andRespond(withSuccess(TOKEN_RESPONSE, MediaType.APPLICATION_JSON));

    refresh(registration);

    server.verify();
  }

  private void exchangeCode(
      final ClientRegistration registration,
      final OAuth2AuthorizationRequest authorizationRequest) {
    final var authorizationResponse =
        OAuth2AuthorizationResponse.success(AUTHORIZATION_CODE)
            .redirectUri(authorizationRequest.getRedirectUri())
            .state(authorizationRequest.getState())
            .build();
    final var client = new RestClientAuthorizationCodeTokenResponseClient();
    client.setRestClient(restClientBuilder.build());

    client.getTokenResponse(
        new OAuth2AuthorizationCodeGrantRequest(
            registration,
            new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse)));
  }

  private void refresh(final ClientRegistration registration) {
    final var client = new RestClientRefreshTokenTokenResponseClient();
    client.setRestClient(restClientBuilder.build());

    client.getTokenResponse(
        new OAuth2RefreshTokenGrantRequest(
            registration,
            new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "the-expired-access-token",
                Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().minus(1, ChronoUnit.MINUTES)),
            new OAuth2RefreshToken(REFRESH_TOKEN_VALUE, Instant.now())));
  }

  /** The registration CSL builds for a provider block of the given type. */
  private static ClientRegistration registration(final String type, final String clientSecret) {
    final var oidc =
        OidcConfiguration.builder()
            .clientId(CLIENT_ID)
            .clientSecret(clientSecret)
            .type(type)
            .redirectUri("{baseUrl}/sso-callback")
            .authorizationUri(BASE + "/auth")
            .tokenUri(TOKEN_ENDPOINT)
            .jwkSetUri(BASE + "/jwks")
            .build();
    return new ScopedClientRegistrationFactory()
        .createFromProviderMap(Map.of(REGISTRATION_ID, oidc))
        .get(0);
  }

  /** The authorization request CSL sends for that registration, PKCE attributes included. */
  private static OAuth2AuthorizationRequest authorizationRequest(
      final ClientRegistration registration) {
    final ClientRegistrationRepository repository =
        id -> REGISTRATION_ID.equals(id) ? registration : null;
    final var resolver =
        new CamundaOidcAuthorizationRequestResolver(
            repository, Map.of(REGISTRATION_ID, new OidcConfiguration()));
    return resolver.resolve(
        new MockHttpServletRequest("GET", "/oauth2/authorization/" + REGISTRATION_ID));
  }

  /**
   * Asserts on the decoded form fields rather than a raw body substring, so percent-encoding cannot
   * make an assertion pass or fail by accident, and so absent fields can be asserted too.
   */
  private static RequestMatcher formBody(final Consumer<Map<String, String>> assertion) {
    return request ->
        assertion.accept(formFields(((MockClientHttpRequest) request).getBodyAsString()));
  }

  private static RequestMatcher requestTo(final String uri) {
    return request -> assertThat(request.getURI()).hasToString(uri);
  }

  private static RequestMatcher post() {
    return request -> assertThat(request.getMethod()).isEqualTo(HttpMethod.POST);
  }

  /**
   * The header counterpart of {@link #formBody}. Spring's own {@code MockRestRequestMatchers}
   * resolve through a {@code Matcher}-typed overload, which drags Hamcrest onto the compile
   * classpath, and CSL tests are AssertJ-only.
   */
  private static RequestMatcher headers(final Consumer<HttpHeaders> assertion) {
    return request -> assertion.accept(request.getHeaders());
  }

  private static Map<String, String> formFields(final String body) {
    if (body.isEmpty()) {
      return Map.of();
    }
    return Arrays.stream(body.split("&"))
        .map(pair -> pair.split("=", 2))
        .collect(
            Collectors.toMap(
                pair -> URLDecoder.decode(pair[0], StandardCharsets.UTF_8),
                pair -> pair.length > 1 ? URLDecoder.decode(pair[1], StandardCharsets.UTF_8) : "",
                (first, second) -> first));
  }

  private static String basicAuth(final String clientId, final String clientSecret) {
    return "Basic "
        + Base64.getEncoder()
            .encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
  }
}
