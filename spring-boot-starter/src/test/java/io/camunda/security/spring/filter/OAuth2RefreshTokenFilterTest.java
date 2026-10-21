/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletResponse;
import java.net.ConnectException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.web.client.ResourceAccessException;

@ExtendWith(MockitoExtension.class)
class OAuth2RefreshTokenFilterTest {

  private static final String REGISTRATION_ID = "registration-id";

  @Mock private OAuth2AuthorizedClientRepository authorizedClientRepository;
  @Mock private OAuth2AuthorizedClientManager authorizedClientManager;
  @Mock private LogoutHandler logoutHandler;
  @Mock private FilterChain chain;

  private MockHttpServletRequest request;
  private MockHttpServletResponse response;
  private ListAppender<ILoggingEvent> appender;
  private Level originalLevel;

  @BeforeEach
  void setUp() {
    request = new MockHttpServletRequest();
    response = new MockHttpServletResponse();
    final Logger logger = filterLogger();
    originalLevel = logger.getLevel();
    logger.setLevel(Level.DEBUG);
    appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);
  }

  @AfterEach
  void tearDown() {
    final Logger logger = filterLogger();
    logger.detachAppender(appender);
    logger.setLevel(originalLevel);
  }

  @Test
  void shouldPassThroughWhenNoOAuth2AuthenticationPresent() throws Exception {
    // given - an unauthenticated request (empty security context)
    final var filter = filter(new SecurityContextImpl());

    // when
    filter.doFilter(request, response, chain);

    // then - filter is a no-op for non-OAuth2 authentication
    verify(chain).doFilter(request, response);
    verify(authorizedClientRepository, never()).loadAuthorizedClient(any(), any(), any());
  }

  @Test
  void shouldLogoutWhenNoAuthorizedClientCanBeLoaded() throws Exception {
    // given - the repository has nothing stored for this principal/registration
    final OAuth2AuthenticationToken authenticationToken = authenticationToken();
    givenStoredClient(authenticationToken, null);

    // when
    final OAuth2AuthenticationException thrown = runFilterExpectingLogout(authenticationToken);

    // then
    assertThat(thrown.getError().getErrorCode()).isEqualTo("unauthorized_client");
    verify(logoutHandler).logout(request, response, authenticationToken);
    verify(chain, never()).doFilter(any(), any());
  }

  @Test
  void shouldPassThroughWhenAccessTokenNotExpired() throws Exception {
    // given - a still-valid access token
    final OAuth2AuthenticationToken authenticationToken = authenticationToken();
    givenStoredClient(authenticationToken, authorizedClient(false, true));

    // when
    filter(authenticationToken).doFilter(request, response, chain);

    // then - no refresh is attempted
    verify(chain).doFilter(request, response);
    verify(authorizedClientManager, never()).authorize(any());
  }

  @Test
  void shouldLogoutWhenAccessTokenExpiredAndNoRefreshTokenExists() throws Exception {
    // given - an expired access token with no refresh token to fall back on
    final OAuth2AuthenticationToken authenticationToken = authenticationToken();
    givenStoredClient(authenticationToken, authorizedClient(true, false));

    // when
    final OAuth2AuthenticationException thrown = runFilterExpectingLogout(authenticationToken);

    // then
    assertThat(thrown.getError().getErrorCode()).isEqualTo("access_token_expired");
    verify(logoutHandler).logout(request, response, authenticationToken);
    verify(authorizedClientManager, never()).authorize(any());
  }

  /**
   * The IdP says the refresh token itself is no longer valid, so no retry can succeed: the session
   * ends.
   */
  @ParameterizedTest
  @ValueSource(strings = {"invalid_grant", "invalid_token", "unauthorized_client"})
  void shouldLogoutWhenIdpRejectsTheRefreshToken(final String errorCode) throws Exception {
    // given - DefaultOAuth2AuthorizedClientManager#authorize rethrows the provider's
    // OAuth2AuthorizationException as-is on a failed refresh
    final OAuth2AuthenticationToken authenticationToken = authenticationToken();
    givenStoredClient(authenticationToken, authorizedClient(true, true));
    when(authorizedClientManager.authorize(any()))
        .thenThrow(
            new ClientAuthorizationException(
                new OAuth2Error(errorCode), REGISTRATION_ID, "Token is not active"));

    // when - the raw ClientAuthorizationException must not escape the filter: it is converted to
    // the controlled OAuth2AuthenticationException + logout flow
    final OAuth2AuthenticationException thrown = runFilterExpectingLogout(authenticationToken);

    // then - the failure handler relies on the cause
    assertThat(thrown.getError().getErrorCode()).isEqualTo("refresh_token_failed");
    assertThat(thrown).hasCauseInstanceOf(ClientAuthorizationException.class);
    assertThat(authenticationToken.isAuthenticated()).isFalse();
    verify(logoutHandler).logout(request, response, authenticationToken);
    verify(chain, never()).doFilter(any(), any());
    assertThat(warnings())
        .singleElement()
        .satisfies(
            message ->
                assertThat(message)
                    .contains("subject 'user-1'")
                    .contains("registration '" + REGISTRATION_ID + "'")
                    .contains("logging the user out")
                    .contains("code=" + errorCode));
  }

  /**
   * An IdP outage must not log out every user whose access token expires during it: the refresh
   * token may still be good, so the session survives for a retry.
   */
  @ParameterizedTest
  @ValueSource(strings = {"server_error", "temporarily_unavailable", "invalid_token_response"})
  void shouldKeepTheSessionWhenTheRefreshFailsTransiently(final String errorCode) throws Exception {
    // given
    final OAuth2AuthenticationToken authenticationToken = authenticationToken();
    givenStoredClient(authenticationToken, authorizedClient(true, true));
    when(authorizedClientManager.authorize(any()))
        .thenThrow(
            new ClientAuthorizationException(
                new OAuth2Error(errorCode), REGISTRATION_ID, "IdP is unhappy"));

    // when
    filter(authenticationToken).doFilter(request, response, chain);

    // then
    assertSessionKeptWithServiceUnavailable(authenticationToken);
    assertThat(warnings())
        .singleElement()
        .satisfies(
            message ->
                assertThat(message).contains("keeping the session").contains("code=" + errorCode));
  }

  /** How Spring's token response client reports an I/O failure (timeout, connection refused). */
  @Test
  void shouldKeepTheSessionWhenTheTokenEndpointIsUnreachable() throws Exception {
    // given
    final OAuth2AuthenticationToken authenticationToken = authenticationToken();
    givenStoredClient(authenticationToken, authorizedClient(true, true));
    when(authorizedClientManager.authorize(any()))
        .thenThrow(
            new OAuth2AuthorizationException(
                new OAuth2Error("invalid_token_response"),
                new ResourceAccessException("Connection refused")));

    // when
    filter(authenticationToken).doFilter(request, response, chain);

    // then
    assertSessionKeptWithServiceUnavailable(authenticationToken);
  }

  @Test
  void shouldLogoutWhenAuthorizedClientManagerThrowsAuthenticationException() throws Exception {
    // given
    final OAuth2AuthenticationToken authenticationToken = authenticationToken();
    givenStoredClient(authenticationToken, authorizedClient(true, true));
    when(authorizedClientManager.authorize(any()))
        .thenThrow(new OAuth2AuthenticationException(new OAuth2Error("invalid_request")));

    // when
    final OAuth2AuthenticationException thrown = runFilterExpectingLogout(authenticationToken);

    // then
    assertThat(thrown.getError().getErrorCode()).isEqualTo("refresh_token_failed");
    assertThat(thrown).hasCauseInstanceOf(OAuth2AuthenticationException.class);
    verify(logoutHandler).logout(request, response, authenticationToken);
    assertThat(warnings())
        .singleElement()
        .satisfies(message -> assertThat(message).contains("code=invalid_request"));
    assertThat(loggedDescription()).isEqualTo("OAuth2AuthenticationException: invalid_request");
  }

  /**
   * The IdP's free text never reaches the log at any level: an IdP may echo request data into
   * error_description. DEBUG carries the exception chain instead.
   */
  @Test
  void shouldNeverLogTheIdpDescription() throws Exception {
    // given
    final OAuth2AuthenticationToken authenticationToken = authenticationToken();
    givenRefreshFailingWith(authenticationToken, "Token is not active");

    // when
    runFilterExpectingLogout(authenticationToken);

    // then
    assertThat(allLogged()).noneSatisfy(m -> assertThat(m).contains("Token is not active"));
    assertThat(loggedDescription()).isEqualTo("ClientAuthorizationException: invalid_grant");
  }

  /**
   * Spring's token response client reports an I/O failure with a message built from the
   * RestClientException, which embeds the token endpoint URI — user-info included.
   */
  @Test
  void shouldNotLogTheTokenEndpointUriOfAnIoFailure() throws Exception {
    // given
    final OAuth2AuthenticationToken authenticationToken = authenticationToken();
    givenStoredClient(authenticationToken, authorizedClient(true, true));
    final var uri = "https://client:s3cret@idp.example.com/token";
    when(authorizedClientManager.authorize(any()))
        .thenThrow(
            new OAuth2AuthorizationException(
                new OAuth2Error("invalid_token_response"),
                "An error occurred while attempting to retrieve the OAuth 2.0 Access Token"
                    + " Response: I/O error on POST request for \""
                    + uri
                    + "\"",
                new ResourceAccessException(
                    "I/O error on POST request for \"" + uri + "\": Connection refused",
                    new ConnectException("Connection refused"))));

    // when
    filter(authenticationToken).doFilter(request, response, chain);

    // then
    assertThat(allLogged()).noneSatisfy(m -> assertThat(m).contains("s3cret"));
    assertThat(loggedDescription())
        .isEqualTo(
            "OAuth2AuthorizationException: invalid_token_response <- ResourceAccessException"
                + " <- ConnectException");
  }

  /** The error code is IdP-controlled too, and it is the one IdP value on the WARN line. */
  @Test
  void shouldEscapeAndBoundTheErrorCode() throws Exception {
    // given - a log-forging attempt that also far exceeds any reasonable log line length
    final OAuth2AuthenticationToken authenticationToken = authenticationToken();
    givenStoredClient(authenticationToken, authorizedClient(true, true));
    when(authorizedClientManager.authorize(any()))
        .thenThrow(
            new ClientAuthorizationException(
                new OAuth2Error(
                    "server_error\nWARN some.other.Logger -- forged"
                        + (char) 0x2028
                        + "x".repeat(400)),
                REGISTRATION_ID));

    // when
    filter(authenticationToken).doFilter(request, response, chain);

    // then
    assertThat(warnings())
        .singleElement()
        .satisfies(
            message -> {
              assertThat(message)
                  .doesNotContain("\n")
                  .doesNotContain("\u2028")
                  .contains("code=server_error\\u000aWARN")
                  .endsWith("…");
              final var code = message.substring(message.indexOf("code=") + "code=".length());
              assertThat(code).hasSize(200 + "…".length());
            });
  }

  @Test
  void shouldEscapeThePrincipalSubject() throws Exception {
    // given - a provider-controlled subject that tries to forge a log line
    final OAuth2AuthenticationToken authenticationToken =
        authenticationToken(Map.of("sub", "user-1\nWARN some.other.Logger -- forged"), "sub");
    givenRefreshFailingWith(authenticationToken, "Token is not active");

    // when
    runFilterExpectingLogout(authenticationToken);

    // then
    assertThat(warnings())
        .singleElement()
        .satisfies(
            message ->
                assertThat(message)
                    .doesNotContain("\n")
                    .contains("subject 'user-1\\u000aWARN some.other.Logger -- forged'"));
  }

  /** getName() follows user-name-attribute, which is often an email address: PII in the log. */
  @Test
  void shouldIdentifyThePrincipalBySubjectRatherThanUserName() throws Exception {
    // given
    final OAuth2AuthenticationToken authenticationToken =
        authenticationToken(Map.of("sub", "user-1", "email", "jane@example.com"), "email");
    givenRefreshFailingWith(authenticationToken, "Token is not active");

    // when
    runFilterExpectingLogout(authenticationToken);

    // then
    assertThat(warnings())
        .singleElement()
        .satisfies(
            message ->
                assertThat(message)
                    .contains("subject 'user-1'")
                    .doesNotContain("jane@example.com"));
  }

  @Test
  void shouldLogoutWhenAuthorizedClientManagerReturnsNull() throws Exception {
    // given
    final OAuth2AuthenticationToken authenticationToken = authenticationToken();
    givenStoredClient(authenticationToken, authorizedClient(true, true));
    when(authorizedClientManager.authorize(any())).thenReturn(null);

    // when
    final OAuth2AuthenticationException thrown = runFilterExpectingLogout(authenticationToken);

    // then
    assertThat(thrown.getError().getErrorCode()).isEqualTo("refresh_token_failed");
    assertThat(thrown).hasMessage("Failed to refresh access token");
    verify(logoutHandler).logout(request, response, authenticationToken);
    verify(chain, never()).doFilter(any(), any());
  }

  @Test
  void shouldLogoutWhenAuthorizedClientManagerDeclinesReauthorization() throws Exception {
    // given - the manager returns the same (already-expired) instance, meaning re-authorization
    // is not supported for this client
    final OAuth2AuthenticationToken authenticationToken = authenticationToken();
    final OAuth2AuthorizedClient authorizedClient = authorizedClient(true, true);
    givenStoredClient(authenticationToken, authorizedClient);
    when(authorizedClientManager.authorize(any())).thenReturn(authorizedClient);

    // when
    final OAuth2AuthenticationException thrown = runFilterExpectingLogout(authenticationToken);

    // then
    assertThat(thrown.getError().getErrorCode()).isEqualTo("refresh_token_failed");
    verify(logoutHandler).logout(request, response, authenticationToken);
    verify(chain, never()).doFilter(any(), any());
  }

  @Test
  void shouldLogoutWhenRefreshedClientIsStillExpired() throws Exception {
    // given - the manager hands back a genuinely new client, but its access token is already
    // expired too (e.g. a clock-skewed IdP)
    final OAuth2AuthenticationToken authenticationToken = authenticationToken();
    givenStoredClient(authenticationToken, authorizedClient(true, true));
    when(authorizedClientManager.authorize(any())).thenReturn(authorizedClient(true, true));

    // when
    final OAuth2AuthenticationException thrown = runFilterExpectingLogout(authenticationToken);

    // then
    assertThat(thrown.getError().getErrorCode()).isEqualTo("access_token_expired");
    verify(logoutHandler).logout(request, response, authenticationToken);
    verify(chain, never()).doFilter(any(), any());
  }

  @Test
  void shouldContinueFilterChainWhenRefreshSucceeds() throws Exception {
    // given - the manager successfully refreshes into a new, unexpired client
    final OAuth2AuthenticationToken authenticationToken = authenticationToken();
    givenStoredClient(authenticationToken, authorizedClient(true, true));
    when(authorizedClientManager.authorize(any())).thenReturn(authorizedClient(false, true));

    // when
    filter(authenticationToken).doFilter(request, response, chain);

    // then
    verify(chain).doFilter(request, response);
    verify(logoutHandler, never()).logout(any(), any(), any());
  }

  private void givenStoredClient(
      final OAuth2AuthenticationToken authenticationToken,
      final OAuth2AuthorizedClient authorizedClient) {
    when(authorizedClientRepository.loadAuthorizedClient(
            eq(REGISTRATION_ID), eq(authenticationToken), any()))
        .thenReturn(authorizedClient);
  }

  private void givenRefreshFailingWith(
      final OAuth2AuthenticationToken authenticationToken, final String description) {
    givenStoredClient(authenticationToken, authorizedClient(true, true));
    when(authorizedClientManager.authorize(any()))
        .thenThrow(
            new ClientAuthorizationException(
                new OAuth2Error("invalid_grant"), REGISTRATION_ID, description));
  }

  private OAuth2AuthenticationException runFilterExpectingLogout(
      final OAuth2AuthenticationToken authenticationToken) {
    final var filter = filter(authenticationToken);
    return catchThrowableOfType(
        () -> filter.doFilter(request, response, chain), OAuth2AuthenticationException.class);
  }

  private void assertSessionKeptWithServiceUnavailable(
      final OAuth2AuthenticationToken authenticationToken) throws Exception {
    assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
    assertThat(authenticationToken.isAuthenticated()).isTrue();
    verify(logoutHandler, never()).logout(any(), any(), any());
    verify(chain, never()).doFilter(any(), any());
  }

  private List<String> warnings() {
    return appender.list.stream()
        .filter(event -> event.getLevel() == Level.WARN)
        .map(ILoggingEvent::getFormattedMessage)
        .toList();
  }

  private List<String> allLogged() {
    return appender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
  }

  /** The failure description is the last argument of the DEBUG failure line. */
  private String loggedDescription() {
    return appender.list.stream()
        .filter(event -> event.getLevel() == Level.DEBUG)
        .filter(event -> event.getMessage().startsWith("Refresh token exchange failure"))
        .map(event -> String.valueOf(event.getArgumentArray()[2]))
        .findFirst()
        .orElseThrow();
  }

  private OAuth2RefreshTokenFilter filter(final SecurityContext securityContext) {
    return new OAuth2RefreshTokenFilter(
        authorizedClientRepository, authorizedClientManager, logoutHandler, () -> securityContext);
  }

  private OAuth2RefreshTokenFilter filter(final OAuth2AuthenticationToken authenticationToken) {
    return filter(new SecurityContextImpl(authenticationToken));
  }

  private static Logger filterLogger() {
    return (Logger) LoggerFactory.getLogger(OAuth2RefreshTokenFilter.class);
  }

  private static OAuth2AuthenticationToken authenticationToken() {
    return authenticationToken(Map.of("sub", "user-1"), "sub");
  }

  private static OAuth2AuthenticationToken authenticationToken(
      final Map<String, Object> attributes, final String nameAttributeKey) {
    final OAuth2User principal =
        new DefaultOAuth2User(
            List.of(new SimpleGrantedAuthority("ROLE_USER")), attributes, nameAttributeKey);
    return new OAuth2AuthenticationToken(principal, principal.getAuthorities(), REGISTRATION_ID);
  }

  private static OAuth2AuthorizedClient authorizedClient(
      final boolean expired, final boolean withRefreshToken) {
    final ClientRegistration clientRegistration =
        ClientRegistration.withRegistrationId(REGISTRATION_ID)
            .clientId("client-id")
            .clientSecret("secret")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
            .authorizationUri("https://idp.example.com/authorize")
            .tokenUri("https://idp.example.com/token")
            .build();
    final OAuth2AccessToken accessToken =
        expired
            ? new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "expired-token",
                Instant.now().minusSeconds(120),
                Instant.now().minusSeconds(60))
            : new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "valid-token",
                Instant.now(),
                Instant.now().plusSeconds(3600));
    if (!withRefreshToken) {
      return new OAuth2AuthorizedClient(clientRegistration, "user-1", accessToken);
    }
    final OAuth2RefreshToken refreshToken =
        new OAuth2RefreshToken("refresh-token", Instant.now().minusSeconds(120));
    return new OAuth2AuthorizedClient(clientRegistration, "user-1", accessToken, refreshToken);
  }
}
