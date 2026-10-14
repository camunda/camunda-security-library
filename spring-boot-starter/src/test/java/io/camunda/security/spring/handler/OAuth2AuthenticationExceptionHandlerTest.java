/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.handler;

import static io.camunda.security.spring.handler.OAuth2AuthenticationExceptionHandler.AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE;
import static io.camunda.security.spring.handler.OAuth2AuthenticationExceptionHandler.GENERIC_TITLE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.camunda.security.spring.spi.OidcLoginFailureNotice;
import io.camunda.security.spring.spi.OidcLoginFailurePort;
import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

@ExtendWith(MockitoExtension.class)
class OAuth2AuthenticationExceptionHandlerTest {

  /** The claim values an ID-token validation failure quotes; none may reach the page or the log. */
  private static final String CLAIMS_IN_DESCRIPTION =
      "Token claims organizations [{id=org-of-the-user}], expected org-of-the-cluster";

  private static final String BROWSER_ACCEPT =
      "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

  @Mock private AuthenticationFailureHandler delegate;
  @Mock private OidcLoginFailurePort loginFailurePort;

  private final MockHttpServletResponse response = new MockHttpServletResponse();
  private ListAppender<ILoggingEvent> logs;

  @BeforeEach
  void attachAppender() {
    logs = new ListAppender<>();
    logs.start();
    handlerLogger().addAppender(logs);
  }

  @AfterEach
  void detachAppender() {
    handlerLogger().detachAppender(logs);
  }

  @Test
  void shouldRecoverToTheApplicationRootUnderAContextPath() throws Exception {
    final MockHttpServletRequest request = browserRequest("/cluster-1");

    handler().onAuthenticationFailure(request, response, authorizationRequestNotFound());

    assertThat(response.getRedirectedUrl()).isEqualTo("/cluster-1/");
    verifyNoInteractions(delegate, loginFailurePort);
  }

  @Test
  void shouldRecoverToTheRootWithoutAContextPath() throws Exception {
    final MockHttpServletRequest request = browserRequest("");

    handler().onAuthenticationFailure(request, response, authorizationRequestNotFound());

    assertThat(response.getRedirectedUrl()).isEqualTo("/");
    verifyNoInteractions(delegate, loginFailurePort);
  }

  @Test
  void shouldDelegateOtherOauth2ErrorsOfNonBrowserRequests() throws Exception {
    final MockHttpServletRequest request = request("/cluster-1", "application/json");
    final AuthenticationException exception = invalidIdToken();

    handler().onAuthenticationFailure(request, response, exception);

    assertThat(response.getRedirectedUrl()).isNull();
    verify(delegate).onAuthenticationFailure(request, response, exception);
    verifyNoInteractions(loginFailurePort);
  }

  @Test
  void shouldDelegateWhenTheRequestAcceptsAnythingWithoutPreferringHtml() throws Exception {
    final MockHttpServletRequest request = request("/cluster-1", "*/*");
    final AuthenticationException exception = new BadCredentialsException("nope");

    handler().onAuthenticationFailure(request, response, exception);

    verify(delegate).onAuthenticationFailure(request, response, exception);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "application/json, text/html;q=0",
        "application/json, text/html;q=0.5",
        "text/*, text/html;q=0",
        "text/html;q=not-a-number"
      })
  void shouldDelegateWhenHtmlIsNotPreferred(final String accept) throws Exception {
    final MockHttpServletRequest request = request("/cluster-1", accept);
    final AuthenticationException exception = invalidIdToken();

    handler().onAuthenticationFailure(request, response, exception);

    verify(delegate).onAuthenticationFailure(request, response, exception);
    assertThat(response.getContentAsString()).isEmpty();
  }

  @ParameterizedTest
  @ValueSource(strings = {BROWSER_ACCEPT, "text/html", "text/*", "text/html;q=0.8, */*"})
  void shouldRenderThePageWhenHtmlIsPreferred(final String accept) throws Exception {
    handler().onAuthenticationFailure(request("/cluster-1", accept), response, invalidIdToken());

    assertThat(response.getContentType()).startsWith("text/html");
    verifyNoInteractions(delegate);
  }

  @Test
  void shouldRenderTheGenericPageForABrowserWithoutAPort() throws Exception {
    final MockHttpServletRequest request = browserRequest("/cluster-1");

    new OAuth2AuthenticationExceptionHandler(delegate, null, "/")
        .onAuthenticationFailure(request, response, invalidIdToken());

    assertThat(response.getStatus()).isEqualTo(401);
    assertThat(response.getContentType()).startsWith("text/html");
    assertThat(response.getHeader(HttpHeaders.CACHE_CONTROL)).isEqualTo("no-store");
    assertThat(response.getContentAsString())
        .contains("<h1>" + GENERIC_TITLE + "</h1>")
        .contains("We could not sign you in to this application.")
        .contains("<html lang=\"en\">")
        .contains("<a class=\"button\" href=\"/cluster-1/\">Try again</a>")
        .doesNotContain("http-equiv")
        .doesNotContain("<script");
    verifyNoInteractions(delegate);
  }

  @Test
  void shouldRenderTheGenericPageWhenThePortHasNothingToSay() throws Exception {
    when(loginFailurePort.explain(any(), any())).thenReturn(Optional.empty());

    handler().onAuthenticationFailure(browserRequest(""), response, invalidIdToken());

    assertThat(response.getStatus()).isEqualTo(401);
    assertThat(response.getContentAsString()).contains("<h1>" + GENERIC_TITLE + "</h1>");
  }

  @Test
  void shouldRenderTheHostsNoticeWithItsStatusAndLink() throws Exception {
    final AuthenticationException exception = invalidIdToken();
    final MockHttpServletRequest request = browserRequest("/cluster-1");
    when(loginFailurePort.explain(request, exception))
        .thenReturn(
            Optional.of(
                new OidcLoginFailureNotice(
                    403,
                    "No access to this cluster",
                    "This cluster belongs to another organization.",
                    new OidcLoginFailureNotice.Link(
                        "Open Console", URI.create("https://console.example.com/")))));

    handler().onAuthenticationFailure(request, response, exception);

    assertThat(response.getStatus()).isEqualTo(403);
    assertThat(response.getContentAsString())
        .contains("<title>No access to this cluster</title>")
        .contains("<p>This cluster belongs to another organization.</p>")
        .contains("<a href=\"https://console.example.com/\">Open Console</a>")
        .contains("<a class=\"button\" href=\"/cluster-1/\">Try again</a>")
        .doesNotContain(GENERIC_TITLE);
  }

  @Test
  void shouldRenderTheHostsNoticeInItsLanguage() throws Exception {
    when(loginFailurePort.explain(any(), any()))
        .thenReturn(
            Optional.of(
                new OidcLoginFailureNotice(403, "Kein Zugriff auf diesen Cluster", "Nachricht")
                    .withLanguage(Locale.forLanguageTag("de-CH"), "Erneut <versuchen>")));

    handler().onAuthenticationFailure(browserRequest("/cluster-1"), response, invalidIdToken());

    assertThat(response.getContentAsString())
        .contains("<html lang=\"de-CH\">")
        .contains("<a class=\"button\" href=\"/cluster-1/\">Erneut &lt;versuchen&gt;</a>")
        .doesNotContain("Try again");
  }

  @Test
  void shouldLinkTryAgainToTheScopedApplicationRoot() throws Exception {
    new OAuth2AuthenticationExceptionHandler(delegate, null, "/physical-tenants/t1/")
        .onAuthenticationFailure(browserRequest("/cluster-1"), response, invalidIdToken());

    assertThat(response.getContentAsString())
        .contains("<a class=\"button\" href=\"/cluster-1/physical-tenants/t1/\">Try again</a>");
  }

  @Test
  void shouldEscapeTheHostsText() throws Exception {
    when(loginFailurePort.explain(any(), any()))
        .thenReturn(
            Optional.of(
                new OidcLoginFailureNotice(
                    401,
                    "<script>alert(1)</script>",
                    "a & b <b>bold</b>",
                    new OidcLoginFailureNotice.Link(
                        "\"><img src=x>", URI.create("/path?a=1&b=2")))));

    handler().onAuthenticationFailure(browserRequest(""), response, invalidIdToken());

    assertThat(response.getContentAsString())
        .doesNotContain("<script>")
        .doesNotContain("<b>")
        .doesNotContain("<img")
        .contains("&lt;script&gt;alert(1)&lt;/script&gt;")
        .contains("a &amp; b &lt;b&gt;bold&lt;/b&gt;")
        .contains("href=\"/path?a=1&amp;b=2\"");
  }

  @Test
  void shouldNeverPutTheExceptionTextIntoThePageOrTheLog() throws Exception {
    when(loginFailurePort.explain(any(), any())).thenReturn(Optional.empty());

    handler().onAuthenticationFailure(browserRequest(""), response, invalidIdToken());

    assertThat(response.getContentAsString())
        .doesNotContain("org-of-the-user")
        .doesNotContain("org-of-the-cluster")
        .doesNotContain("invalid_id_token");
    assertThat(logs.list)
        .singleElement()
        .satisfies(
            event -> {
              assertThat(event.getLevel()).isEqualTo(Level.WARN);
              assertThat(event.getFormattedMessage())
                  .contains("/sso-callback")
                  .contains("invalid_id_token")
                  .doesNotContain("org-of-the-user")
                  .doesNotContain("org-of-the-cluster");
            });
  }

  @Test
  void shouldLogTheExceptionTypeOfANonOauth2Failure() throws Exception {
    handler()
        .onAuthenticationFailure(
            request("", "application/json"), response, new BadCredentialsException("secret"));

    assertThat(logs.list)
        .singleElement()
        .satisfies(
            event ->
                assertThat(event.getFormattedMessage())
                    .contains(BadCredentialsException.class.getName())
                    .doesNotContain("secret"));
  }

  @Test
  void shouldFallBackToTheGenericPageWhenThePortThrows() throws Exception {
    when(loginFailurePort.explain(any(), any()))
        .thenThrow(new IllegalStateException(CLAIMS_IN_DESCRIPTION));

    handler().onAuthenticationFailure(browserRequest(""), response, invalidIdToken());

    assertThat(response.getStatus()).isEqualTo(401);
    assertThat(response.getContentAsString()).contains("<h1>" + GENERIC_TITLE + "</h1>");
    assertThat(logs.list)
        .extracting(ILoggingEvent::getFormattedMessage)
        .anySatisfy(
            message ->
                assertThat(message)
                    .contains(IllegalStateException.class.getName())
                    .doesNotContain("org-of-the-user"));
  }

  @Test
  void shouldDelegateWhenTheResponseIsAlreadyCommitted() throws Exception {
    final MockHttpServletRequest request = browserRequest("");
    final AuthenticationException exception = invalidIdToken();
    response.setCommitted(true);

    handler().onAuthenticationFailure(request, response, exception);

    verify(delegate).onAuthenticationFailure(request, response, exception);
    verifyNoInteractions(loginFailurePort);
  }

  private OAuth2AuthenticationExceptionHandler handler() {
    return new OAuth2AuthenticationExceptionHandler(delegate, loginFailurePort, "/");
  }

  private static MockHttpServletRequest browserRequest(final String contextPath) {
    return request(contextPath, BROWSER_ACCEPT);
  }

  private static MockHttpServletRequest request(final String contextPath, final String accept) {
    final MockHttpServletRequest request =
        new MockHttpServletRequest("GET", contextPath + "/sso-callback");
    request.setContextPath(contextPath);
    request.addHeader(HttpHeaders.ACCEPT, accept);
    return request;
  }

  private static AuthenticationException authorizationRequestNotFound() {
    return new OAuth2AuthenticationException(
        new OAuth2Error(AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE));
  }

  /**
   * The shape Spring's OIDC login raises when a host's ID-token validator rejects the token: an
   * {@code invalid_id_token} error whose description, and the cause's errors, quote the claims.
   */
  private static AuthenticationException invalidIdToken() {
    final OAuth2Error validatorError =
        new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, CLAIMS_IN_DESCRIPTION, null);
    final OAuth2Error loginError =
        new OAuth2Error(
            "invalid_id_token",
            "An error occurred while attempting to decode the Jwt: " + CLAIMS_IN_DESCRIPTION,
            null);
    return new OAuth2AuthenticationException(
        loginError,
        loginError.toString(),
        new JwtValidationException(CLAIMS_IN_DESCRIPTION, List.of(validatorError)));
  }

  private static Logger handlerLogger() {
    return (Logger) LoggerFactory.getLogger(OAuth2AuthenticationExceptionHandler.class);
  }
}
