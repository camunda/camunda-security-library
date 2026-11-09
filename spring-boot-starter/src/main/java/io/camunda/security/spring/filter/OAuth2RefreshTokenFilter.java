/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.filter;

import io.camunda.security.spring.oidc.FailureDescription;
import io.camunda.security.spring.oidc.UrlRedaction;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Filter that transparently refreshes an expired OAuth2 access token using the stored refresh
 * token.
 *
 * <p>If the token cannot be refreshed (no refresh token available, the IdP rejects the refresh
 * token, etc.) the user is forcibly logged out and an {@link OAuth2AuthenticationException} is
 * thrown so the authentication failure handler can take over. A refresh that fails because the IdP
 * is unreachable or erroring keeps the session and answers 503 with a {@code Retry-After} header,
 * so the client can retry.
 */
public class OAuth2RefreshTokenFilter extends OncePerRequestFilter {

  private static final Logger LOG = LoggerFactory.getLogger(OAuth2RefreshTokenFilter.class);
  private static final int MAX_LOGGED_VALUE_LENGTH = 200;
  private static final String SUBJECT_CLAIM = "sub";
  private static final String RETRY_AFTER_SECONDS = "5";

  /** Spring's error code for a token endpoint response it could not read or did not accept. */
  private static final String INVALID_TOKEN_RESPONSE = "invalid_token_response";

  /** Refresh failures after which the refresh token can never succeed; see isSessionEnding. */
  private static final Set<String> SESSION_ENDING_ERROR_CODES =
      Set.of(
          OAuth2ErrorCodes.INVALID_GRANT,
          OAuth2ErrorCodes.INVALID_TOKEN,
          OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);

  private final Duration clockSkew = Duration.ofSeconds(60L);
  private final Duration doubleClockSkew = clockSkew.multipliedBy(2);
  private final OAuth2AuthorizedClientRepository authorizedClientRepository;
  private final OAuth2AuthorizedClientManager authorizedClientManager;
  private final LogoutHandler logoutHandler;
  private final Supplier<SecurityContext> securityContextSupplier;
  private final RequestMatcher skipMatcher;

  public OAuth2RefreshTokenFilter(
      final OAuth2AuthorizedClientRepository authorizedClientRepository,
      final OAuth2AuthorizedClientManager authorizedClientManager,
      final LogoutHandler logoutHandler,
      final Supplier<SecurityContext> securityContextSupplier) {
    this(
        authorizedClientRepository,
        authorizedClientManager,
        logoutHandler,
        securityContextSupplier,
        null);
  }

  /**
   * As above, with a {@code skipMatcher} naming the requests this filter must leave alone, so an
   * endpoint that answers without authentication keeps answering whatever state the caller's
   * session is in (camunda-security-library#662). A {@code null} matcher skips nothing, which is
   * what every other constructor passes.
   *
   * <p>There is deliberately no four-argument {@code (…, LogoutHandler, RequestMatcher)} overload:
   * it would make an existing {@code (…, logoutHandler, null)} call ambiguous against the {@link
   * Supplier} overload above, and so break a consumer's compile on upgrade. A caller that wants the
   * default security context passes {@code SecurityContextHolder::getContext} here.
   */
  public OAuth2RefreshTokenFilter(
      final OAuth2AuthorizedClientRepository authorizedClientRepository,
      final OAuth2AuthorizedClientManager authorizedClientManager,
      final LogoutHandler logoutHandler,
      final Supplier<SecurityContext> securityContextSupplier,
      final RequestMatcher skipMatcher) {
    this.authorizedClientRepository = authorizedClientRepository;
    this.authorizedClientManager = authorizedClientManager;
    this.logoutHandler = logoutHandler;
    this.securityContextSupplier = securityContextSupplier;
    this.skipMatcher = skipMatcher;
  }

  public OAuth2RefreshTokenFilter(
      final OAuth2AuthorizedClientRepository authorizedClientRepository,
      final OAuth2AuthorizedClientManager authorizedClientManager,
      final LogoutHandler logoutHandler) {
    this(
        authorizedClientRepository,
        authorizedClientManager,
        logoutHandler,
        SecurityContextHolder::getContext);
  }

  @Override
  protected boolean shouldNotFilter(final HttpServletRequest request) {
    return skipMatcher != null && skipMatcher.matches(request);
  }

  @Override
  protected void doFilterInternal(
      final HttpServletRequest request,
      final HttpServletResponse response,
      final FilterChain filterChain)
      throws ServletException, IOException {

    final OAuth2AuthenticationToken authenticationToken = getAuthenticationToken();

    if (authenticationToken == null) {
      LOG.debug("No OAuth2 authentication found in request");
      filterChain.doFilter(request, response);
      return;
    }

    final OAuth2AuthorizedClient authorizedClient =
        getAuthorizedClient(authenticationToken, request);
    if (authorizedClient == null) {
      logoutAndThrowAuthenticationException(
          request,
          response,
          authenticationToken,
          "unauthorized_client",
          "No client could be authorized");
    }

    if (!hasTokenExpired(authorizedClient)) {
      filterChain.doFilter(request, response);
      return;
    }

    if (!existsRefreshToken(authorizedClient)) {
      logoutAndThrowAuthenticationException(
          request,
          response,
          authenticationToken,
          "access_token_expired",
          "Access token expired, refresh token does not exist");
    }

    final OAuth2AuthorizedClient refreshedAuthorizedClient;
    try {
      refreshedAuthorizedClient =
          refreshAccessToken(authenticationToken, authorizedClient, request, response);
    } catch (final OAuth2AuthenticationException e) {
      logRefreshFailure("logging the user out", authenticationToken, e.getError(), e);
      logoutAndThrowAuthenticationException(
          request, response, authenticationToken, "refresh_token_failed", e);
      return;
    } catch (final OAuth2AuthorizationException e) {
      // A failed refresh surfaces as OAuth2AuthorizationException, not
      // OAuth2AuthenticationException; uncaught, it escapes to the container and logs as ERROR.
      if (!isSessionEnding(e)) {
        // The IdP is unreachable or failing (server_error, temporarily_unavailable, an I/O error
        // wrapped as invalid_token_response, ...). The refresh token may still be good, so keep
        // the session and let the client retry, rather than log out every user whose access
        // token expires during an outage.
        logRefreshFailure("keeping the session", authenticationToken, e.getError(), e);
        response.setHeader(HttpHeaders.RETRY_AFTER, RETRY_AFTER_SECONDS);
        response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        return;
      }
      logRefreshFailure("logging the user out", authenticationToken, e.getError(), e);
      logoutAndThrowAuthenticationException(
          request, response, authenticationToken, "refresh_token_failed", e);
      return;
    }

    if (refreshedAuthorizedClient == null) {
      logoutAndThrowAuthenticationException(
          request,
          response,
          authenticationToken,
          "refresh_token_failed",
          "Failed to refresh access token");
    }

    // Same instance returned means the manager declined to refresh — treat as failure since the
    // token is already known-expired.
    if (refreshedAuthorizedClient == authorizedClient) {
      logoutAndThrowAuthenticationException(
          request,
          response,
          authenticationToken,
          "refresh_token_failed",
          "Re-authorization is not supported or not required for the client");
    }

    if (hasTokenExpired(refreshedAuthorizedClient)) {
      logoutAndThrowAuthenticationException(
          request, response, authenticationToken, "access_token_expired", "Access token expired");
    }

    filterChain.doFilter(request, response);
  }

  protected OAuth2AuthenticationToken getAuthenticationToken() {
    final var authentication = securityContextSupplier.get().getAuthentication();
    return authentication instanceof final OAuth2AuthenticationToken oauth2AuthenticationToken
        ? oauth2AuthenticationToken
        : null;
  }

  protected OAuth2AuthorizedClient getAuthorizedClient(
      final OAuth2AuthenticationToken authenticationToken, final HttpServletRequest request) {
    final String clientRegistrationId = authenticationToken.getAuthorizedClientRegistrationId();
    return authorizedClientRepository.loadAuthorizedClient(
        clientRegistrationId, authenticationToken, request);
  }

  protected boolean hasTokenExpired(final OAuth2AuthorizedClient authorizedClient) {
    final boolean tokenExpired =
        Optional.of(authorizedClient)
            .map(OAuth2AuthorizedClient::getAccessToken)
            .map(this::isExpired)
            .orElse(false);

    if (tokenExpired) {
      LOG.debug("Token expired for {}", authorizedClient.getPrincipalName());
    }

    return tokenExpired;
  }

  protected boolean isExpired(final OAuth2AccessToken token) {
    if (token.getExpiresAt() == null) {
      return false;
    }

    if (applyClockSkewToExpirationCheck(token)) {
      return Instant.now().plus(clockSkew).isAfter(token.getExpiresAt());
    }

    return Instant.now().isAfter(token.getExpiresAt());
  }

  private boolean applyClockSkewToExpirationCheck(final OAuth2AccessToken token) {
    if (token.getIssuedAt() == null || token.getExpiresAt() == null) {
      return false;
    }

    // Skip skew when token lifetime is shorter than 2x the skew, otherwise we'd get stuck in a
    // perpetual refresh loop.
    final Duration tokenDuration =
        Duration.between(token.getIssuedAt(), token.getExpiresAt()).abs();
    return tokenDuration.minus(doubleClockSkew).isPositive();
  }

  protected boolean existsRefreshToken(final OAuth2AuthorizedClient authorizedClient) {
    return authorizedClient.getRefreshToken() != null;
  }

  protected OAuth2AuthorizedClient refreshAccessToken(
      final OAuth2AuthenticationToken authenticationToken,
      final OAuth2AuthorizedClient authorizedClient,
      final HttpServletRequest request,
      final HttpServletResponse response) {
    // The HTTP request/response are required so DefaultOAuth2AuthorizedClientManager can
    // persist the refreshed client back into the OAuth2AuthorizedClientRepository (which by
    // default writes to the HTTP session). Without these attributes the success handler runs
    // against a null request and the refreshed client is never stored.
    final OAuth2AuthorizeRequest authorizeRequest =
        OAuth2AuthorizeRequest.withAuthorizedClient(authorizedClient)
            .principal(authenticationToken)
            .attribute(HttpServletRequest.class.getName(), request)
            .attribute(HttpServletResponse.class.getName(), response)
            .build();
    return authorizedClientManager.authorize(authorizeRequest);
  }

  /**
   * Whether a refresh failure means the refresh token can never work again, so the session has to
   * end: the IdP rejected the grant itself (expired, revoked or already rotated) or no longer lets
   * this client refresh. Anything else is treated as transient.
   *
   * <p>Spring reports a token endpoint answer it can't read as {@code invalid_token_response}, the
   * same code it uses for an I/O failure. When that answer was an HTTP 4xx other than 408 or 429,
   * the IdP or a proxy in front of it rejected the request, so the session ends too. Spring keeps
   * the status only for a status other than 400. A 400 with a body that isn't an OAuth2 error, such
   * as an HTML page, loses it and is treated as transient: the user gets 503 until the session
   * expires. A compliant IdP answers a dead refresh token with {@code invalid_grant} instead.
   */
  private static boolean isSessionEnding(final OAuth2AuthorizationException e) {
    final var error = e.getError();
    if (error == null) {
      return false;
    }
    if (SESSION_ENDING_ERROR_CODES.contains(error.getErrorCode())) {
      return true;
    }
    return INVALID_TOKEN_RESPONSE.equals(error.getErrorCode()) && isRejectedByTokenEndpoint(e);
  }

  /** Whether the token endpoint answered with a 4xx that a retry can't fix (not 408 or 429). */
  private static boolean isRejectedByTokenEndpoint(final Throwable e) {
    for (Throwable cause = e.getCause(); cause != null; cause = cause.getCause()) {
      if (cause instanceof final RestClientResponseException response) {
        final var status = response.getStatusCode();
        return status.is4xxClientError()
            && status.value() != HttpStatus.REQUEST_TIMEOUT.value()
            && status.value() != HttpStatus.TOO_MANY_REQUESTS.value();
      }
    }
    return false;
  }

  /**
   * Logs the error code (stable and diagnostic) at WARN, and the exception chain at DEBUG through
   * {@link FailureDescription}. Never the exception message: Spring builds it from the IdP's {@code
   * error_description} or from a {@code RestClientException} that embeds the token endpoint URI,
   * user-info included, so it can carry credentials or echoed request data. Every logged value is
   * IdP-controlled, so each is escaped and bounded. The principal is identified by its {@code sub}
   * claim rather than {@link OAuth2AuthenticationToken#getName()}, which follows {@code
   * user-name-attribute} and is often an email address.
   */
  private static void logRefreshFailure(
      final String outcome,
      final OAuth2AuthenticationToken authenticationToken,
      final OAuth2Error error,
      final RuntimeException e) {
    final var subject = forLog(authenticationToken.getPrincipal().getAttribute(SUBJECT_CLAIM));
    final var registrationId = forLog(authenticationToken.getAuthorizedClientRegistrationId());
    final var errorCode = forLog(error == null ? null : error.getErrorCode());
    LOG.warn(
        "Refresh token exchange failed for subject '{}' on registration '{}', {}: code={}",
        subject,
        registrationId,
        outcome,
        errorCode);
    LOG.debug(
        "Refresh token exchange failure for subject '{}' on registration '{}': {}",
        subject,
        registrationId,
        forLog(FailureDescription.describe(e)));
  }

  private static String forLog(final Object value) {
    return value == null
        ? "n/a"
        : UrlRedaction.escapeControlCharacters(value.toString(), MAX_LOGGED_VALUE_LENGTH);
  }

  private void logoutAndThrowAuthenticationException(
      final HttpServletRequest request,
      final HttpServletResponse response,
      final OAuth2AuthenticationToken authenticationToken,
      final String reasonCode,
      final String reasonMessage) {
    forceLogout(authenticationToken, request, response);
    throw new OAuth2AuthenticationException(new OAuth2Error(reasonCode), reasonMessage);
  }

  private void logoutAndThrowAuthenticationException(
      final HttpServletRequest request,
      final HttpServletResponse response,
      final OAuth2AuthenticationToken authenticationToken,
      final String reasonCode,
      final Throwable e) {
    forceLogout(authenticationToken, request, response);
    throw new OAuth2AuthenticationException(new OAuth2Error(reasonCode), e);
  }

  private void forceLogout(
      final OAuth2AuthenticationToken authenticationToken,
      final HttpServletRequest request,
      final HttpServletResponse response) {
    authenticationToken.setAuthenticated(false);
    logoutHandler.logout(request, response, authenticationToken);
  }
}
