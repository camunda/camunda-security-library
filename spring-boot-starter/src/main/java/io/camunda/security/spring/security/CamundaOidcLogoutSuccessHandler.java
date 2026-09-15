/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * {@link OidcClientInitiatedLogoutSuccessHandler} customization that:
 *
 * <ul>
 *   <li>Stores a validated {@code Referer} header as the post-logout redirect URI under {@link
 *       #POST_LOGOUT_REDIRECT_ATTRIBUTE}, so the host application can navigate back to the
 *       originating page after IdP logout.
 *   <li>Propagates the OIDC user claim {@code login_hint} as a {@code logout_hint} query parameter
 *       to the provider's end-session endpoint when available, so the IdP can terminate the right
 *       session for users with multiple active identities.
 *   <li>Resolves the {@code post_logout_redirect_uri} per client registration, so each IdP in a
 *       multi-provider deployment can carry its own landing URL or send none at all (ADR-0024).
 * </ul>
 *
 * <p>The post-logout redirect URL is only accepted when it points back to the same application
 * (same-origin check).
 *
 * <p>CSL configures {@code post_logout_redirect_uri} per registration through the constructor; the
 * inherited {@link OidcClientInitiatedLogoutSuccessHandler#setPostLogoutRedirectUri} is not used.
 */
public final class CamundaOidcLogoutSuccessHandler extends OidcClientInitiatedLogoutSuccessHandler {

  /**
   * Session attribute under which the validated, same-origin {@code Referer} is stored as the
   * post-logout redirect URI. Hosts that render a post-logout page read this attribute via the
   * constant to keep the contract stable.
   */
  public static final String POST_LOGOUT_REDIRECT_ATTRIBUTE = "postLogoutRedirect";

  /**
   * Session attribute used to surface a human-readable explanation when RP-initiated logout cannot
   * reach the IdP (for example, no {@code end_session_endpoint} was published). Stored on the
   * session — not the request — so the message survives the redirect that the {@link
   * org.springframework.security.web.authentication.logout.LogoutSuccessHandler
   * LogoutSuccessHandler} issues and is readable by the post-logout page on the subsequent request.
   */
  public static final String REDIRECT_MESSAGE_ATTRIBUTE = "redirectMessage";

  private static final Logger LOG = LoggerFactory.getLogger(CamundaOidcLogoutSuccessHandler.class);

  private static final String END_SESSION_UNAVAILABLE_MESSAGE =
      "The identity provider's end_session_endpoint is not available. "
          + "The local session has been terminated, but the IdP session will still be active.";

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  private static final String SEC_FETCH_DEST_HEADER = "Sec-Fetch-Dest";

  /** The {@code Sec-Fetch-Dest} value browsers send for {@code fetch()}/XHR requests. */
  private static final String SEC_FETCH_DEST_EMPTY = "empty";

  private final ClientRegistrationRepository clientRegistrationRepository;

  /**
   * The resolved configuration this handler was built from: the {@code post_logout_redirect_uri}
   * template per registrationId, where {@code ""} means "send none for this registration".
   *
   * <p>Supplied by {@link ScopedWebappSecurityChainBuilder}, which derives it from the same
   * registrationId-keyed map the chain's {@link ClientRegistrationRepository} is built from, so the
   * keys line up by construction. It is total over the scope's registrations: an explicit {@code
   * ""} (the redirect was configured off) and an absent key (no such registration in this chain)
   * are different statements, even though both send no parameter.
   *
   * <p>Dispatch uses {@link #delegatesByRegistrationId}, derived from this at construction. This
   * map is kept as the handler's record of what the chain resolved — it is what the chain's tests
   * assert against, and the one place the suppressed registrations remain visible.
   */
  private final Map<String, String> postLogoutRedirectUriByRegistrationId;

  /**
   * One delegate per registration that actually sends a {@code post_logout_redirect_uri}, built
   * eagerly because the registration set is fixed at construction and a delegate is a two-field
   * object.
   *
   * <p>Spring's {@code postLogoutRedirectUri} is a private, single-valued field and every helper
   * that reads it is private too, so the only way to send a different value per registration is to
   * hold a separate {@link OidcClientInitiatedLogoutSuccessHandler} per value. Mutating one shared
   * handler's field per request would be the obvious alternative and is a data race: two concurrent
   * logouts would hand each other's redirect URI to the wrong IdP.
   *
   * <p>Holds only the registrations with a non-empty template, so a registrationId absent here
   * sends no {@code post_logout_redirect_uri} — covering a disabled registration, a host that
   * declares no route, and an unknown registrationId under one rule.
   */
  private final Map<String, RegistrationScopedHandler> delegatesByRegistrationId;

  public CamundaOidcLogoutSuccessHandler(
      final ClientRegistrationRepository clientRegistrationRepository,
      final Map<String, String> postLogoutRedirectUriByRegistrationId) {
    super(clientRegistrationRepository);
    this.clientRegistrationRepository = clientRegistrationRepository;
    this.postLogoutRedirectUriByRegistrationId =
        Map.copyOf(
            Objects.requireNonNull(
                postLogoutRedirectUriByRegistrationId,
                "postLogoutRedirectUriByRegistrationId must not be null; pass an empty map to send"
                    + " no post_logout_redirect_uri"));
    final Map<String, RegistrationScopedHandler> delegates = new LinkedHashMap<>();
    this.postLogoutRedirectUriByRegistrationId.forEach(
        (registrationId, redirectUri) -> {
          if (!redirectUri.isEmpty()) {
            // The delegate must share this handler's repository: the two have to agree on whether a
            // registration publishes an end_session_endpoint, or the fall-through below misfires.
            final var delegate = new RegistrationScopedHandler(clientRegistrationRepository);
            delegate.setPostLogoutRedirectUri(redirectUri);
            delegates.put(registrationId, delegate);
          }
        });
    delegatesByRegistrationId = Map.copyOf(delegates);
  }

  /**
   * Handles logout success differently depending on how the client called {@code /logout}:
   *
   * <ul>
   *   <li>Full-page navigations (no {@code Sec-Fetch-Dest: empty}, no JSON {@code Accept}) delegate
   *       to {@link OidcClientInitiatedLogoutSuccessHandler#onLogoutSuccess} and keep the standard
   *       302 redirect to the IdP's {@code end_session_endpoint}.
   *   <li>Fetch/XHR calls (as issued by the Orchestration Cluster webapps) instead receive a 2xx
   *       response they can act on: 200 with a JSON body {@code {"url": "<end-session-url>"}} when
   *       an end-session URL is available, or 204 with no body when it is not. A 302 cannot drive a
   *       cross-origin top-level navigation from a fetch call, so the frontend needs the URL back
   *       to navigate itself.
   * </ul>
   */
  @Override
  public void onLogoutSuccess(
      final HttpServletRequest request,
      final HttpServletResponse response,
      final Authentication authentication)
      throws IOException, ServletException {
    if (!isFetchRequest(request)) {
      super.onLogoutSuccess(request, response, authentication);
      return;
    }

    final String targetUrl = determineTargetUrl(request, response, authentication);
    if (Objects.equals(targetUrl, getDefaultTargetUrl())) {
      LOG.trace("No end-session URL available for fetch-based logout. Responding with 204.");
      response.setStatus(HttpServletResponse.SC_NO_CONTENT);
      return;
    }

    LOG.trace("Responding to fetch-based logout with 200 and an end-session URL.");
    response.setStatus(HttpServletResponse.SC_OK);
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    response.setCharacterEncoding(StandardCharsets.UTF_8.name());
    OBJECT_MAPPER.writeValue(response.getWriter(), Map.of("url", targetUrl));
  }

  /**
   * Detects fetch/XHR calls as opposed to full-page (top-level) navigations.
   *
   * <p>Primary signal is the {@code Sec-Fetch-Dest} header: browsers set it to {@code empty} for
   * {@code fetch()}/XHR requests and to other values (e.g. {@code document}, {@code iframe}, {@code
   * frame}, or subresource dests like {@code image}/{@code script}) for anything else. Only {@code
   * empty} is treated as fetch. When the header is absent (older browsers, some HTTP clients),
   * falls back to checking whether {@code Accept} contains {@code application/json}.
   */
  private static boolean isFetchRequest(final HttpServletRequest request) {
    final String secFetchDest = request.getHeader(SEC_FETCH_DEST_HEADER);
    if (secFetchDest != null && !secFetchDest.isBlank()) {
      return SEC_FETCH_DEST_EMPTY.equalsIgnoreCase(secFetchDest);
    }
    final String accept = request.getHeader(HttpHeaders.ACCEPT);
    return accept != null
        && accept.toLowerCase(Locale.ROOT).contains(MediaType.APPLICATION_JSON_VALUE);
  }

  @Override
  protected String determineTargetUrl(
      final HttpServletRequest request,
      final HttpServletResponse response,
      final Authentication authentication) {

    final String referer = request.getHeader(HttpHeaders.REFERER);
    if (isSameOriginRedirect(request, referer)) {
      request.getSession().setAttribute(POST_LOGOUT_REDIRECT_ATTRIBUTE, referer);
    }

    final String baseLogoutUrl = endSessionUrlForRegistration(request, response, authentication);

    // Validate the auth context first. Spring's super.determineTargetUrl returns
    // getDefaultTargetUrl() for ANY non-OIDC authentication context (non-OAuth2, non-OidcUser, or
    // unknown registration), not just for a missing end_session_endpoint — so the end-session
    // diagnostic must only fire once we know we're looking at a valid OIDC session.
    if (!(authentication instanceof final OAuth2AuthenticationToken oauth)) {
      LOG.trace(
          "Authentication is not of type OAuth2AuthenticationToken: '{}'. "
              + "Falling back to '{}' without logout hint.",
          authentication,
          baseLogoutUrl);
      return baseLogoutUrl;
    }

    final String registrationId = oauth.getAuthorizedClientRegistrationId();
    final ClientRegistration clientRegistration =
        clientRegistrationRepository.findByRegistrationId(registrationId);

    if (clientRegistration == null) {
      LOG.trace(
          "No client registration found for id '{}'. Falling back to '{}' without logout hint.",
          registrationId,
          baseLogoutUrl);
      return baseLogoutUrl;
    }

    if (!(oauth.getPrincipal() instanceof final OidcUser oidcUser)) {
      LOG.trace(
          "Principal is not of type OidcUser: '{}'. Falling back to '{}' without logout hint.",
          oauth.getPrincipal(),
          baseLogoutUrl);
      return baseLogoutUrl;
    }

    // With a confirmed OIDC session in hand, an equality with getDefaultTargetUrl() can be
    // attributed to the IdP not publishing end_session_endpoint in its discovery metadata.
    if (Objects.equals(baseLogoutUrl, getDefaultTargetUrl())) {
      LOG.trace(
          "Unable to determine end-session endpoint for OIDC logout. "
              + "The local session has been terminated, but the IdP session will still be active. "
              + "Falling back to '{}' without logout hint.",
          baseLogoutUrl);
      request
          .getSession()
          .setAttribute(REDIRECT_MESSAGE_ATTRIBUTE, END_SESSION_UNAVAILABLE_MESSAGE);
      return baseLogoutUrl;
    }

    final String logoutHint = oidcUser.getClaim("login_hint");
    if (logoutHint == null) {
      LOG.trace(
          "No 'login_hint' claim found in OIDC user. Falling back to '{}' without logout hint.",
          baseLogoutUrl);
      return baseLogoutUrl;
    }

    return UriComponentsBuilder.fromUriString(baseLogoutUrl)
        .queryParam("logout_hint", logoutHint)
        .build()
        .toUriString();
  }

  /**
   * The IdP end-session URL for the registration this user authenticated with.
   *
   * <p>Delegates when the registration has a {@code post_logout_redirect_uri} of its own, and falls
   * back to {@code super} — this handler's own, exactly the call made before the parameter became
   * per-registration — for every other case: no configured URI, an unknown registrationId, a
   * non-OIDC authentication, or a delegate that found no {@code end_session_endpoint}.
   *
   * <p>That fall-through is load-bearing, not tidiness. {@link #determineTargetUrl} and {@link
   * #onLogoutSuccess} both detect "the IdP published no {@code end_session_endpoint}" by comparing
   * the result against this handler's {@link #getDefaultTargetUrl()}, and every handler carries its
   * own copy of that field (plus {@code useReferer} and {@code targetUrlParameter}, which the same
   * Spring fall-through consults). Letting a delegate's default reach that comparison would make
   * the sentinel depend on two objects agreeing; routing it back through {@code super} keeps it an
   * identity on one. Getting this wrong is silent: a fetch-based logout would answer {@code 200
   * {"url": "/"}} instead of {@code 204}, and the webapp would navigate to {@code /} believing it
   * was the IdP's end-session URL.
   */
  private String endSessionUrlForRegistration(
      final HttpServletRequest request,
      final HttpServletResponse response,
      final Authentication authentication) {
    if (authentication instanceof final OAuth2AuthenticationToken oauth) {
      final var delegate = delegatesByRegistrationId.get(oauth.getAuthorizedClientRegistrationId());
      if (delegate != null) {
        final var endSessionUrl = delegate.endSessionUrl(request, response, authentication);
        if (endSessionUrl != null) {
          return endSessionUrl;
        }
      }
    }
    return super.determineTargetUrl(request, response, authentication);
  }

  /**
   * Same-origin check for the post-logout redirect URI. The redirect is only honoured when its
   * scheme, host, and effective port (default ports normalised) match those of the request that
   * triggered logout. Header-injection attempts (CR/LF), blank values, and non-absolute or
   * unparseable URLs are rejected.
   *
   * <p>Explicit scheme/host/port comparison is used rather than a prefix check on the base URL — a
   * {@code startsWith}-style check is vulnerable to host-confusion bypasses such as {@code
   * https://app.example.com.evil.com/} and {@code https://app.example.com@evil.com/}.
   */
  private static boolean isSameOriginRedirect(final HttpServletRequest request, final String url) {
    if (url == null || url.isBlank() || url.indexOf('\r') >= 0 || url.indexOf('\n') >= 0) {
      return false;
    }
    final URI candidate;
    final URI requestUri;
    try {
      candidate = new URI(url);
      requestUri = new URI(UrlUtils.buildFullRequestUrl(request));
    } catch (final URISyntaxException ignored) {
      return false;
    }
    if (!candidate.isAbsolute() || candidate.getHost() == null) {
      return false;
    }
    // URI scheme (RFC 3986 §3.1) and DNS host names are case-insensitive — compare with
    // equalsIgnoreCase so a referer like HTTPS://Camunda.com/ is not wrongly rejected.
    return equalsIgnoreCase(candidate.getScheme(), requestUri.getScheme())
        && equalsIgnoreCase(candidate.getHost(), requestUri.getHost())
        && effectivePort(candidate) == effectivePort(requestUri);
  }

  private static boolean equalsIgnoreCase(final String a, final String b) {
    return a == null ? b == null : a.equalsIgnoreCase(b);
  }

  private static int effectivePort(final URI uri) {
    if (uri.getPort() != -1) {
      return uri.getPort();
    }
    final String scheme = uri.getScheme();
    if ("http".equalsIgnoreCase(scheme)) {
      return 80;
    }
    if ("https".equalsIgnoreCase(scheme)) {
      return 443;
    }
    return -1;
  }

  /**
   * Carries one registration's {@code post_logout_redirect_uri}.
   *
   * <p>Reached through a {@code private} method rather than by calling the {@code protected} {@link
   * OidcClientInitiatedLogoutSuccessHandler#determineTargetUrl} on it: JLS 6.6.2.1 only permits a
   * protected access on an expression whose type is the accessing class or a subclass of it, and
   * this nested class is a sibling of {@link CamundaOidcLogoutSuccessHandler}, not a subclass — so
   * that call would not compile. A private member of a nested class, by contrast, is accessible
   * anywhere in the enclosing top-level class (nestmates, JEP 181).
   *
   * <p>Nothing may call {@code setDefaultTargetUrl}, {@code setUseReferer} or {@code
   * setTargetUrlParameter} on an instance: the {@code null} return below is only a reliable "no
   * end-session endpoint" signal while the inherited fall-through stays at its untouched default.
   */
  private static final class RegistrationScopedHandler
      extends OidcClientInitiatedLogoutSuccessHandler {

    private RegistrationScopedHandler(final ClientRegistrationRepository repository) {
      super(repository);
    }

    /** The IdP end-session URL, or {@code null} when Spring fell through to its default target. */
    private String endSessionUrl(
        final HttpServletRequest request,
        final HttpServletResponse response,
        final Authentication authentication) {
      final var targetUrl = determineTargetUrl(request, response, authentication);
      return Objects.equals(targetUrl, getDefaultTargetUrl()) ? null : targetUrl;
    }
  }
}
