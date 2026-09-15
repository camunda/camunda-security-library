/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static io.camunda.security.spring.security.CamundaOidcLogoutSuccessHandler.POST_LOGOUT_REDIRECT_ATTRIBUTE;
import static io.camunda.security.spring.security.CamundaOidcLogoutSuccessHandler.REDIRECT_MESSAGE_ATTRIBUTE;
import static java.time.Instant.now;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

@ExtendWith(MockitoExtension.class)
class CamundaOidcLogoutSuccessHandlerTest {

  private static final String REGISTRATION_ID = "client";
  private static final String SECONDARY_REGISTRATION_ID = "client-secondary";
  private static final String ABSOLUTE_POST_LOGOUT_URI = "https://accounts.example.com/logged-out";
  private static final String SAME_ORIGIN_REFERER = "https://camunda.com/component/ui/page";
  private static final String CROSS_ORIGIN_REFERER = "https://other.com/component/ui/page";

  @Mock private ClientRegistrationRepository clientRegistrationRepository;

  private CamundaOidcLogoutSuccessHandler handler;

  @BeforeEach
  void setUp() {
    handler = new CamundaOidcLogoutSuccessHandler(clientRegistrationRepository, Map.of());
  }

  @Test
  void sameOriginRefererIsStoredOnSession() {
    final MockHttpServletRequest request = requestWithReferer(SAME_ORIGIN_REFERER);
    final HttpSession session = request.getSession(true);
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration());

    handler.determineTargetUrl(request, new MockHttpServletResponse(), oidcAuthentication(null));

    assertThat(session.getAttribute(POST_LOGOUT_REDIRECT_ATTRIBUTE)).isEqualTo(SAME_ORIGIN_REFERER);
  }

  @Test
  void crossOriginRefererIsNotStoredOnSession() {
    final MockHttpServletRequest request = requestWithReferer(CROSS_ORIGIN_REFERER);
    final HttpSession session = request.getSession(true);
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration());

    handler.determineTargetUrl(request, new MockHttpServletResponse(), oidcAuthentication(null));

    assertThat(session.getAttribute(POST_LOGOUT_REDIRECT_ATTRIBUTE)).isNull();
  }

  @Test
  void loginHintIsPropagatedAsLogoutHint() {
    final MockHttpServletRequest request = requestWithReferer(SAME_ORIGIN_REFERER);
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration());

    final String targetUrl =
        handler.determineTargetUrl(
            request, new MockHttpServletResponse(), oidcAuthentication("user@camunda.com"));

    assertThat(targetUrl).contains("logout_hint=user@camunda.com");
  }

  @Test
  void missingLoginHintProducesNoLogoutHintParam() {
    final MockHttpServletRequest request = requestWithReferer(SAME_ORIGIN_REFERER);
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration());

    final String targetUrl =
        handler.determineTargetUrl(
            request, new MockHttpServletResponse(), oidcAuthentication(null));

    assertThat(targetUrl).doesNotContain("logout_hint");
  }

  @Test
  void missingEndSessionEndpointStoresRedirectMessageOnSession() {
    final MockHttpServletRequest request = requestWithReferer(SAME_ORIGIN_REFERER);
    final HttpSession session = request.getSession(true);
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistrationWithoutEndSessionEndpoint());

    handler.determineTargetUrl(
        request, new MockHttpServletResponse(), oidcAuthentication("user@camunda.com"));

    assertThat(session.getAttribute(REDIRECT_MESSAGE_ATTRIBUTE))
        .asInstanceOf(InstanceOfAssertFactories.STRING)
        .contains("end_session_endpoint");
  }

  @Test
  void caseInsensitiveSameOriginRefererIsStoredOnSession() {
    final MockHttpServletRequest request =
        requestWithReferer("HTTPS://CAMUNDA.com/component/ui/page");
    final HttpSession session = request.getSession(true);
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration());

    handler.determineTargetUrl(request, new MockHttpServletResponse(), oidcAuthentication(null));

    assertThat(session.getAttribute(POST_LOGOUT_REDIRECT_ATTRIBUTE))
        .isEqualTo("HTTPS://CAMUNDA.com/component/ui/page");
  }

  @Test
  void hostConfusionPrefixedRefererIsNotStoredOnSession() {
    final MockHttpServletRequest request =
        requestWithReferer("https://camunda.com.evil.com/component/ui/page");
    final HttpSession session = request.getSession(true);
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration());

    handler.determineTargetUrl(request, new MockHttpServletResponse(), oidcAuthentication(null));

    assertThat(session.getAttribute(POST_LOGOUT_REDIRECT_ATTRIBUTE)).isNull();
  }

  @Test
  void userInfoBypassRefererIsNotStoredOnSession() {
    final MockHttpServletRequest request =
        requestWithReferer("https://camunda.com@evil.com/component/ui/page");
    final HttpSession session = request.getSession(true);
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration());

    handler.determineTargetUrl(request, new MockHttpServletResponse(), oidcAuthentication(null));

    assertThat(session.getAttribute(POST_LOGOUT_REDIRECT_ATTRIBUTE)).isNull();
  }

  @Test
  void mismatchedPortRefererIsNotStoredOnSession() {
    final MockHttpServletRequest request =
        requestWithReferer("https://camunda.com:8443/component/ui/page");
    final HttpSession session = request.getSession(true);
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration());

    handler.determineTargetUrl(request, new MockHttpServletResponse(), oidcAuthentication(null));

    assertThat(session.getAttribute(POST_LOGOUT_REDIRECT_ATTRIBUTE)).isNull();
  }

  @Test
  void explicitDefaultPortRefererIsAcceptedAsSameOrigin() {
    final MockHttpServletRequest request =
        requestWithReferer("https://camunda.com:443/component/ui/page");
    final HttpSession session = request.getSession(true);
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration());

    handler.determineTargetUrl(request, new MockHttpServletResponse(), oidcAuthentication(null));

    assertThat(session.getAttribute(POST_LOGOUT_REDIRECT_ATTRIBUTE))
        .isEqualTo("https://camunda.com:443/component/ui/page");
  }

  @Test
  void carriageReturnInjectedRefererIsNotStoredOnSession() {
    final MockHttpServletRequest request =
        requestWithReferer("https://camunda.com/component\r\nSet-Cookie: x=y");
    final HttpSession session = request.getSession(true);
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration());

    handler.determineTargetUrl(request, new MockHttpServletResponse(), oidcAuthentication(null));

    assertThat(session.getAttribute(POST_LOGOUT_REDIRECT_ATTRIBUTE)).isNull();
  }

  @Test
  void relativeRefererIsNotStoredOnSession() {
    final MockHttpServletRequest request = requestWithReferer("/component/ui/page");
    final HttpSession session = request.getSession(true);
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration());

    handler.determineTargetUrl(request, new MockHttpServletResponse(), oidcAuthentication(null));

    assertThat(session.getAttribute(POST_LOGOUT_REDIRECT_ATTRIBUTE)).isNull();
  }

  @Test
  void unparseableRefererIsNotStoredOnSession() {
    final MockHttpServletRequest request =
        requestWithReferer("https://camunda.com/path with space");
    final HttpSession session = request.getSession(true);
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration());

    handler.determineTargetUrl(request, new MockHttpServletResponse(), oidcAuthentication(null));

    assertThat(session.getAttribute(POST_LOGOUT_REDIRECT_ATTRIBUTE)).isNull();
  }

  @Test
  void nonOAuth2AuthenticationFallsBackWithoutLogoutHint() {
    final MockHttpServletRequest request = requestWithReferer(SAME_ORIGIN_REFERER);
    final Authentication authentication =
        new UsernamePasswordAuthenticationToken("user", "password");

    final String targetUrl =
        handler.determineTargetUrl(request, new MockHttpServletResponse(), authentication);

    assertThat(targetUrl).doesNotContain("logout_hint");
  }

  @Test
  void nonOidcUserPrincipalFallsBackWithoutLogoutHint() {
    final MockHttpServletRequest request = requestWithReferer(SAME_ORIGIN_REFERER);

    final String targetUrl =
        handler.determineTargetUrl(
            request, new MockHttpServletResponse(), plainOAuth2Authentication());

    assertThat(targetUrl).doesNotContain("logout_hint");
  }

  @Test
  void unknownRegistrationIdFallsBackWithoutLogoutHint() {
    final MockHttpServletRequest request = requestWithReferer(SAME_ORIGIN_REFERER);
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID)).thenReturn(null);

    final String targetUrl =
        handler.determineTargetUrl(
            request, new MockHttpServletResponse(), oidcAuthentication("user@camunda.com"));

    assertThat(targetUrl).doesNotContain("logout_hint");
  }

  private static MockHttpServletRequest requestWithReferer(final String referer) {
    final MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader("referer", referer);
    request.setScheme("https");
    request.setServerName("camunda.com");
    request.setServerPort(443);
    request.setContextPath("/component");
    request.setRequestURI("/component/some/path");
    return request;
  }

  private static MockHttpServletRequest fetchRequestWithReferer(final String referer) {
    final MockHttpServletRequest request = requestWithReferer(referer);
    request.addHeader("Sec-Fetch-Dest", "empty");
    return request;
  }

  @Test
  void fetchLogoutWithEndSessionReturnsJsonBodyWithUrl() throws IOException, ServletException {
    final MockHttpServletRequest request = fetchRequestWithReferer(SAME_ORIGIN_REFERER);
    final MockHttpServletResponse response = new MockHttpServletResponse();
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration());

    handler.onLogoutSuccess(request, response, oidcAuthentication("user@camunda.com"));

    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentType()).contains(MediaType.APPLICATION_JSON_VALUE);

    final JsonNode body = new ObjectMapper().readTree(response.getContentAsString());
    final MultiValueMap<String, String> query =
        queryParams(body.get("url").asText(), "idp.com", "/logout");
    assertThat(query.getFirst("id_token_hint")).isNotBlank();
    assertThat(
            URLDecoder.decode(
                Objects.requireNonNull(query.getFirst("logout_hint")), StandardCharsets.UTF_8))
        .isEqualTo("user@camunda.com");
  }

  @Test
  void fetchLogoutWithoutEndSessionReturnsNoContent() throws IOException, ServletException {
    final MockHttpServletRequest request = fetchRequestWithReferer(SAME_ORIGIN_REFERER);
    final MockHttpServletResponse response = new MockHttpServletResponse();
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistrationWithoutEndSessionEndpoint());

    handler.onLogoutSuccess(request, response, oidcAuthentication("user@camunda.com"));

    assertThat(response.getStatus()).isEqualTo(204);
    assertThat(response.getContentAsString()).isEmpty();
  }

  @Test
  void nonFetchLogoutWithEndSessionEmitsRedirect() throws IOException, ServletException {
    final MockHttpServletRequest request = requestWithReferer(SAME_ORIGIN_REFERER);
    request.addHeader("Accept", "text/html");
    final MockHttpServletResponse response = new MockHttpServletResponse();
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration());

    handler.onLogoutSuccess(request, response, oidcAuthentication("user@camunda.com"));

    assertThat(response.getStatus()).isEqualTo(302);
    final MultiValueMap<String, String> query =
        queryParams(response.getRedirectedUrl(), "idp.com", "/logout");
    assertThat(query.getFirst("id_token_hint")).isNotBlank();
  }

  @Test
  void fetchLogoutWithJsonAcceptFallbackReturnsJsonBodyWithUrl()
      throws IOException, ServletException {
    final MockHttpServletRequest request = requestWithReferer(SAME_ORIGIN_REFERER);
    request.addHeader("Accept", "application/json");
    final MockHttpServletResponse response = new MockHttpServletResponse();
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration());

    handler.onLogoutSuccess(request, response, oidcAuthentication("user@camunda.com"));

    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentType()).contains(MediaType.APPLICATION_JSON_VALUE);

    final JsonNode body = new ObjectMapper().readTree(response.getContentAsString());
    final MultiValueMap<String, String> query =
        queryParams(body.get("url").asText(), "idp.com", "/logout");
    assertThat(query.getFirst("id_token_hint")).isNotBlank();
    assertThat(
            URLDecoder.decode(
                Objects.requireNonNull(query.getFirst("logout_hint")), StandardCharsets.UTF_8))
        .isEqualTo("user@camunda.com");
  }

  @Test
  void subresourceSecFetchDestIsNotTreatedAsFetch() throws IOException, ServletException {
    final MockHttpServletRequest request = requestWithReferer(SAME_ORIGIN_REFERER);
    request.addHeader("Sec-Fetch-Dest", "image");
    final MockHttpServletResponse response = new MockHttpServletResponse();
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration());

    handler.onLogoutSuccess(request, response, oidcAuthentication("user@camunda.com"));

    assertThat(response.getStatus()).isEqualTo(302);
    assertThat(response.getRedirectedUrl()).contains("https://idp.com/logout");
  }

  /** A scoped chain's {@code post_logout_redirect_uri} resolves under the scope's base path. */
  @Test
  void scopedPostLogoutRedirectUriResolvesUnderScopeBasePath() {
    final var scopedHandler =
        handlerWithRedirectUris(
            Map.of(
                REGISTRATION_ID,
                ScopedWebappSecurityChainBuilder.postLogoutRedirectUri(
                    "/physical-tenants/t1", Optional.of("/post-logout"))));
    final MockHttpServletRequest request = requestWithReferer(SAME_ORIGIN_REFERER);
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration());

    final String targetUrl =
        scopedHandler.determineTargetUrl(
            request, new MockHttpServletResponse(), oidcAuthentication(null));

    assertThat(postLogoutRedirectUriOf(targetUrl))
        .isEqualTo("https://camunda.com/component/physical-tenants/t1/post-logout");
  }

  /**
   * An absolute configured value reaches the IdP untouched — no {@code {baseUrl}} expansion, and
   * notably no chain base path, which is what makes it registerable at an OP that matches the
   * parameter exactly.
   */
  @Test
  void configuredAbsoluteUriIsSentVerbatim() {
    final var configuredHandler =
        handlerWithRedirectUris(Map.of(REGISTRATION_ID, ABSOLUTE_POST_LOGOUT_URI));
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration());

    final String targetUrl =
        configuredHandler.determineTargetUrl(
            requestWithReferer(SAME_ORIGIN_REFERER),
            new MockHttpServletResponse(),
            oidcAuthentication(null));

    assertThat(postLogoutRedirectUriOf(targetUrl)).isEqualTo(ABSOLUTE_POST_LOGOUT_URI);
  }

  /**
   * The behaviour this whole change exists for: two IdPs in one chain, each told to send the
   * browser somewhere different. Before ADR-0024 one handler served the chain, so both got whatever
   * the last-written template said.
   */
  @Test
  void eachRegistrationReceivesItsOwnPostLogoutRedirectUri() {
    final var multiIdpHandler =
        handlerWithRedirectUris(
            Map.of(
                REGISTRATION_ID,
                ABSOLUTE_POST_LOGOUT_URI,
                SECONDARY_REGISTRATION_ID,
                "{baseUrl}/post-logout"));
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration());
    when(clientRegistrationRepository.findByRegistrationId(SECONDARY_REGISTRATION_ID))
        .thenReturn(clientRegistration(SECONDARY_REGISTRATION_ID));

    final String first =
        multiIdpHandler.determineTargetUrl(
            requestWithReferer(SAME_ORIGIN_REFERER),
            new MockHttpServletResponse(),
            oidcAuthentication(REGISTRATION_ID, null));
    final String second =
        multiIdpHandler.determineTargetUrl(
            requestWithReferer(SAME_ORIGIN_REFERER),
            new MockHttpServletResponse(),
            oidcAuthentication(SECONDARY_REGISTRATION_ID, null));

    assertThat(postLogoutRedirectUriOf(first)).isEqualTo(ABSOLUTE_POST_LOGOUT_URI);
    assertThat(postLogoutRedirectUriOf(second))
        .isEqualTo("https://camunda.com/component/post-logout");
  }

  /**
   * A registration mapped to {@code ""} — how the chain builder expresses {@code
   * post-logout-redirect-enabled=false} — sends no parameter, while its sibling still does.
   */
  @Test
  void registrationMappedToAnEmptyUriSendsNoPostLogoutRedirectParam() {
    final var multiIdpHandler =
        handlerWithRedirectUris(
            Map.of(REGISTRATION_ID, "", SECONDARY_REGISTRATION_ID, ABSOLUTE_POST_LOGOUT_URI));
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration());

    final String targetUrl =
        multiIdpHandler.determineTargetUrl(
            requestWithReferer(SAME_ORIGIN_REFERER),
            new MockHttpServletResponse(),
            oidcAuthentication(null));

    assertThat(queryParams(targetUrl, "idp.com", "/logout").getFirst("post_logout_redirect_uri"))
        .isNull();
  }

  /** A registrationId the chain never configured must not inherit another registration's URI. */
  @Test
  void unknownRegistrationIdSendsNoPostLogoutRedirectParam() {
    final var multiIdpHandler =
        handlerWithRedirectUris(Map.of(SECONDARY_REGISTRATION_ID, ABSOLUTE_POST_LOGOUT_URI));
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration());

    final String targetUrl =
        multiIdpHandler.determineTargetUrl(
            requestWithReferer(SAME_ORIGIN_REFERER),
            new MockHttpServletResponse(),
            oidcAuthentication(null));

    assertThat(queryParams(targetUrl, "idp.com", "/logout").getFirst("post_logout_redirect_uri"))
        .isNull();
  }

  /**
   * {@code logout_hint} is appended by this handler after the delegate has produced the end-session
   * URL, so it has to survive the delegate hop.
   */
  @Test
  void logoutHintIsStillAppendedWhenAPerRegistrationUriIsConfigured() {
    final var configuredHandler =
        handlerWithRedirectUris(Map.of(REGISTRATION_ID, ABSOLUTE_POST_LOGOUT_URI));
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration());

    final String targetUrl =
        configuredHandler.determineTargetUrl(
            requestWithReferer(SAME_ORIGIN_REFERER),
            new MockHttpServletResponse(),
            oidcAuthentication("user@camunda.com"));

    assertThat(targetUrl).contains("logout_hint=user@camunda.com");
    assertThat(postLogoutRedirectUriOf(targetUrl)).isEqualTo(ABSOLUTE_POST_LOGOUT_URI);
  }

  /**
   * Regression guard for the delegate's fall-through. "The IdP published no {@code
   * end_session_endpoint}" is detected by comparing the resolved URL against this handler's own
   * default target URL; a delegate carries its own copy of that field, so a delegate-produced
   * default reaching the comparison would silently defeat it. Here the registration has a mapped
   * URI (so a delegate is used) but no end-session endpoint.
   */
  @Test
  void missingEndSessionEndpointStillStoresRedirectMessageWhenAUriIsMapped() {
    final var configuredHandler =
        handlerWithRedirectUris(Map.of(REGISTRATION_ID, ABSOLUTE_POST_LOGOUT_URI));
    final MockHttpServletRequest request = requestWithReferer(SAME_ORIGIN_REFERER);
    final HttpSession session = request.getSession(true);
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistrationWithoutEndSessionEndpoint());

    configuredHandler.determineTargetUrl(
        request, new MockHttpServletResponse(), oidcAuthentication(null));

    assertThat(session.getAttribute(REDIRECT_MESSAGE_ATTRIBUTE)).isNotNull();
  }

  /**
   * The other, louder half of the same guard: a fetch-based logout with no end-session endpoint
   * must answer 204. If the sentinel were defeated it would answer {@code 200 {"url": "/"}} and the
   * webapp would navigate to {@code /} believing it was the IdP's end-session URL.
   */
  @Test
  void fetchLogoutWithoutEndSessionStillReturnsNoContentWhenAUriIsMapped()
      throws IOException, ServletException {
    final var configuredHandler =
        handlerWithRedirectUris(Map.of(REGISTRATION_ID, ABSOLUTE_POST_LOGOUT_URI));
    final MockHttpServletResponse response = new MockHttpServletResponse();
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistrationWithoutEndSessionEndpoint());

    configuredHandler.onLogoutSuccess(
        fetchRequestWithReferer(SAME_ORIGIN_REFERER), response, oidcAuthentication(null));

    assertThat(response.getStatus()).isEqualTo(204);
    assertThat(response.getContentAsString()).isEmpty();
  }

  private CamundaOidcLogoutSuccessHandler handlerWithRedirectUris(
      final Map<String, String> postLogoutRedirectUriByRegistrationId) {
    return new CamundaOidcLogoutSuccessHandler(
        clientRegistrationRepository, postLogoutRedirectUriByRegistrationId);
  }

  private static String postLogoutRedirectUriOf(final String targetUrl) {
    final MultiValueMap<String, String> query = queryParams(targetUrl, "idp.com", "/logout");
    return URLDecoder.decode(
        Objects.requireNonNull(query.getFirst("post_logout_redirect_uri")), StandardCharsets.UTF_8);
  }

  private static MultiValueMap<String, String> queryParams(
      final String url, final String expectedHost, final String expectedPath) {
    final UriComponents parsed = UriComponentsBuilder.fromUriString(url).build();
    assertThat(parsed.getScheme()).isEqualTo("https");
    assertThat(parsed.getHost()).isEqualTo(expectedHost);
    assertThat(parsed.getPath()).isEqualTo(expectedPath);
    return parsed.getQueryParams();
  }

  private static OAuth2AuthenticationToken oidcAuthentication(final String loginHint) {
    return oidcAuthentication(REGISTRATION_ID, loginHint);
  }

  private static OAuth2AuthenticationToken oidcAuthentication(
      final String registrationId, final String loginHint) {
    final Map<String, Object> claims = new HashMap<>();
    claims.put("sub", "user-id");
    if (loginHint != null) {
      claims.put("login_hint", loginHint);
    }
    final OidcIdToken token = new OidcIdToken("value", now(), now().plusSeconds(60), claims);
    final DefaultOidcUser oidcUser =
        new DefaultOidcUser(List.of(new SimpleGrantedAuthority("ROLE_USER")), token);
    return new OAuth2AuthenticationToken(oidcUser, oidcUser.getAuthorities(), registrationId);
  }

  private static OAuth2AuthenticationToken plainOAuth2Authentication() {
    final Map<String, Object> attributes = new HashMap<>();
    attributes.put("sub", "user-id");
    final OAuth2User user =
        new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("ROLE_USER")), attributes, "sub");
    return new OAuth2AuthenticationToken(user, user.getAuthorities(), REGISTRATION_ID);
  }

  private static ClientRegistration clientRegistration() {
    return clientRegistration(REGISTRATION_ID);
  }

  private static ClientRegistration clientRegistration(final String registrationId) {
    final Map<String, Object> metadata = new HashMap<>();
    metadata.put("end_session_endpoint", "https://idp.com/logout");
    return baseRegistrationBuilder()
        .registrationId(registrationId)
        .providerConfigurationMetadata(metadata)
        .build();
  }

  private static ClientRegistration clientRegistrationWithoutEndSessionEndpoint() {
    return baseRegistrationBuilder().build();
  }

  private static ClientRegistration.Builder baseRegistrationBuilder() {
    return ClientRegistration.withRegistrationId(REGISTRATION_ID)
        .clientId("client-id")
        .clientSecret("client-secret")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
        .authorizationUri("https://idp.com/oauth2/v1/authorize")
        .tokenUri("https://idp.com/oauth2/v1/token");
  }
}
