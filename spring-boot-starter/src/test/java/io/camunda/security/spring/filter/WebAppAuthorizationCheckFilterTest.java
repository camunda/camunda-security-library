/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.filter;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.Either;
import io.camunda.security.api.model.authz.AuthorizationRejection;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.core.auth.RequiredAuthorization;
import io.camunda.security.core.port.in.AuthorizationCheckPort;
import io.camunda.security.spring.spi.WebAppAccessDeniedHandlerPort;
import io.camunda.security.spring.spi.WebAppAuthorizationEnabledPort;
import io.camunda.security.spring.spi.WebAppProviderPort;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class WebAppAuthorizationCheckFilterTest {

  private static final Set<String> DEFAULT_STATIC_RESOURCE_SUFFIXES =
      Set.of(".css", ".js", ".js.map", ".jpg", ".png", ".woff2", ".ico", ".svg");

  @Test
  void staticResourcePassesThroughWithoutCheck() throws Exception {
    final var webAppProvider = new RecordingWebAppProvider("operate");
    final var checkPort = new RecordingCheckPort(false);
    final var deniedHandler = new RecordingDeniedHandler();
    final var filter = filter(webAppProvider, checkPort, deniedHandler, alice());

    final var chain = new MockFilterChain();
    filter.doFilter(request("/operate/assets/main.js"), new MockHttpServletResponse(), chain);

    assertThat(chain.getRequest()).isNotNull();
    assertThat(webAppProvider.callCount).isZero();
    assertThat(checkPort.callCount).isZero();
    assertThat(deniedHandler.callCount).isZero();
  }

  @Test
  void forbiddenUrlPassesThroughWithoutCheck() throws Exception {
    final var webAppProvider = new RecordingWebAppProvider("operate");
    final var checkPort = new RecordingCheckPort(false);
    final var deniedHandler = new RecordingDeniedHandler();
    final var filter = filter(webAppProvider, checkPort, deniedHandler, alice());

    final var chain = new MockFilterChain();
    filter.doFilter(request("/operate/forbidden"), new MockHttpServletResponse(), chain);

    assertThat(chain.getRequest()).isNotNull();
    assertThat(webAppProvider.callCount).isZero();
    assertThat(checkPort.callCount).isZero();
    assertThat(deniedHandler.callCount).isZero();
  }

  @Test
  void anonymousPrincipalPassesThroughWithoutCheck() throws Exception {
    final var webAppProvider = new RecordingWebAppProvider("operate");
    final var checkPort = new RecordingCheckPort(false);
    final var deniedHandler = new RecordingDeniedHandler();
    final var filter =
        filter(webAppProvider, checkPort, deniedHandler, CamundaAuthentication.anonymous());

    final var chain = new MockFilterChain();
    filter.doFilter(request("/operate/processes"), new MockHttpServletResponse(), chain);

    assertThat(chain.getRequest()).isNotNull();
    assertThat(webAppProvider.callCount).isZero();
    assertThat(checkPort.callCount).isZero();
    assertThat(deniedHandler.callCount).isZero();
  }

  @Test
  void nullPrincipalPassesThroughWithoutCheck() throws Exception {
    final var webAppProvider = new RecordingWebAppProvider("operate");
    final var checkPort = new RecordingCheckPort(false);
    final var deniedHandler = new RecordingDeniedHandler();
    final var filter = filter(webAppProvider, checkPort, deniedHandler, null);

    final var chain = new MockFilterChain();
    filter.doFilter(request("/operate/processes"), new MockHttpServletResponse(), chain);

    assertThat(chain.getRequest()).isNotNull();
    assertThat(webAppProvider.callCount).isZero();
    assertThat(checkPort.callCount).isZero();
    assertThat(deniedHandler.callCount).isZero();
  }

  @Test
  void emptyWebAppPassesThroughWithoutCheck() throws Exception {
    final var webAppProvider = new RecordingWebAppProvider(null);
    final var checkPort = new RecordingCheckPort(false);
    final var deniedHandler = new RecordingDeniedHandler();
    final var filter = filter(webAppProvider, checkPort, deniedHandler, alice());

    final var chain = new MockFilterChain();
    filter.doFilter(request("/some/random/path"), new MockHttpServletResponse(), chain);

    assertThat(chain.getRequest()).isNotNull();
    assertThat(webAppProvider.callCount).isOne();
    assertThat(checkPort.callCount).isZero();
    assertThat(deniedHandler.callCount).isZero();
  }

  @Test
  void authorizationDisabledPassesThroughWithoutCheck() throws Exception {
    // With authorization globally disabled, an authenticated principal on a resolved web app whose
    // check port would deny access must still pass through — no authentication or web-app
    // resolution, no port call, no denial.
    final var authenticationCalls = new AtomicInteger();
    final var webAppProvider = new RecordingWebAppProvider("operate");
    final var checkPort = new RecordingCheckPort(false);
    final var deniedHandler = new RecordingDeniedHandler();
    final var filter =
        new WebAppAuthorizationCheckFilter(
            false,
            webAppProvider,
            checkPort,
            deniedHandler,
            () -> {
              authenticationCalls.incrementAndGet();
              return alice();
            },
            DEFAULT_STATIC_RESOURCE_SUFFIXES);

    final var chain = new MockFilterChain();
    filter.doFilter(request("/operate/processes"), new MockHttpServletResponse(), chain);

    assertThat(chain.getRequest()).isNotNull();
    assertThat(authenticationCalls).hasValue(0);
    assertThat(webAppProvider.callCount).isZero();
    assertThat(checkPort.callCount).isZero();
    assertThat(deniedHandler.callCount).isZero();
  }

  @Test
  void authorizationEnablementIsResolvedForEachRequest() throws Exception {
    final var filter =
        filterAsking(
            request -> request.getRequestURI().startsWith("/scope-on/"), "operate", alice());

    assertThat(passesThrough(filter, "/scope-off/operate/processes")).isTrue();
    assertThat(passesThrough(filter, "/scope-on/operate/processes")).isFalse();
  }

  @Test
  void requestsSkippingTheCheckPassWithoutAskingAuthorizationEnabledPort() throws Exception {
    final var enabledPort = new RecordingEnabledPort();
    final var filter = filterAsking(enabledPort, "operate", alice());

    assertThat(passesThrough(filter, "/operate/assets/main.js")).isTrue();
    assertThat(passesThrough(filter, "/operate/forbidden")).isTrue();
    assertThat(
            passesThrough(
                filterAsking(enabledPort, "operate", CamundaAuthentication.anonymous()),
                "/operate/processes"))
        .isTrue();
    assertThat(passesThrough(filterAsking(enabledPort, null, alice()), "/some/random/path"))
        .isTrue();
    assertThat(enabledPort.callCount).isZero();
  }

  @Test
  void failingAuthorizationEnabledPortLeavesTheDecisionToTheCheckPort() throws Exception {
    final var filter =
        filterAsking(
            request -> {
              throw new IllegalStateException("scope lookup failed");
            },
            "operate",
            alice());

    assertThat(passesThrough(filter, "/operate/processes")).isFalse();
  }

  @Test
  void allowedAccessPassesThrough() throws Exception {
    final var webAppProvider = new RecordingWebAppProvider("operate");
    final var checkPort = new RecordingCheckPort(true);
    final var deniedHandler = new RecordingDeniedHandler();
    final var filter = filter(webAppProvider, checkPort, deniedHandler, alice());

    final var chain = new MockFilterChain();
    filter.doFilter(request("/operate/processes"), new MockHttpServletResponse(), chain);

    assertThat(chain.getRequest()).isNotNull();
    assertThat(checkPort.callCount).isOne();
    assertThat(deniedHandler.callCount).isZero();
  }

  @Test
  void deniedAccessInvokesHandlerAndDoesNotForwardRequest() throws Exception {
    final var webAppProvider = new RecordingWebAppProvider("operate");
    final var checkPort = new RecordingCheckPort(false);
    final var deniedHandler = new RecordingDeniedHandler();
    final var filter = filter(webAppProvider, checkPort, deniedHandler, alice());

    final var chain = new MockFilterChain();
    final var request = request("/operate/processes");
    final var response = new MockHttpServletResponse();
    filter.doFilter(request, response, chain);

    assertThat(chain.getRequest()).isNull();
    assertThat(deniedHandler.callCount).isOne();
    assertThat(deniedHandler.lastWebApp).isEqualTo("operate");
    assertThat(deniedHandler.lastRequest).isSameAs(request);
    assertThat(deniedHandler.lastResponse).isSameAs(response);
    assertThat(deniedHandler.lastAuthentication.authenticatedUsername()).isEqualTo("alice");
  }

  @Test
  void hostSuppliedSuffixesArePassedThrough() throws Exception {
    // Host has added ".json" to its bypass list — the filter must respect it.
    final var webAppProvider = new RecordingWebAppProvider("operate");
    final var checkPort = new RecordingCheckPort(false);
    final var deniedHandler = new RecordingDeniedHandler();
    final var filter =
        new WebAppAuthorizationCheckFilter(
            true, webAppProvider, checkPort, deniedHandler, () -> alice(), Set.of(".json"));

    final var chain = new MockFilterChain();
    filter.doFilter(request("/operate/data.json"), new MockHttpServletResponse(), chain);

    assertThat(chain.getRequest()).isNotNull();
    assertThat(checkPort.callCount).isZero();
    assertThat(deniedHandler.callCount).isZero();
  }

  @Test
  void filterPassesAuthorizationCheckShape() throws Exception {
    // The filter must ask for ACCESS on the resolved web app as a COMPONENT resource.
    final var webAppProvider = new RecordingWebAppProvider("tasklist");
    final var checkPort = new RecordingCheckPort(true);
    final var deniedHandler = new RecordingDeniedHandler();
    final var filter = filter(webAppProvider, checkPort, deniedHandler, alice());

    filter.doFilter(
        request("/tasklist/processes"), new MockHttpServletResponse(), new MockFilterChain());

    assertThat(checkPort.lastAuthorization).isNotNull();
    assertThat(checkPort.lastAuthorization.resourceType())
        .isEqualTo(AuthorizationResourceType.COMPONENT);
    assertThat(checkPort.lastAuthorization.resourceIds()).containsExactly("tasklist");
    assertThat(checkPort.lastAuthorization.permissionType()).isEqualTo(PermissionType.ACCESS);
  }

  private static WebAppAuthorizationCheckFilter filter(
      final WebAppProviderPort webAppProvider,
      final AuthorizationCheckPort checkPort,
      final WebAppAccessDeniedHandlerPort deniedHandler,
      final CamundaAuthentication authentication) {
    return new WebAppAuthorizationCheckFilter(
        true,
        webAppProvider,
        checkPort,
        deniedHandler,
        () -> authentication,
        DEFAULT_STATIC_RESOURCE_SUFFIXES);
  }

  private static WebAppAuthorizationCheckFilter filterAsking(
      final WebAppAuthorizationEnabledPort enabledPort,
      final String webApp,
      final CamundaAuthentication authentication) {
    return new WebAppAuthorizationCheckFilter(
        enabledPort,
        new RecordingWebAppProvider(webApp),
        new RecordingCheckPort(false),
        new RecordingDeniedHandler(),
        () -> authentication,
        DEFAULT_STATIC_RESOURCE_SUFFIXES);
  }

  /** Returns whether the filter forwarded the request; it is denied otherwise. */
  private static boolean passesThrough(
      final WebAppAuthorizationCheckFilter filter, final String uri) throws Exception {
    final var chain = new MockFilterChain();
    filter.doFilter(request(uri), new MockHttpServletResponse(), chain);
    return chain.getRequest() != null;
  }

  private static MockHttpServletRequest request(final String uri) {
    final var request = new MockHttpServletRequest();
    request.setRequestURI(uri);
    return request;
  }

  private static CamundaAuthentication alice() {
    return CamundaAuthentication.of(b -> b.user("alice").role("admin"));
  }

  private static final class RecordingWebAppProvider implements WebAppProviderPort {
    int callCount;
    private final String webApp;

    RecordingWebAppProvider(final String webApp) {
      this.webApp = webApp;
    }

    @Override
    public Optional<String> webAppFor(final HttpServletRequest request) {
      callCount++;
      return Optional.ofNullable(webApp);
    }
  }

  private static final class RecordingEnabledPort implements WebAppAuthorizationEnabledPort {
    int callCount;

    @Override
    public boolean isAuthorizationEnabled(final HttpServletRequest request) {
      callCount++;
      return true;
    }
  }

  private static final class RecordingCheckPort implements AuthorizationCheckPort {
    int callCount;
    RequiredAuthorization<?> lastAuthorization;
    private final boolean allowed;

    RecordingCheckPort(final boolean allowed) {
      this.allowed = allowed;
    }

    @Override
    public <T> Either<AuthorizationRejection, Void> check(
        final CamundaAuthentication authentication, final RequiredAuthorization<T> authorization) {
      callCount++;
      lastAuthorization = authorization;
      return allowed
          ? Either.right(null)
          : Either.left(
              new AuthorizationRejection.Permission(
                  AuthorizationResourceType.COMPONENT, PermissionType.ACCESS, "denied"));
    }

    @Override
    public <T> Either<AuthorizationRejection, Void> check(
        final Map<String, Object> claims, final RequiredAuthorization<T> authorization) {
      throw new UnsupportedOperationException("claims-based check is not used by the filter");
    }

    @Override
    public <T> Either<AuthorizationRejection, Void> check(
        final CamundaAuthentication authentication,
        final RequiredAuthorization<T> authorization,
        final T resource) {
      throw new UnsupportedOperationException("resource-based check is not used by the filter");
    }
  }

  private static final class RecordingDeniedHandler implements WebAppAccessDeniedHandlerPort {
    int callCount;
    HttpServletRequest lastRequest;
    HttpServletResponse lastResponse;
    String lastWebApp;
    CamundaAuthentication lastAuthentication;

    @Override
    public void handle(
        final HttpServletRequest request,
        final HttpServletResponse response,
        final String webApp,
        final CamundaAuthentication authentication) {
      callCount++;
      lastRequest = request;
      lastResponse = response;
      lastWebApp = webApp;
      lastAuthentication = authentication;
    }
  }
}
