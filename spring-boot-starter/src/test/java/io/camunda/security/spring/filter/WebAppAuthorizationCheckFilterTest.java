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
import io.camunda.security.api.model.PermissionType;
import io.camunda.security.api.model.ResourceType;
import io.camunda.security.core.port.in.ResourcePermissionPort;
import io.camunda.security.spring.spi.WebAppAccessDeniedHandler;
import io.camunda.security.spring.spi.WebAppProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Optional;
import java.util.Set;
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
    final var permissionPort = new RecordingPermissionPort(false);
    final var deniedHandler = new RecordingDeniedHandler();
    final var filter = filter(webAppProvider, permissionPort, deniedHandler, alice());

    final var chain = new MockFilterChain();
    filter.doFilter(request("/operate/assets/main.js"), new MockHttpServletResponse(), chain);

    assertThat(chain.getRequest()).isNotNull();
    assertThat(webAppProvider.callCount).isZero();
    assertThat(permissionPort.callCount).isZero();
    assertThat(deniedHandler.callCount).isZero();
  }

  @Test
  void forbiddenUrlPassesThroughWithoutCheck() throws Exception {
    final var webAppProvider = new RecordingWebAppProvider("operate");
    final var permissionPort = new RecordingPermissionPort(false);
    final var deniedHandler = new RecordingDeniedHandler();
    final var filter = filter(webAppProvider, permissionPort, deniedHandler, alice());

    final var chain = new MockFilterChain();
    filter.doFilter(request("/operate/forbidden"), new MockHttpServletResponse(), chain);

    assertThat(chain.getRequest()).isNotNull();
    assertThat(webAppProvider.callCount).isZero();
    assertThat(permissionPort.callCount).isZero();
    assertThat(deniedHandler.callCount).isZero();
  }

  @Test
  void anonymousPrincipalPassesThroughWithoutCheck() throws Exception {
    final var webAppProvider = new RecordingWebAppProvider("operate");
    final var permissionPort = new RecordingPermissionPort(false);
    final var deniedHandler = new RecordingDeniedHandler();
    final var filter =
        filter(webAppProvider, permissionPort, deniedHandler, CamundaAuthentication.anonymous());

    final var chain = new MockFilterChain();
    filter.doFilter(request("/operate/processes"), new MockHttpServletResponse(), chain);

    assertThat(chain.getRequest()).isNotNull();
    assertThat(webAppProvider.callCount).isZero();
    assertThat(permissionPort.callCount).isZero();
    assertThat(deniedHandler.callCount).isZero();
  }

  @Test
  void nullPrincipalPassesThroughWithoutCheck() throws Exception {
    final var webAppProvider = new RecordingWebAppProvider("operate");
    final var permissionPort = new RecordingPermissionPort(false);
    final var deniedHandler = new RecordingDeniedHandler();
    final var filter = filter(webAppProvider, permissionPort, deniedHandler, null);

    final var chain = new MockFilterChain();
    filter.doFilter(request("/operate/processes"), new MockHttpServletResponse(), chain);

    assertThat(chain.getRequest()).isNotNull();
    assertThat(webAppProvider.callCount).isZero();
    assertThat(permissionPort.callCount).isZero();
    assertThat(deniedHandler.callCount).isZero();
  }

  @Test
  void emptyWebAppPassesThroughWithoutCheck() throws Exception {
    final var webAppProvider = new RecordingWebAppProvider(null);
    final var permissionPort = new RecordingPermissionPort(false);
    final var deniedHandler = new RecordingDeniedHandler();
    final var filter = filter(webAppProvider, permissionPort, deniedHandler, alice());

    final var chain = new MockFilterChain();
    filter.doFilter(request("/some/random/path"), new MockHttpServletResponse(), chain);

    assertThat(chain.getRequest()).isNotNull();
    assertThat(webAppProvider.callCount).isOne();
    assertThat(permissionPort.callCount).isZero();
    assertThat(deniedHandler.callCount).isZero();
  }

  @Test
  void allowedAccessPassesThrough() throws Exception {
    final var webAppProvider = new RecordingWebAppProvider("operate");
    final var permissionPort = new RecordingPermissionPort(true);
    final var deniedHandler = new RecordingDeniedHandler();
    final var filter = filter(webAppProvider, permissionPort, deniedHandler, alice());

    final var chain = new MockFilterChain();
    filter.doFilter(request("/operate/processes"), new MockHttpServletResponse(), chain);

    assertThat(chain.getRequest()).isNotNull();
    assertThat(permissionPort.callCount).isOne();
    assertThat(deniedHandler.callCount).isZero();
  }

  @Test
  void deniedAccessInvokesHandlerAndDoesNotForwardRequest() throws Exception {
    final var webAppProvider = new RecordingWebAppProvider("operate");
    final var permissionPort = new RecordingPermissionPort(false);
    final var deniedHandler = new RecordingDeniedHandler();
    final var filter = filter(webAppProvider, permissionPort, deniedHandler, alice());

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
    final var permissionPort = new RecordingPermissionPort(false);
    final var deniedHandler = new RecordingDeniedHandler();
    final var filter =
        new WebAppAuthorizationCheckFilter(
            webAppProvider, permissionPort, deniedHandler, () -> alice(), Set.of(".json"));

    final var chain = new MockFilterChain();
    filter.doFilter(request("/operate/data.json"), new MockHttpServletResponse(), chain);

    assertThat(chain.getRequest()).isNotNull();
    assertThat(permissionPort.callCount).isZero();
    assertThat(deniedHandler.callCount).isZero();
  }

  @Test
  void filterPassesPermissionCheckShape() throws Exception {
    final var webAppProvider = new RecordingWebAppProvider("tasklist");
    final var permissionPort = new RecordingPermissionPort(true);
    final var deniedHandler = new RecordingDeniedHandler();
    final var filter = filter(webAppProvider, permissionPort, deniedHandler, alice());

    filter.doFilter(
        request("/tasklist/processes"), new MockHttpServletResponse(), new MockFilterChain());

    assertThat(permissionPort.lastResourceType).isEqualTo(ResourceType.COMPONENT);
    assertThat(permissionPort.lastResourceId).isEqualTo("tasklist");
    assertThat(permissionPort.lastPermissionType).isEqualTo(PermissionType.ACCESS);
  }

  private static WebAppAuthorizationCheckFilter filter(
      final WebAppProvider webAppProvider,
      final ResourcePermissionPort permissionPort,
      final WebAppAccessDeniedHandler deniedHandler,
      final CamundaAuthentication authentication) {
    return new WebAppAuthorizationCheckFilter(
        webAppProvider,
        permissionPort,
        deniedHandler,
        () -> authentication,
        DEFAULT_STATIC_RESOURCE_SUFFIXES);
  }

  private static MockHttpServletRequest request(final String uri) {
    final var request = new MockHttpServletRequest();
    request.setRequestURI(uri);
    return request;
  }

  private static CamundaAuthentication alice() {
    return CamundaAuthentication.of(b -> b.user("alice").role("admin"));
  }

  private static final class RecordingWebAppProvider implements WebAppProvider {
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

  private static final class RecordingPermissionPort implements ResourcePermissionPort {
    int callCount;
    ResourceType lastResourceType;
    String lastResourceId;
    PermissionType lastPermissionType;
    private final boolean result;

    RecordingPermissionPort(final boolean result) {
      this.result = result;
    }

    @Override
    public boolean hasPermission(
        final CamundaAuthentication authentication,
        final ResourceType resourceType,
        final String resourceId,
        final PermissionType permissionType) {
      callCount++;
      lastResourceType = resourceType;
      lastResourceId = resourceId;
      lastPermissionType = permissionType;
      return result;
    }
  }

  private static final class RecordingDeniedHandler implements WebAppAccessDeniedHandler {
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
