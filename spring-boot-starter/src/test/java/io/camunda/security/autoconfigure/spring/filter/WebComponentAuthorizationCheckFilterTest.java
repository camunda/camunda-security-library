/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.autoconfigure.spring.filter;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.autoconfigure.spring.spi.WebComponentAccessDeniedHandler;
import io.camunda.security.autoconfigure.spring.spi.WebComponentProvider;
import io.camunda.security.core.authorization.Authorization;
import io.camunda.security.core.authorization.CamundaAuthentication;
import io.camunda.security.core.authorization.ResourceAccess;
import io.camunda.security.core.port.in.AuthorizationPort;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class WebComponentAuthorizationCheckFilterTest {

  @Test
  void staticResourcePassesThroughWithoutCheck() throws Exception {
    final var componentProvider = new RecordingComponentProvider("operate");
    final var authorizationPort = new RecordingAuthorizationPort(new ResourceAccess.Denied());
    final var deniedHandler = new RecordingDeniedHandler();
    final var filter =
        filter(componentProvider, authorizationPort, deniedHandler, authenticatedUser());

    final var chain = new MockFilterChain();
    filter.doFilter(request("/operate/assets/main.js"), new MockHttpServletResponse(), chain);

    assertThat(chain.getRequest()).isNotNull();
    assertThat(componentProvider.callCount).isZero();
    assertThat(authorizationPort.callCount).isZero();
    assertThat(deniedHandler.callCount).isZero();
  }

  @Test
  void forbiddenUrlPassesThroughWithoutCheck() throws Exception {
    final var componentProvider = new RecordingComponentProvider("operate");
    final var authorizationPort = new RecordingAuthorizationPort(new ResourceAccess.Denied());
    final var deniedHandler = new RecordingDeniedHandler();
    final var filter =
        filter(componentProvider, authorizationPort, deniedHandler, authenticatedUser());

    final var chain = new MockFilterChain();
    filter.doFilter(request("/operate/forbidden"), new MockHttpServletResponse(), chain);

    assertThat(chain.getRequest()).isNotNull();
    assertThat(componentProvider.callCount).isZero();
    assertThat(authorizationPort.callCount).isZero();
    assertThat(deniedHandler.callCount).isZero();
  }

  @Test
  void unauthenticatedPrincipalPassesThroughWithoutCheck() throws Exception {
    final var componentProvider = new RecordingComponentProvider("operate");
    final var authorizationPort = new RecordingAuthorizationPort(new ResourceAccess.Denied());
    final var deniedHandler = new RecordingDeniedHandler();
    final var filter =
        filter(
            componentProvider,
            authorizationPort,
            deniedHandler,
            CamundaAuthentication.unauthenticated());

    final var chain = new MockFilterChain();
    filter.doFilter(request("/operate/processes"), new MockHttpServletResponse(), chain);

    assertThat(chain.getRequest()).isNotNull();
    assertThat(componentProvider.callCount).isZero();
    assertThat(authorizationPort.callCount).isZero();
    assertThat(deniedHandler.callCount).isZero();
  }

  @Test
  void emptyComponentPassesThroughWithoutCheck() throws Exception {
    final var componentProvider = new RecordingComponentProvider(null);
    final var authorizationPort = new RecordingAuthorizationPort(new ResourceAccess.Denied());
    final var deniedHandler = new RecordingDeniedHandler();
    final var filter =
        filter(componentProvider, authorizationPort, deniedHandler, authenticatedUser());

    final var chain = new MockFilterChain();
    filter.doFilter(request("/some/random/path"), new MockHttpServletResponse(), chain);

    assertThat(chain.getRequest()).isNotNull();
    assertThat(componentProvider.callCount).isOne();
    assertThat(authorizationPort.callCount).isZero();
    assertThat(deniedHandler.callCount).isZero();
  }

  @Test
  void allowedAccessPassesThrough() throws Exception {
    final var componentProvider = new RecordingComponentProvider("operate");
    final var authorizationPort =
        new RecordingAuthorizationPort(new ResourceAccess.Allowed(Set.of("operate")));
    final var deniedHandler = new RecordingDeniedHandler();
    final var filter =
        filter(componentProvider, authorizationPort, deniedHandler, authenticatedUser());

    final var chain = new MockFilterChain();
    filter.doFilter(request("/operate/processes"), new MockHttpServletResponse(), chain);

    assertThat(chain.getRequest()).isNotNull();
    assertThat(authorizationPort.callCount).isOne();
    assertThat(deniedHandler.callCount).isZero();
  }

  @Test
  void wildcardAccessIsTreatedAsAllowed() throws Exception {
    final var componentProvider = new RecordingComponentProvider("operate");
    final var authorizationPort = new RecordingAuthorizationPort(new ResourceAccess.Wildcard());
    final var deniedHandler = new RecordingDeniedHandler();
    final var filter =
        filter(componentProvider, authorizationPort, deniedHandler, authenticatedUser());

    final var chain = new MockFilterChain();
    filter.doFilter(request("/operate/processes"), new MockHttpServletResponse(), chain);

    assertThat(chain.getRequest()).isNotNull();
    assertThat(deniedHandler.callCount).isZero();
  }

  @Test
  void deniedAccessInvokesHandlerAndDoesNotForwardRequest() throws Exception {
    final var componentProvider = new RecordingComponentProvider("operate");
    final var authorizationPort = new RecordingAuthorizationPort(new ResourceAccess.Denied());
    final var deniedHandler = new RecordingDeniedHandler();
    final var filter =
        filter(componentProvider, authorizationPort, deniedHandler, authenticatedUser());

    final var chain = new MockFilterChain();
    final var request = request("/operate/processes");
    final var response = new MockHttpServletResponse();
    filter.doFilter(request, response, chain);

    assertThat(chain.getRequest()).isNull();
    assertThat(deniedHandler.callCount).isOne();
    assertThat(deniedHandler.lastComponent).isEqualTo("operate");
    assertThat(deniedHandler.lastRequest).isSameAs(request);
    assertThat(deniedHandler.lastResponse).isSameAs(response);
    assertThat(deniedHandler.lastAuthentication.authenticatedUsername()).isEqualTo("alice");
  }

  @Test
  void filterPassesAuthorizationWithComponentAccessShape() throws Exception {
    final var componentProvider = new RecordingComponentProvider("tasklist");
    final var authorizationPort = new RecordingAuthorizationPort(new ResourceAccess.Wildcard());
    final var deniedHandler = new RecordingDeniedHandler();
    final var filter =
        filter(componentProvider, authorizationPort, deniedHandler, authenticatedUser());

    filter.doFilter(
        request("/tasklist/processes"), new MockHttpServletResponse(), new MockFilterChain());

    assertThat(authorizationPort.lastRequired).isNotNull();
    assertThat(authorizationPort.lastRequired.permissionType()).isEqualTo("ACCESS");
    assertThat(authorizationPort.lastRequired.resourceType()).isEqualTo("COMPONENT");
    assertThat(authorizationPort.lastRequired.resourceIds()).containsExactly("tasklist");
  }

  private static WebComponentAuthorizationCheckFilter filter(
      final WebComponentProvider componentProvider,
      final AuthorizationPort authorizationPort,
      final WebComponentAccessDeniedHandler deniedHandler,
      final CamundaAuthentication authentication) {
    return new WebComponentAuthorizationCheckFilter(
        componentProvider, authorizationPort, deniedHandler, () -> authentication);
  }

  private static MockHttpServletRequest request(final String uri) {
    final var request = new MockHttpServletRequest();
    request.setRequestURI(uri);
    return request;
  }

  private static CamundaAuthentication authenticatedUser() {
    return CamundaAuthentication.builder()
        .authenticatedUsername("alice")
        .authenticatedRoleIds(Set.of("admin"))
        .build();
  }

  private static final class RecordingComponentProvider implements WebComponentProvider {
    int callCount;
    private final String component;

    RecordingComponentProvider(final String component) {
      this.component = component;
    }

    @Override
    public Optional<String> componentFor(final HttpServletRequest request) {
      callCount++;
      return Optional.ofNullable(component);
    }
  }

  private static final class RecordingAuthorizationPort implements AuthorizationPort {
    int callCount;
    Authorization<?> lastRequired;
    private final ResourceAccess result;

    RecordingAuthorizationPort(final ResourceAccess result) {
      this.result = result;
    }

    @Override
    public <T> ResourceAccess lookup(
        final CamundaAuthentication authentication, final Authorization<T> required) {
      callCount++;
      lastRequired = required;
      return result;
    }
  }

  private static final class RecordingDeniedHandler implements WebComponentAccessDeniedHandler {
    int callCount;
    HttpServletRequest lastRequest;
    HttpServletResponse lastResponse;
    String lastComponent;
    CamundaAuthentication lastAuthentication;

    @Override
    public void handle(
        final HttpServletRequest request,
        final HttpServletResponse response,
        final String component,
        final CamundaAuthentication authentication) {
      callCount++;
      lastRequest = request;
      lastResponse = response;
      lastComponent = component;
      lastAuthentication = authentication;
    }
  }
}
