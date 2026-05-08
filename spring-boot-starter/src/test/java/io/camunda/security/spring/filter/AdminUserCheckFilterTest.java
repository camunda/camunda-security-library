/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.filter;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.core.port.out.AdminUserPresencePort;
import io.camunda.security.spring.spi.AdminUserMissingHandler;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class AdminUserCheckFilterTest {

  private static final Set<String> DEFAULT_BYPASS_PATHS = Set.of("/admin/setup", "/admin/assets");

  @Test
  void exactBypassPathPassesThroughWithoutCheckingPresence() throws Exception {
    final var presencePort = new RecordingPresencePort(false);
    final var missingHandler = new RecordingMissingHandler();
    final var filter = filter(presencePort, missingHandler, DEFAULT_BYPASS_PATHS);

    final var chain = new MockFilterChain();
    filter.doFilter(request("/admin/setup"), new MockHttpServletResponse(), chain);

    assertThat(chain.getRequest()).isNotNull();
    assertThat(presencePort.callCount).isZero();
    assertThat(missingHandler.callCount).isZero();
  }

  @Test
  void subPathBypassPathPassesThroughWithoutCheckingPresence() throws Exception {
    // A request whose URI starts with `<bypassPath>/` is treated as part of the bypass set —
    // covers static-asset paths like `/admin/assets/main.css` under the `/admin/assets` prefix.
    final var presencePort = new RecordingPresencePort(false);
    final var missingHandler = new RecordingMissingHandler();
    final var filter = filter(presencePort, missingHandler, DEFAULT_BYPASS_PATHS);

    final var chain = new MockFilterChain();
    filter.doFilter(request("/admin/assets/main.css"), new MockHttpServletResponse(), chain);

    assertThat(chain.getRequest()).isNotNull();
    assertThat(presencePort.callCount).isZero();
    assertThat(missingHandler.callCount).isZero();
  }

  @Test
  void uriThatMerelyExtendsBypassPathDoesNotBypass() throws Exception {
    // `/admin/setupbar` shares a prefix with `/admin/setup` but is a different path — must not
    // bypass. Tightens the match semantics relative to OC's `String#contains` source.
    final var presencePort = new RecordingPresencePort(true);
    final var missingHandler = new RecordingMissingHandler();
    final var filter = filter(presencePort, missingHandler, DEFAULT_BYPASS_PATHS);

    final var chain = new MockFilterChain();
    filter.doFilter(request("/admin/setupbar"), new MockHttpServletResponse(), chain);

    assertThat(chain.getRequest()).isNotNull();
    assertThat(presencePort.callCount).isOne();
  }

  @Test
  void adminUserExistsPassesThrough() throws Exception {
    final var presencePort = new RecordingPresencePort(true);
    final var missingHandler = new RecordingMissingHandler();
    final var filter = filter(presencePort, missingHandler, DEFAULT_BYPASS_PATHS);

    final var chain = new MockFilterChain();
    filter.doFilter(request("/operate/processes"), new MockHttpServletResponse(), chain);

    assertThat(chain.getRequest()).isNotNull();
    assertThat(presencePort.callCount).isOne();
    assertThat(missingHandler.callCount).isZero();
  }

  @Test
  void adminUserMissingInvokesHandlerAndDoesNotForwardRequest() throws Exception {
    final var presencePort = new RecordingPresencePort(false);
    final var missingHandler = new RecordingMissingHandler();
    final var filter = filter(presencePort, missingHandler, DEFAULT_BYPASS_PATHS);

    final var chain = new MockFilterChain();
    final var request = request("/operate/processes");
    final var response = new MockHttpServletResponse();
    filter.doFilter(request, response, chain);

    assertThat(chain.getRequest()).isNull();
    assertThat(presencePort.callCount).isOne();
    assertThat(missingHandler.callCount).isOne();
    assertThat(missingHandler.lastRequest).isSameAs(request);
    assertThat(missingHandler.lastResponse).isSameAs(response);
  }

  @Test
  void presencePortRuntimeExceptionFallsThroughDefensively() throws Exception {
    final var presencePort = new ThrowingPresencePort();
    final var missingHandler = new RecordingMissingHandler();
    final var filter = filter(presencePort, missingHandler, DEFAULT_BYPASS_PATHS);

    final var chain = new MockFilterChain();
    filter.doFilter(request("/operate/processes"), new MockHttpServletResponse(), chain);

    assertThat(chain.getRequest()).isNotNull();
    // The defensive path is only meaningful if the presence check was actually attempted —
    // assert the call happened so a regression that skipped the check would fail this test.
    assertThat(presencePort.callCount).isOne();
    assertThat(missingHandler.callCount).isZero();
  }

  @Test
  void emptyBypassPathSetCausesEveryRequestToBeChecked() throws Exception {
    final var presencePort = new RecordingPresencePort(true);
    final var missingHandler = new RecordingMissingHandler();
    final var filter = filter(presencePort, missingHandler, Set.of());

    filter.doFilter(request("/admin/setup"), new MockHttpServletResponse(), new MockFilterChain());

    assertThat(presencePort.callCount).isOne();
  }

  private static AdminUserCheckFilter filter(
      final AdminUserPresencePort presencePort,
      final AdminUserMissingHandler missingHandler,
      final Set<String> bypassPaths) {
    return new AdminUserCheckFilter(presencePort, missingHandler, bypassPaths);
  }

  private static MockHttpServletRequest request(final String uri) {
    final var request = new MockHttpServletRequest();
    request.setRequestURI(uri);
    return request;
  }

  private static final class RecordingPresencePort implements AdminUserPresencePort {
    int callCount;
    private final boolean exists;

    RecordingPresencePort(final boolean exists) {
      this.exists = exists;
    }

    @Override
    public boolean adminUserExists() {
      callCount++;
      return exists;
    }
  }

  private static final class ThrowingPresencePort implements AdminUserPresencePort {
    int callCount;

    @Override
    public boolean adminUserExists() {
      callCount++;
      throw new RuntimeException("simulated secondary storage outage");
    }
  }

  private static final class RecordingMissingHandler implements AdminUserMissingHandler {
    int callCount;
    HttpServletRequest lastRequest;
    HttpServletResponse lastResponse;

    @Override
    public void handle(final HttpServletRequest request, final HttpServletResponse response) {
      callCount++;
      lastRequest = request;
      lastResponse = response;
    }
  }
}
