/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.filter;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class RequestPathSupportTest {

  @Test
  void emptyContextPathReturnsServletPath() {
    final var request = new MockHttpServletRequest();
    request.setContextPath("");
    request.setServletPath("/admin/setup");

    assertThat(RequestPathSupport.pathWithinApplication(request)).isEqualTo("/admin/setup");
  }

  @Test
  void nonEmptyContextPathStripsContextFromPathWithinApplication() {
    final var request = new MockHttpServletRequest();
    request.setContextPath("/operate");
    request.setServletPath("/admin/setup");

    assertThat(RequestPathSupport.pathWithinApplication(request)).isEqualTo("/admin/setup");
  }

  @Test
  void servletPathPlusPathInfoAreComposed() {
    final var request = new MockHttpServletRequest();
    request.setServletPath("/api");
    request.setPathInfo("/v1/widgets/42");

    assertThat(RequestPathSupport.pathWithinApplication(request)).isEqualTo("/api/v1/widgets/42");
  }

  @Test
  void nullServletPathFallsBackToPathInfo() {
    final var request = new MockHttpServletRequest();
    request.setServletPath(null);
    request.setPathInfo("/widgets/42");

    assertThat(RequestPathSupport.pathWithinApplication(request)).isEqualTo("/widgets/42");
  }

  @Test
  void nullServletPathAndNullPathInfoReturnEmptyString() {
    final var request = new MockHttpServletRequest();
    request.setServletPath(null);
    request.setPathInfo(null);

    assertThat(RequestPathSupport.pathWithinApplication(request)).isEmpty();
  }
}
