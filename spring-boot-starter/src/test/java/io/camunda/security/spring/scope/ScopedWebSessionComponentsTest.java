/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.Test;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.web.http.SessionRepositoryFilter;

class ScopedWebSessionComponentsTest {

  @Test
  void buildsSessionRepositoryFilterForScope() {
    final var repo = new MapSessionRepository(new ConcurrentHashMap<>());
    final SessionRepositoryFilter<?> filter =
        ScopedWebSessionComponents.sessionRepositoryFilter("/physical-tenants/t1", repo);
    assertThat(filter).as("a per-scope SessionRepositoryFilter must be produced").isNotNull();
  }

  @Test
  void derivesCookieNameAndPathFromBasePath() {
    final var serializer = ScopedWebSessionComponents.cookieSerializer("/physical-tenants/t1");
    assertThat(serializer).as("cookieSerializer must be non-null").isNotNull();

    final var response = new org.springframework.mock.web.MockHttpServletResponse();
    final var request = new org.springframework.mock.web.MockHttpServletRequest();
    request.setContextPath("");
    serializer.writeCookieValue(
        new org.springframework.session.web.http.CookieSerializer.CookieValue(
            request, response, "abc"));

    final var cookie = response.getCookie("camunda-session-physical-tenants-t1");
    assertThat(cookie)
        .as("cookie must be named camunda-session-<sanitize> and scoped to basePath")
        .isNotNull();
    assertThat(cookie.getPath()).isEqualTo("/physical-tenants/t1");
  }
}
