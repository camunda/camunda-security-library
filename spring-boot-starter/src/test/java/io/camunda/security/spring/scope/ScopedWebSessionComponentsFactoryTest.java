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
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.SessionRepositoryFilter;

class ScopedWebSessionComponentsFactoryTest {

  @Test
  void buildsSessionRepositoryFilterForScope() {
    final var repo = new MapSessionRepository(new ConcurrentHashMap<>());
    final SessionRepositoryFilter<?> filter =
        ScopedWebSessionComponentsFactory.sessionRepositoryFilter("/physical-tenants/t1", repo);
    assertThat(filter).as("a per-scope SessionRepositoryFilter must be produced").isNotNull();
  }

  @Test
  void derivesCookieNameAndPathFromBasePath() {
    final var serializer =
        ScopedWebSessionComponentsFactory.cookieSerializer("/physical-tenants/t1");
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

  @Test
  void trailingSlashBasePathIsNormalizedInCookiePath() {
    final var serializer =
        ScopedWebSessionComponentsFactory.cookieSerializer("/physical-tenants/t1/");

    final var response = new org.springframework.mock.web.MockHttpServletResponse();
    final var request = new org.springframework.mock.web.MockHttpServletRequest();
    request.setContextPath("");
    serializer.writeCookieValue(
        new org.springframework.session.web.http.CookieSerializer.CookieValue(
            request, response, "abc"));

    final var cookie = response.getCookie("camunda-session-physical-tenants-t1");
    assertThat(cookie).as("cookie must be set for a trailing-slash basePath").isNotNull();
    assertThat(cookie.getPath())
        .as("cookie Path must be normalized (no trailing slash)")
        .isEqualTo("/physical-tenants/t1");
  }

  @Test
  void prependsContextPathToCookiePath() {
    // given
    final CookieSerializer serializer =
        ScopedWebSessionComponentsFactory.cookieSerializer("/physical-tenants/t1");
    final var request = new MockHttpServletRequest();
    request.setContextPath("/ctx");
    final var response = new MockHttpServletResponse();

    // when
    serializer.writeCookieValue(new CookieSerializer.CookieValue(request, response, "abc"));

    // then
    final var cookie = response.getCookie("camunda-session-physical-tenants-t1");
    assertThat(cookie).as("cookie must be set").isNotNull();
    assertThat(cookie.getPath())
        .as("cookie Path must be contextPath + basePath")
        .isEqualTo("/ctx/physical-tenants/t1");
  }
}
