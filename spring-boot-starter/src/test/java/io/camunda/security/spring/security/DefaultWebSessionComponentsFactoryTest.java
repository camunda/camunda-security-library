/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.SessionRepositoryFilter;

class DefaultWebSessionComponentsFactoryTest {

  @Test
  void fallsBackToDefaultCookieNameWhenPropertyAbsent() {
    final var serializer =
        DefaultWebSessionComponentsFactory.cookieSerializer(new MockEnvironment());

    final var request = new MockHttpServletRequest();
    final var response = new MockHttpServletResponse();
    serializer.writeCookieValue(new CookieSerializer.CookieValue(request, response, "abc"));

    assertThat(response.getCookie(CamundaSecurityFilterChainConstants.SESSION_COOKIE))
        .as("must fall back to the CSL default session cookie name")
        .isNotNull();
  }

  @Test
  void honoursConfiguredCookieNameProperty() {
    final var environment = new MockEnvironment();
    environment.setProperty("server.servlet.session.cookie.name", "custom-cookie");
    final var serializer = DefaultWebSessionComponentsFactory.cookieSerializer(environment);

    final var request = new MockHttpServletRequest();
    final var response = new MockHttpServletResponse();
    serializer.writeCookieValue(new CookieSerializer.CookieValue(request, response, "abc"));

    assertThat(response.getCookie("custom-cookie"))
        .as("must honour the configured server.servlet.session.cookie.name")
        .isNotNull();
    assertThat(response.getCookie(CamundaSecurityFilterChainConstants.SESSION_COOKIE))
        .as("must not also write the default cookie name")
        .isNull();
  }

  @Test
  void defaultsToHttpOnlyAndLaxSameSiteWhenPropertiesAbsent() {
    final var serializer =
        DefaultWebSessionComponentsFactory.cookieSerializer(new MockEnvironment());

    final var request = new MockHttpServletRequest();
    final var response = new MockHttpServletResponse();
    serializer.writeCookieValue(new CookieSerializer.CookieValue(request, response, "abc"));

    final var setCookieHeader = response.getHeader("Set-Cookie");
    assertThat(setCookieHeader).contains("HttpOnly").contains("SameSite=Lax");
  }

  @Test
  void honoursConfiguredHttpOnlyProperty() {
    final var environment = new MockEnvironment();
    environment.setProperty("server.servlet.session.cookie.http-only", "false");
    final var serializer = DefaultWebSessionComponentsFactory.cookieSerializer(environment);

    final var request = new MockHttpServletRequest();
    final var response = new MockHttpServletResponse();
    serializer.writeCookieValue(new CookieSerializer.CookieValue(request, response, "abc"));

    assertThat(response.getHeader("Set-Cookie"))
        .as("must honour server.servlet.session.cookie.http-only=false")
        .doesNotContain("HttpOnly");
  }

  @Test
  void honoursConfiguredSameSiteProperty() {
    final var environment = new MockEnvironment();
    environment.setProperty("server.servlet.session.cookie.same-site", "Strict");
    final var serializer = DefaultWebSessionComponentsFactory.cookieSerializer(environment);

    final var request = new MockHttpServletRequest();
    final var response = new MockHttpServletResponse();
    serializer.writeCookieValue(new CookieSerializer.CookieValue(request, response, "abc"));

    assertThat(response.getHeader("Set-Cookie"))
        .as("must honour server.servlet.session.cookie.same-site=Strict")
        .contains("SameSite=Strict");
  }

  @Test
  void honoursConfiguredSecureProperty() {
    final var environment = new MockEnvironment();
    environment.setProperty("server.servlet.session.cookie.secure", "true");
    final var serializer = DefaultWebSessionComponentsFactory.cookieSerializer(environment);

    final var request = new MockHttpServletRequest();
    final var response = new MockHttpServletResponse();
    serializer.writeCookieValue(new CookieSerializer.CookieValue(request, response, "abc"));

    assertThat(response.getHeader("Set-Cookie"))
        .as("must honour server.servlet.session.cookie.secure=true")
        .contains("Secure");
  }

  @Test
  void buildsSessionRepositoryFilterOverTheGivenRepository() {
    final var repo = new MapSessionRepository(new ConcurrentHashMap<>());
    final SessionRepositoryFilter<?> filter =
        DefaultWebSessionComponentsFactory.sessionRepositoryFilter(new MockEnvironment(), repo);
    assertThat(filter).as("a SessionRepositoryFilter must be produced").isNotNull();
  }
}
