/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/** Unit tests for {@link SecurityFilterChainSupport}. */
final class SecurityFilterChainSupportTest {

  private static CamundaSecurityLibraryProperties csrfEnabledProperties() {
    final var props = new CamundaSecurityLibraryProperties();
    props.getCsrf().setEnabled(true);
    props.getCsrf().setCookieHttpOnly(false);
    return props;
  }

  /** Minimal stub that returns empty sets for all path groups. */
  private static SecurityPathPort emptyPathPort() {
    return StubSecurityPaths.builder()
        .apiPaths()
        .unprotectedApiPaths()
        .unprotectedPaths()
        .webappPaths()
        .webComponentNames()
        .build();
  }

  @Test
  void shouldSetCsrfCookiePathWhenCookiePathProvided() {
    // given
    final var properties = csrfEnabledProperties();
    final var cookiePath = "/physical-tenants/t1";

    // when
    final var repository =
        SecurityFilterChainSupport.cookieCsrfTokenRepository(properties, cookiePath);
    final var request = new MockHttpServletRequest();
    final var response = new MockHttpServletResponse();
    final var token = repository.generateToken(request);
    repository.saveToken(token, request, response);

    // then
    final var cookie = response.getCookie("X-CSRF-TOKEN");
    assertThat(cookie).as("CSRF cookie must be set").isNotNull();
    assertThat(cookie.getPath())
        .as("CSRF cookie must have Path=" + cookiePath)
        .isEqualTo(cookiePath);
  }

  @Test
  void shouldNotSetCookiePathWhenNullCookiePathProvided() {
    // given
    final var properties = csrfEnabledProperties();

    // when
    final var repository = SecurityFilterChainSupport.cookieCsrfTokenRepository(properties, null);
    final var request = new MockHttpServletRequest();
    final var response = new MockHttpServletResponse();
    final var token = repository.generateToken(request);
    repository.saveToken(token, request, response);

    // then
    final var cookie = response.getCookie("X-CSRF-TOKEN");
    assertThat(cookie).as("CSRF cookie must be set").isNotNull();
    // No path set — Spring uses request context path or "/" by default
    assertThat(cookie.getPath())
        .as("CSRF cookie must not have the scoped cookie path")
        .doesNotContain("/physical-tenants");
  }

  @Test
  void shouldNotSetCookiePathWhenSingleArgOverloadUsed() {
    // given
    final var properties = csrfEnabledProperties();

    // when
    final var repository = SecurityFilterChainSupport.cookieCsrfTokenRepository(properties);
    final var request = new MockHttpServletRequest();
    final var response = new MockHttpServletResponse();
    final var token = repository.generateToken(request);
    repository.saveToken(token, request, response);

    // then
    final var cookie = response.getCookie("X-CSRF-TOKEN");
    assertThat(cookie).as("CSRF cookie must be set").isNotNull();
    assertThat(cookie.getPath())
        .as("primary chain CSRF cookie must not have a scoped path")
        .doesNotContain("/physical-tenants");
  }

  @Test
  void shouldIncludePrefixedLoginAndLogoutPathsWhenCookiePathProvided() {
    // given
    final var properties = csrfEnabledProperties();
    final var pathPort = emptyPathPort();
    final var cookiePath = "/physical-tenants/t1";

    // when
    final var allowedPaths =
        SecurityFilterChainSupport.csrfAllowedPaths(properties, pathPort, cookiePath);

    // then
    assertThat(allowedPaths)
        .as("must contain unprefixed /login (primary chain compatibility)")
        .contains("/login")
        .as("must contain unprefixed /logout (primary chain compatibility)")
        .contains("/logout")
        .as("must contain scoped /physical-tenants/t1/login")
        .contains("/physical-tenants/t1/login")
        .as("must contain scoped /physical-tenants/t1/logout")
        .contains("/physical-tenants/t1/logout");
  }

  @Test
  void shouldNotIncludePrefixedPathsWhenCookiePathIsNull() {
    // given
    final var properties = csrfEnabledProperties();
    final var pathPort = emptyPathPort();

    // when
    final var allowedPaths =
        SecurityFilterChainSupport.csrfAllowedPaths(properties, pathPort, null);

    // then
    assertThat(allowedPaths)
        .as("must contain /login")
        .contains("/login")
        .as("must contain /logout")
        .contains("/logout")
        .as("must not contain any scoped login path")
        .noneMatch(p -> p.contains("/physical-tenants"));
  }

  @Test
  void shouldStripTrailingSlashFromCookiePathOnCsrfCookie() {
    // given
    final var properties = csrfEnabledProperties();
    final var cookiePath = "/physical-tenants/t1/"; // trailing slash

    // when
    final var repository =
        SecurityFilterChainSupport.cookieCsrfTokenRepository(properties, cookiePath);
    final var request = new MockHttpServletRequest();
    final var response = new MockHttpServletResponse();
    final var token = repository.generateToken(request);
    repository.saveToken(token, request, response);

    // then
    final var cookie = response.getCookie("X-CSRF-TOKEN");
    assertThat(cookie).as("CSRF cookie must be set").isNotNull();
    assertThat(cookie.getPath())
        .as("CSRF cookie Path must have trailing slash stripped")
        .isEqualTo("/physical-tenants/t1")
        .doesNotEndWith("/");
  }

  @Test
  void shouldSetCookiePathToSlashWhenRootBasePathProvided() {
    // given — root "/" is the cluster / non-PT default; cookie Path cannot be empty
    final var properties = csrfEnabledProperties();

    // when
    final var repository = SecurityFilterChainSupport.cookieCsrfTokenRepository(properties, "/");
    final var request = new MockHttpServletRequest();
    final var response = new MockHttpServletResponse();
    final var token = repository.generateToken(request);
    repository.saveToken(token, request, response);

    // then — normalize("/" ) → "" → cookie Path must be set to "/"
    final var cookie = response.getCookie("X-CSRF-TOKEN");
    assertThat(cookie).as("CSRF cookie must be set").isNotNull();
    assertThat(cookie.getPath()).as("root basePath must produce cookie Path=/").isEqualTo("/");
  }

  @Test
  void shouldIncludeUnprefixedLoginLogoutWhenRootBasePathProvided() {
    // given — root "/" normalizes to "" so prefixed paths collapse to /login and /logout
    final var properties = csrfEnabledProperties();
    final var pathPort = emptyPathPort();

    // when
    final var allowedPaths = SecurityFilterChainSupport.csrfAllowedPaths(properties, pathPort, "/");

    // then — base="" so "" + "/login" = "/login"; deduped by Set, still present
    assertThat(allowedPaths)
        .as("must contain /login")
        .contains("/login")
        .as("must contain /logout")
        .contains("/logout")
        .as("must not produce double-slash paths")
        .noneMatch(p -> p.contains("//"));
  }

  @Test
  void shouldPrependContextPathToCsrfCookiePath() {
    // given
    final var properties = csrfEnabledProperties();
    final var basePath = "/physical-tenants/t1";

    // when — wrapping happens in applyCsrfConfiguration; construct it directly here
    final var repository =
        new ContextPathScopedCsrfTokenRepository(
            SecurityFilterChainSupport.cookieCsrfTokenRepository(properties, basePath), basePath);
    final var request = new MockHttpServletRequest();
    request.setContextPath("/ctx");
    final var response = new MockHttpServletResponse();
    final var token = repository.generateToken(request);
    repository.saveToken(token, request, response);

    // then
    final var cookie = response.getCookie("X-CSRF-TOKEN");
    assertThat(cookie).as("CSRF cookie must be set").isNotNull();
    assertThat(cookie.getPath())
        .as("CSRF cookie Path must be contextPath + basePath")
        .isEqualTo("/ctx/physical-tenants/t1");
  }

  @Test
  void shouldUseScopedCookieNameWhenCookieNameIsProvided() {
    // given
    final var properties = csrfEnabledProperties();
    final var cookiePath = "/physical-tenants/t1";
    final var cookieName = "camunda-csrf-physical-tenants-t1";

    // when
    final var repository =
        SecurityFilterChainSupport.cookieCsrfTokenRepository(properties, cookiePath, cookieName);
    final var request = new MockHttpServletRequest();
    final var response = new MockHttpServletResponse();
    final var token = repository.generateToken(request);
    repository.saveToken(token, request, response);

    // then
    assertThat(response.getCookie("X-CSRF-TOKEN"))
        .as("no cookie named X-CSRF-TOKEN must be present for a scoped chain")
        .isNull();
    final var cookie = response.getCookie(cookieName);
    assertThat(cookie).as("scoped CSRF cookie must be set with the per-scope name").isNotNull();
    assertThat(cookie.getPath())
        .as("scoped CSRF cookie must still have the scoped path")
        .isEqualTo(cookiePath);
  }

  @Test
  void primaryChainCookieNameRemainsXCsrfToken() {
    // given
    final var properties = csrfEnabledProperties();

    // when
    final var repository = SecurityFilterChainSupport.cookieCsrfTokenRepository(properties);
    final var request = new MockHttpServletRequest();
    final var response = new MockHttpServletResponse();
    final var token = repository.generateToken(request);
    repository.saveToken(token, request, response);

    // then
    assertThat(response.getCookie("X-CSRF-TOKEN"))
        .as("primary chain must still use the X-CSRF-TOKEN cookie name")
        .isNotNull();
  }

  @Test
  void cookieCsrfTokenRepositoryRejectsNullCookieName() {
    final var properties = csrfEnabledProperties();
    assertThatNullPointerException()
        .isThrownBy(
            () -> SecurityFilterChainSupport.cookieCsrfTokenRepository(properties, null, null))
        .withMessageContaining("cookieName");
  }

  @Test
  void cookieCsrfTokenRepositoryRejectsBlankCookieName() {
    final var properties = csrfEnabledProperties();
    assertThatIllegalArgumentException()
        .isThrownBy(
            () -> SecurityFilterChainSupport.cookieCsrfTokenRepository(properties, null, "   "))
        .withMessageContaining("cookieName");
  }

  @Test
  void shouldStripTrailingSlashFromCookiePathBeforeComputingPrefixedPaths() {
    // given
    final var properties = csrfEnabledProperties();
    final var pathPort = emptyPathPort();
    final var cookiePath = "/physical-tenants/t1/"; // trailing slash

    // when
    final var allowedPaths =
        SecurityFilterChainSupport.csrfAllowedPaths(properties, pathPort, cookiePath);

    // then
    assertThat(allowedPaths)
        .as("must contain /physical-tenants/t1/login without double slash")
        .contains("/physical-tenants/t1/login")
        .as("must contain /physical-tenants/t1/logout without double slash")
        .contains("/physical-tenants/t1/logout")
        .as("must not contain a double-slash path")
        .noneMatch(p -> p.contains("//"));
  }
}
