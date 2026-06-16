/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import java.util.Set;
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
    return new SecurityPathPort() {
      @Override
      public Set<String> apiPaths() {
        return Set.of();
      }

      @Override
      public Set<String> unprotectedApiPaths() {
        return Set.of();
      }

      @Override
      public Set<String> unprotectedPaths() {
        return Set.of();
      }

      @Override
      public Set<String> webappPaths() {
        return Set.of();
      }

      @Override
      public Set<String> webComponentNames() {
        return Set.of();
      }
    };
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
