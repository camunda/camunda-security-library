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
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;

/**
 * Regression coverage for a bypass a reviewer flagged on the PR implementing ADR-0027
 * (camunda/security-testing-findings#281): {@code BaseSecurityConfiguration}'s always-first,
 * CSRF-disabled unprotected-paths chain is driven entirely by the host-supplied {@code
 * SecurityPathPort#unprotectedPaths()}. If a host ever declared a pattern overlapping the login
 * endpoint there, {@code FilterChainProxy} would route {@code /login} to that chain and never reach
 * the webapp chain that enforces CSRF on it, silently defeating the "unconditional" guarantee.
 * {@code BaseSecurityConfiguration} now fails fast at startup instead.
 */
class BaseSecurityConfigurationLoginOverlapTest {

  private final WebApplicationContextRunner runner =
      new WebApplicationContextRunner()
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class, BaseSecurityConfiguration.class));

  @Test
  void startsNormallyWhenUnprotectedPathsDoNotOverlapLogin() {
    runner
        .withBean(
            SecurityPathPort.class,
            () -> StubSecurityPaths.builder().unprotectedPaths("/error", "/logs/**").build())
        .run(ctx -> assertThat(ctx).hasNotFailed().hasBean("unprotectedPathsSecurityFilterChain"));
  }

  @Test
  void rejectsUnprotectedPathThatExactlyMatchesLogin() {
    runner
        .withBean(
            SecurityPathPort.class,
            () -> StubSecurityPaths.builder().unprotectedPaths("/login").build())
        .run(
            ctx ->
                assertThat(ctx)
                    .hasFailed()
                    .getFailure()
                    .rootCause()
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("/login"));
  }

  @Test
  void rejectsUnprotectedPathThatMatchesLoginViaWildcard() {
    runner
        .withBean(
            SecurityPathPort.class,
            () -> StubSecurityPaths.builder().unprotectedPaths("/log*").build())
        .run(
            ctx ->
                assertThat(ctx)
                    .hasFailed()
                    .getFailure()
                    .rootCause()
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("/log*"));
  }
}
