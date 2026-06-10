/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link ScopedApiChainRegistrar#sanitizeBasePath(String)}, the helper that turns a
 * descriptor's {@code basePath} into the readable suffix of a scoped-chain bean name ({@code
 * scopedApiSecurityFilterChain-<index>-<sanitized-basePath>}).
 *
 * <p>The registrar's container behaviour — provider discovery, duplicate-basePath rejection, chain
 * registration and ordering — is exercised end-to-end by {@code ScopedApiSecurityConfigurationTest}
 * against a real {@code ApplicationContext}, which is the appropriate level for a {@code
 * BeanDefinitionRegistryPostProcessor}. These tests cover the one piece of pure, container-free
 * logic.
 */
final class ScopedApiChainRegistrarTest {

  @Test
  void returnsEmptyStringForNull() {
    assertThat(ScopedApiChainRegistrar.sanitizeBasePath(null)).isEmpty();
  }

  @Test
  void stripsTheLeadingSlash() {
    assertThat(ScopedApiChainRegistrar.sanitizeBasePath("/api")).isEqualTo("api");
  }

  @Test
  void replacesPathSeparatorsWithHyphens() {
    assertThat(ScopedApiChainRegistrar.sanitizeBasePath("/some/base/path"))
        .isEqualTo("some-base-path");
  }

  @Test
  void collapsesRunsOfNonAlphanumericCharactersToASingleHyphen() {
    assertThat(ScopedApiChainRegistrar.sanitizeBasePath("/a//b")).isEqualTo("a-b");
    assertThat(ScopedApiChainRegistrar.sanitizeBasePath("/a_b.c")).isEqualTo("a-b-c");
  }

  @Test
  void trimsLeadingAndTrailingSeparators() {
    assertThat(ScopedApiChainRegistrar.sanitizeBasePath("/api/")).isEqualTo("api");
  }

  @Test
  void stripsWildcardLikeCharacters() {
    // basePath validation already forbids ant wildcards; sanitisation is defensive regardless.
    assertThat(ScopedApiChainRegistrar.sanitizeBasePath("/scope/*")).isEqualTo("scope");
  }

  @Test
  void distinctBasePathsCanSanitiseToTheSameFragment() {
    // "/a/b" and "/a-b" both collapse to "a-b" — which is exactly why the bean name carries the
    // descriptor index as a uniqueness tiebreaker rather than relying on the sanitised path alone.
    assertThat(ScopedApiChainRegistrar.sanitizeBasePath("/a/b"))
        .isEqualTo(ScopedApiChainRegistrar.sanitizeBasePath("/a-b"))
        .isEqualTo("a-b");
  }
}
