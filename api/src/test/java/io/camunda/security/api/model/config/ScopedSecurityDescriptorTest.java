/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.camunda.security.api.context.CamundaSecurityScopeProvider;
import java.util.List;
import org.junit.jupiter.api.Test;

class ScopedSecurityDescriptorTest {

  @Test
  void nullBasePathThrows() {
    final var auth = new AuthenticationConfiguration();
    assertThatThrownBy(() -> new ScopedSecurityDescriptor(null, auth))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("basePath");
  }

  @Test
  void blankBasePathThrows() {
    final var auth = new AuthenticationConfiguration();
    assertThatThrownBy(() -> new ScopedSecurityDescriptor("  ", auth))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("basePath");
  }

  @Test
  void rootBasePathThrows() {
    final var auth = new AuthenticationConfiguration();
    assertThatThrownBy(() -> new ScopedSecurityDescriptor("/", auth))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("basePath");
  }

  @Test
  void relativeBasePathThrows() {
    final var auth = new AuthenticationConfiguration();
    assertThatThrownBy(() -> new ScopedSecurityDescriptor("my-scope", auth))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("basePath");
  }

  @Test
  void nullAuthenticationThrows() {
    assertThatThrownBy(() -> new ScopedSecurityDescriptor("/api", null))
        .isInstanceOf(NullPointerException.class)
        .hasMessageContaining("authentication");
  }

  @Test
  void wildcardBasePathThrows() {
    final var auth = new AuthenticationConfiguration();
    assertThatThrownBy(() -> new ScopedSecurityDescriptor("/scope/**", auth))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("basePath");
  }

  @Test
  void accessorsRoundTrip() {
    // given:
    final var auth = new AuthenticationConfiguration();
    final var descriptor = new ScopedSecurityDescriptor("/pt-api", auth);

    // expect:
    assertThat(descriptor.basePath()).isEqualTo("/pt-api");
    assertThat(descriptor.authentication()).isSameAs(auth);
  }

  @Test
  void recordEquality() {
    // given:
    final var auth = new AuthenticationConfiguration();
    final var a = new ScopedSecurityDescriptor("/api", auth);
    final var b = new ScopedSecurityDescriptor("/api", auth);

    // expect: records with identical components are equal
    assertThat(a).isEqualTo(b);
  }

  @Test
  void spiContractShape() {
    // Verify that an implementation of CamundaSecurityScopeProvider compiles and behaves correctly:
    // the SPI is PT-agnostic (CSL never inspects what the scope is for) and simply returns a list.
    final var auth = new AuthenticationConfiguration();
    final CamundaSecurityScopeProvider provider =
        () ->
            List.of(
                new ScopedSecurityDescriptor("/scope-a", auth),
                new ScopedSecurityDescriptor("/scope-b", auth));

    final var descriptors = provider.get();

    assertThat(descriptors).hasSize(2);
    assertThat(descriptors.get(0).basePath()).isEqualTo("/scope-a");
    assertThat(descriptors.get(1).basePath()).isEqualTo("/scope-b");
  }
}
