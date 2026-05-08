/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.out;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Set;
import org.junit.jupiter.api.Test;

class SecurityPathPortTest {

  /**
   * A minimal {@link SecurityPathPort} that only declares the required methods, leaving every
   * default in place. Exercises the {@code default} contract so that hosts implementing the port
   * before the library introduced new optional methods stay source- and binary-compatible.
   */
  private static final SecurityPathPort MINIMAL =
      new SecurityPathPort() {
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

  @Test
  void adminFilterBypassPathsDefaultsToEmpty() {
    assertThat(MINIMAL.adminFilterBypassPaths()).isEmpty();
  }
}
