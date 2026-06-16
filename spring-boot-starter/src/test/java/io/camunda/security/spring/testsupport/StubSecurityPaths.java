/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.testsupport;

import io.camunda.security.core.port.out.SecurityPathPort;
import java.util.Set;

/**
 * Test builder that produces a {@link SecurityPathPort} with sensible defaults, overridable
 * per-field. The defaults match the most common stub used across the scoped-chain tests.
 *
 * <p>Call {@link #builder()}, override only fields that differ from the defaults, then {@link
 * Builder#build()}.
 */
public final class StubSecurityPaths {

  private StubSecurityPaths() {}

  public static Builder builder() {
    return new Builder();
  }

  public static final class Builder {
    private Set<String> apiPaths = Set.of("/api/**");
    private Set<String> unprotectedApiPaths = Set.of();
    private Set<String> unprotectedPaths = Set.of("/error");
    private Set<String> webappPaths = Set.of("/operate/**", "/login", "/logout");
    private Set<String> webComponentNames = Set.of("operate");

    public Builder apiPaths(final String... v) {
      this.apiPaths = Set.of(v);
      return this;
    }

    public Builder unprotectedApiPaths(final String... v) {
      this.unprotectedApiPaths = Set.of(v);
      return this;
    }

    public Builder unprotectedPaths(final String... v) {
      this.unprotectedPaths = Set.of(v);
      return this;
    }

    public Builder webappPaths(final String... v) {
      this.webappPaths = Set.of(v);
      return this;
    }

    public Builder webComponentNames(final String... v) {
      this.webComponentNames = Set.of(v);
      return this;
    }

    public SecurityPathPort build() {
      final Set<String> finalApiPaths = apiPaths;
      final Set<String> finalUnprotectedApiPaths = unprotectedApiPaths;
      final Set<String> finalUnprotectedPaths = unprotectedPaths;
      final Set<String> finalWebappPaths = webappPaths;
      final Set<String> finalWebComponentNames = webComponentNames;
      return new SecurityPathPort() {
        @Override
        public Set<String> apiPaths() {
          return finalApiPaths;
        }

        @Override
        public Set<String> unprotectedApiPaths() {
          return finalUnprotectedApiPaths;
        }

        @Override
        public Set<String> unprotectedPaths() {
          return finalUnprotectedPaths;
        }

        @Override
        public Set<String> webappPaths() {
          return finalWebappPaths;
        }

        @Override
        public Set<String> webComponentNames() {
          return finalWebComponentNames;
        }
      };
    }
  }
}
