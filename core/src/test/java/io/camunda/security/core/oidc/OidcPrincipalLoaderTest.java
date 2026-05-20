/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.oidc;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;

class OidcPrincipalLoaderTest {

  @Test
  void loadsUsernameFromSimpleClaim() {
    final var loader = new OidcPrincipalLoader("sub", "azp");
    final var principals = loader.load(Map.of("sub", "alice", "azp", "client-1"));
    assertThat(principals.username()).isEqualTo("alice");
    assertThat(principals.clientId()).isEqualTo("client-1");
  }

  @Test
  void returnsNullWhenClaimAbsent() {
    final var loader = new OidcPrincipalLoader("sub", "azp");
    final var principals = loader.load(Map.of("other", "value"));
    assertThat(principals.username()).isNull();
    assertThat(principals.clientId()).isNull();
  }

  @Test
  void supportsJsonPathExpression() {
    final var loader = new OidcPrincipalLoader("$.realm_access.user", null);
    final var principals = loader.load(Map.of("realm_access", Map.of("user", "bob")));
    assertThat(principals.username()).isEqualTo("bob");
  }

  @Test
  void nullClaimProducesNullLoader() {
    final var loader = new OidcPrincipalLoader(null, null);
    final var principals = loader.load(Map.of("sub", "alice"));
    assertThat(principals.username()).isNull();
    assertThat(principals.clientId()).isNull();
  }
}
