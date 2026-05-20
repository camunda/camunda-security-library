/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.out;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.camunda.security.api.model.auth.Groups;
import io.camunda.security.api.model.auth.MappingRules;
import io.camunda.security.api.model.auth.Memberships;
import io.camunda.security.api.model.auth.Roles;
import io.camunda.security.api.model.auth.Tenants;
import io.camunda.security.core.port.out.MembershipPort.PrincipalType;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class MembershipPortTest {

  @Test
  void portContractIsCallable() {
    final MembershipPort port = mock(MembershipPort.class);
    final var expected =
        new Memberships(
            new Groups(List.of("g1")),
            new Roles(List.of()),
            new Tenants(List.of()),
            new MappingRules(List.of()));
    when(port.resolveMemberships(Map.of("sub", "alice"), "alice", PrincipalType.USER))
        .thenReturn(expected);

    final var result = port.resolveMemberships(Map.of("sub", "alice"), "alice", PrincipalType.USER);
    assertThat(result.groups().groupIds()).containsExactly("g1");
  }
}
