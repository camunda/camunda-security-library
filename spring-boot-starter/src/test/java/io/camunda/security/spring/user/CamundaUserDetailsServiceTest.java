/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

import io.camunda.security.core.port.out.UserDetailsPort;
import io.camunda.security.core.port.out.UserDetailsPort.CamundaUserDetails;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@ExtendWith(MockitoExtension.class)
class CamundaUserDetailsServiceTest {

  @Mock private UserDetailsPort userDetailsPort;

  @InjectMocks private CamundaUserDetailsService service;

  @Test
  void mapsResolvedUserToSpringUserDetails() {
    when(userDetailsPort.loadUser("alice"))
        .thenReturn(new CamundaUserDetails("alice", "{noop}secret"));

    final UserDetails details = service.loadUserByUsername("alice");

    assertThat(details.getUsername()).isEqualTo("alice");
    assertThat(details.getPassword()).isEqualTo("{noop}secret");
    assertThat(details.getAuthorities()).isEmpty();
  }

  @Test
  void throwsUsernameNotFoundWhenPortReturnsNull() {
    when(userDetailsPort.loadUser("ghost")).thenReturn(null);

    assertThatThrownBy(() -> service.loadUserByUsername("ghost"))
        .isInstanceOf(UsernameNotFoundException.class)
        .hasMessageContaining("ghost");
  }

  @Test
  void throwsUsernameNotFoundOnNullUsername() {
    assertThatThrownBy(() -> service.loadUserByUsername(null))
        .isInstanceOf(UsernameNotFoundException.class);
  }

  @Test
  void throwsUsernameNotFoundOnBlankUsername() {
    assertThatThrownBy(() -> service.loadUserByUsername("   "))
        .isInstanceOf(UsernameNotFoundException.class);
  }
}
