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

import io.camunda.security.core.port.out.BasicAuthUserDetailsPort;
import io.camunda.security.core.port.out.BasicAuthUserDetailsPort.CamundaUserDetails;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@ExtendWith(MockitoExtension.class)
class CamundaUserDetailsServiceTest {

  @Mock private BasicAuthUserDetailsPort userDetailsPort;

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
        .isInstanceOf(UsernameNotFoundException.class);
  }

  @Test
  void doesNotEchoUsernameInNotFoundException() {
    when(userDetailsPort.loadUser("alice")).thenReturn(null);

    // The username can be PII / carry control characters — it must not leak into the exception.
    assertThatThrownBy(() -> service.loadUserByUsername("alice"))
        .isInstanceOf(UsernameNotFoundException.class)
        .hasMessageNotContaining("alice");
  }

  @Test
  void failsClosedWhenPortReturnsRecordWithNullPassword() {
    when(userDetailsPort.loadUser("alice")).thenReturn(new CamundaUserDetails("alice", null));

    assertThatThrownBy(() -> service.loadUserByUsername("alice"))
        .isInstanceOf(UsernameNotFoundException.class);
  }

  @Test
  void failsClosedWhenPortReturnsRecordWithBlankPassword() {
    // A blank password builds a User Spring accepts, but DelegatingPasswordEncoder.matches(...)
    // would then throw — so treat it as an unusable record (clean rejection, not a 500).
    when(userDetailsPort.loadUser("alice")).thenReturn(new CamundaUserDetails("alice", "  "));

    assertThatThrownBy(() -> service.loadUserByUsername("alice"))
        .isInstanceOf(UsernameNotFoundException.class);
  }

  @Test
  void failsClosedWhenPortReturnsRecordWithBlankUsername() {
    when(userDetailsPort.loadUser("alice")).thenReturn(new CamundaUserDetails("  ", "{noop}pw"));

    assertThatThrownBy(() -> service.loadUserByUsername("alice"))
        .isInstanceOf(UsernameNotFoundException.class);
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
