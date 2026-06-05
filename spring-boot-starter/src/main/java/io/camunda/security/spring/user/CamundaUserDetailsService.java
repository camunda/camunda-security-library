/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.user;

import io.camunda.security.core.port.out.UserDetailsPort;
import io.camunda.security.core.port.out.UserDetailsPort.CamundaUserDetails;
import java.util.Collections;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * CSL-default Spring Security {@link UserDetailsService} backing the HTTP Basic authentication
 * chains. It delegates user resolution to the host-supplied {@link UserDetailsPort} and maps the
 * framework-free {@link CamundaUserDetails} record onto Spring Security's {@link User}.
 *
 * <p>Authorities are intentionally empty: CSL performs authorization separately (via its
 * authorization ports), so basic-auth here only verifies credentials and establishes identity.
 */
public final class CamundaUserDetailsService implements UserDetailsService {

  private static final Logger LOG = LoggerFactory.getLogger(CamundaUserDetailsService.class);

  private final UserDetailsPort userDetailsPort;

  public CamundaUserDetailsService(final UserDetailsPort userDetailsPort) {
    this.userDetailsPort = userDetailsPort;
  }

  @Override
  public UserDetails loadUserByUsername(final String username) {
    if (username == null || username.isBlank()) {
      throw new UsernameNotFoundException("Username must not be null or blank");
    }

    final CamundaUserDetails user = userDetailsPort.loadUser(username);
    if (user == null
        || user.username() == null
        || user.username().isBlank()
        || user.password() == null) {
      // Fail closed: a missing user — or an adapter that returned an incomplete record — is an
      // authentication failure, not an internal error (an invalid record would otherwise make
      // User.withUsername(...)/.password(...) throw IllegalArgumentException). The username is not
      // echoed: it can be PII and may carry control characters (log forging).
      LOG.debug("Basic-auth user resolution did not yield a usable account");
      throw new UsernameNotFoundException("User not found");
    }

    return User.withUsername(user.username())
        .password(user.password())
        .authorities(Collections.emptyList())
        .build();
  }
}
