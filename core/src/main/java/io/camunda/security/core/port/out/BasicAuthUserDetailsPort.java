/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.out;

/**
 * Outbound port the host application implements to resolve a user by username for HTTP Basic
 * authentication credential verification. The library owns the Spring Security plumbing (the {@code
 * UserDetailsService}, the {@code PasswordEncoder}, the basic-auth filter chains); the host only
 * supplies this scope-agnostic lookup.
 *
 * <p>The host resolves any tenant or scope internally (for example from the request context) — the
 * library passes <em>no</em> scope, keeping the contract dead-simple and letting hosts evolve their
 * scope resolution (e.g. per-physical-tenant) without changing this signature.
 *
 * <p>Returns {@code null} when no such user exists; the library translates that into the
 * appropriate Spring Security {@code UsernameNotFoundException}.
 */
@FunctionalInterface
public interface BasicAuthUserDetailsPort {

  /**
   * Resolves a user by username for basic-auth credential verification. The host resolves any
   * tenant/scope internally (e.g. from the request context); the library passes no scope.
   *
   * @param username the username to resolve; never blank when called by the library
   * @return the resolved user, or {@code null} when no such user exists
   */
  CamundaUserDetails loadUser(String username);

  /**
   * Framework-free user record: the username and the stored password hash the library uses to
   * verify HTTP Basic credentials.
   *
   * @param username the resolved username
   * @param password the stored (encoded) password
   */
  record CamundaUserDetails(String username, String password) {}
}
