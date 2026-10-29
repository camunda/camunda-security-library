/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import io.camunda.security.api.model.config.ScopedSecurityDescriptor;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.spring.oidc.ScopedOidcClients;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.util.StringUtils;

/**
 * One immutable build of a scope: its API and webapp chains and everything built for them. A scope
 * publishes a generation in one step, so a request is served by one generation, never by parts of
 * two.
 *
 * <p>A removed scope publishes a tombstone: both chains match the whole base path and answer 404,
 * so its requests fail closed rather than reaching a chain behind it.
 */
final class ScopeGeneration {

  private final long number;
  private final ScopedSecurityDescriptor descriptor;
  private final ScopeFingerprints fingerprints;
  private final SecurityFilterChain api;
  private final SecurityFilterChain webapp;
  private final ScopeObjects objects;
  private final List<ScopedOidcClients> oidcClients;
  private final Set<String> issuers;

  ScopeGeneration(
      final long number,
      final ScopedSecurityDescriptor descriptor,
      final ScopeFingerprints fingerprints,
      final SecurityFilterChain api,
      final SecurityFilterChain webapp,
      final ScopeObjects objects,
      final List<ScopedOidcClients> oidcClients) {
    this.number = number;
    this.descriptor = descriptor;
    this.fingerprints = fingerprints;
    this.api = api;
    this.webapp = webapp;
    this.objects = objects;
    this.oidcClients = List.copyOf(oidcClients);
    issuers =
        this.oidcClients.stream()
            .flatMap(clients -> clients.registrations().providers().values().stream())
            .map(OidcConfiguration::getIssuerUri)
            .filter(StringUtils::hasText)
            .collect(Collectors.toUnmodifiableSet());
  }

  static ScopeGeneration tombstone(final long number, final String basePath) {
    final var notFound =
        new DefaultSecurityFilterChain(
            PathPatternRequestMatcher.withDefaults().matcher(basePath + "/**"),
            (request, response, chain) ->
                ((HttpServletResponse) response).sendError(HttpServletResponse.SC_NOT_FOUND));
    return new ScopeGeneration(
        number, null, null, notFound, notFound, new ScopeObjects(basePath), List.of());
  }

  long number() {
    return number;
  }

  boolean isTombstone() {
    return descriptor == null;
  }

  /** The descriptor this generation was built from; {@code null} for a tombstone. */
  ScopedSecurityDescriptor descriptor() {
    return descriptor;
  }

  /** {@code null} for a tombstone. */
  ScopeFingerprints fingerprints() {
    return fingerprints;
  }

  SecurityFilterChain api() {
    return api;
  }

  SecurityFilterChain webapp() {
    return webapp;
  }

  SecurityFilterChain chain(final ScopeChainKind kind) {
    return kind == ScopeChainKind.API ? api : webapp;
  }

  ScopeObjects objects() {
    return objects;
  }

  /** The OIDC client stacks of this generation, empty for a BASIC scope or a tombstone. */
  List<ScopedOidcClients> oidcClients() {
    return oidcClients;
  }

  /** The issuer-uris its OIDC providers are configured with. */
  Set<String> issuers() {
    return issuers;
  }

  /** Releases what this generation owns once no request can reach it any more. */
  void retire() {
    objects.dispose();
  }
}
