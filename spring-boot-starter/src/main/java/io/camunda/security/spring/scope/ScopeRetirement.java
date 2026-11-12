/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import io.camunda.security.api.model.scope.ScopeReloadOutcome;
import io.camunda.security.spring.converter.OidcUserAuthenticationConverter;
import io.camunda.security.spring.oidc.ScopedClientRegistrationFactory;
import io.camunda.security.spring.session.ScopedWebSessionRepositoryFactory;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

/**
 * Releases what a generation leaves behind once it is no longer published: the objects it owns, and
 * the entries application-wide caches hold for it — the discovery documents of issuers no served
 * scope uses any more, and the session access-token decoders of its registrations.
 */
final class ScopeRetirement {

  private final ConfigurableListableBeanFactory beanFactory;

  ScopeRetirement(final ConfigurableListableBeanFactory beanFactory) {
    this.beanFactory = beanFactory;
  }

  /**
   * Retires a generation replaced by {@code next}. A credential change keeps the decoders: a
   * session's registration keeps its issuer, keys and audiences.
   */
  void retireReplaced(
      final ScopeGeneration replaced,
      final ScopeGeneration next,
      final ScopeReloadOutcome outcome,
      final ScopeSlots slots) {
    replaced.retire();
    if (replaced.isTombstone()) {
      return;
    }
    evictUnusedDiscovery(replaced, slots);
    if (outcome == ScopeReloadOutcome.REPLACED) {
      evictDecoders(replaced);
    }
  }

  /** Retires the last generation of a removed scope. */
  void retireRemoved(final ScopeGeneration removed, final String basePath, final ScopeSlots slots) {
    removed.retire();
    beanFactory
        .getBeanProvider(ScopedWebSessionRepositoryFactory.class)
        .ifAvailable(repositories -> repositories.evict(basePath));
    evictUnusedDiscovery(removed, slots);
    evictDecoders(removed);
  }

  private void evictUnusedDiscovery(final ScopeGeneration retired, final ScopeSlots slots) {
    final var factory =
        beanFactory.getBeanProvider(ScopedClientRegistrationFactory.class).getIfAvailable();
    if (factory == null || retired.issuers().isEmpty()) {
      return;
    }
    final Set<String> unused = new HashSet<>(retired.issuers());
    for (final var slot : slots.all()) {
      final var current = slot.current();
      if (current != null) {
        unused.removeAll(current.issuers());
      }
    }
    beanFactory
        .getBeanProvider(PrimaryChains.class)
        .ifAvailable(primary -> unused.removeAll(primary.issuersInUse()));
    factory.evictDiscovery(unused);
  }

  private void evictDecoders(final ScopeGeneration retired) {
    final List<ClientRegistration> registrations =
        retired.oidcClients().stream()
            .flatMap(clients -> clients.registrations().resolvedRegistrations().stream())
            .toList();
    if (registrations.isEmpty()) {
      return;
    }
    beanFactory
        .getBeanProvider(OidcUserAuthenticationConverter.class)
        .forEach(converter -> converter.evictDecoders(registrations));
  }
}
