/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import io.camunda.security.api.context.CamundaSecurityScopeProvider;
import io.camunda.security.api.model.config.ScopedSecurityDescriptor;
import io.camunda.security.api.model.scope.ScopeReloadOutcome;
import io.camunda.security.api.model.scope.ScopeReloadReport;
import io.camunda.security.api.model.scope.ScopeReloadResult;
import io.camunda.security.api.model.scope.UnreachableIdentityProviderPolicy;
import io.camunda.security.core.port.in.ScopedSecurityReloadPort;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;

/**
 * Changes scopes at runtime (ADR-0040): builds a scope's next generation off to the side, checks
 * it, and publishes it in one step, then releases what the previous generation owned.
 */
final class ScopedSecurityReloadService implements ScopedSecurityReloadPort {

  private static final Logger LOG = LoggerFactory.getLogger(ScopedSecurityReloadService.class);

  private final ConfigurableListableBeanFactory beanFactory;
  private final ScopeSlots slots;
  private final ScopeGenerationBuilder builder;
  private final ScopeRetirement retirement;
  private final Object reloadAllLock = new Object();

  ScopedSecurityReloadService(
      final ConfigurableListableBeanFactory beanFactory,
      final ScopeSlots slots,
      final ScopeGenerationBuilder builder,
      final ScopeRetirement retirement) {
    this.beanFactory = beanFactory;
    this.slots = slots;
    this.builder = builder;
    this.retirement = retirement;
  }

  ScopeSlots slots() {
    return slots;
  }

  /**
   * Builds and publishes the first generation of a scope contributed at startup, when its first
   * chain bean is created. Failures propagate: a scope that cannot be built at startup is a
   * configuration error.
   */
  void initializeStartupScope(final ScopeSlot slot, final ScopedSecurityDescriptor descriptor) {
    slot.lock().lock();
    try {
      if (slot.current() == null) {
        final var fingerprints = ScopeFingerprints.of(descriptor.authentication());
        slot.publish(builder.build(slot, descriptor, slot.nextNumber(), fingerprints));
      }
    } finally {
      slot.lock().unlock();
    }
  }

  @Override
  public ScopeReloadReport reloadAll() {
    synchronized (reloadAllLock) {
      final var descriptors =
          ScopedSecurityChainRegistrar.collectDescriptors(
              beanFactory, beanFactory.getBeanNamesForType(CamundaSecurityScopeProvider.class));
      ScopedSecurityChainRegistrar.rejectDuplicateBasePaths(descriptors);
      ScopedSecurityChainRegistrar.rejectCookieNameCollisions(descriptors);
      final Map<String, ScopedSecurityDescriptor> contributed = new LinkedHashMap<>();
      descriptors.forEach(d -> contributed.put(BasePaths.normalize(d.basePath(), "basePath"), d));

      final List<ScopeReloadResult> results = new ArrayList<>();
      for (final var slot : slots.all()) {
        final var current = slot.current();
        if (current != null
            && !current.isTombstone()
            && !contributed.containsKey(slot.basePath())) {
          results.add(remove(slot.basePath()));
        }
      }
      contributed
          .values()
          .forEach(
              descriptor ->
                  results.add(apply(descriptor, UnreachableIdentityProviderPolicy.KEEP_PREVIOUS)));
      return new ScopeReloadReport(results);
    }
  }

  @Override
  public ScopeReloadResult apply(final ScopedSecurityDescriptor descriptor) {
    return apply(descriptor, UnreachableIdentityProviderPolicy.KEEP_PREVIOUS);
  }

  @Override
  public ScopeReloadResult apply(
      final ScopedSecurityDescriptor descriptor, final UnreachableIdentityProviderPolicy policy) {
    final var basePath = BasePaths.normalize(descriptor.basePath(), "basePath");
    final long start = System.nanoTime();
    rejectCookieNameCollision(descriptor, basePath);
    final var slot = slots.slotFor(basePath);
    slot.lock().lock();
    try {
      final var fingerprints = ScopeFingerprints.of(descriptor.authentication());
      final var previous = live(slot);
      if (previous != null && fingerprints.sameAs(previous.fingerprints())) {
        return result(basePath, ScopeReloadOutcome.UNCHANGED, previous.number(), start, null);
      }
      final ScopeReloadOutcome outcome;
      if (previous == null) {
        outcome = ScopeReloadOutcome.ADDED;
      } else if (fingerprints.sameAuthenticationAs(previous.fingerprints())) {
        outcome = ScopeReloadOutcome.CREDENTIALS_ROTATED;
      } else {
        outcome = ScopeReloadOutcome.REPLACED;
      }
      return replace(slot, descriptor, fingerprints, outcome, policy, start);
    } finally {
      slot.lock().unlock();
    }
  }

  @Override
  public ScopeReloadResult remove(final String basePath) {
    final var normalized = BasePaths.normalize(basePath, "basePath");
    final long start = System.nanoTime();
    final var slot = slots.find(normalized);
    if (slot == null) {
      return result(normalized, ScopeReloadOutcome.ABSENT, 0, start, null);
    }
    slot.lock().lock();
    try {
      final var previous = live(slot);
      if (previous == null) {
        return result(normalized, ScopeReloadOutcome.ABSENT, 0, start, null);
      }
      slot.publish(ScopeGeneration.tombstone(slot.nextNumber(), normalized));
      slot.dropSessionFilter();
      retirement.retireRemoved(previous, normalized, slots);
      LOG.info("Scope basePath={} removed; its requests now answer 404", normalized);
      return result(normalized, ScopeReloadOutcome.REMOVED, 0, start, null);
    } finally {
      slot.lock().unlock();
    }
  }

  @Override
  public ScopeReloadResult rotateCredentials(final ScopedSecurityDescriptor descriptor) {
    final var basePath = BasePaths.normalize(descriptor.basePath(), "basePath");
    final long start = System.nanoTime();
    final var slot = requireServed(basePath);
    slot.lock().lock();
    try {
      final var previous = requireLive(slot);
      final var fingerprints = ScopeFingerprints.of(descriptor.authentication());
      if (!fingerprints.sameAuthenticationAs(previous.fingerprints())) {
        throw new IllegalArgumentException(
            "The descriptor for basePath="
                + basePath
                + " changes more than credentials; apply it instead, which ends the scope's"
                + " sessions");
      }
      if (fingerprints.sameAs(previous.fingerprints())) {
        return result(basePath, ScopeReloadOutcome.UNCHANGED, previous.number(), start, null);
      }
      return replace(
          slot,
          descriptor,
          fingerprints,
          ScopeReloadOutcome.CREDENTIALS_ROTATED,
          UnreachableIdentityProviderPolicy.KEEP_PREVIOUS,
          start);
    } finally {
      slot.lock().unlock();
    }
  }

  @Override
  public ScopeReloadResult refreshCredentials(final String basePath) {
    final var normalized = BasePaths.normalize(basePath, "basePath");
    final long start = System.nanoTime();
    final var slot = slots.find(normalized);
    if (slot == null) {
      return result(normalized, ScopeReloadOutcome.ABSENT, 0, start, null);
    }
    slot.lock().lock();
    try {
      final var previous = live(slot);
      if (previous == null) {
        return result(normalized, ScopeReloadOutcome.ABSENT, 0, start, null);
      }
      return replace(
          slot,
          previous.descriptor(),
          previous.fingerprints(),
          ScopeReloadOutcome.CREDENTIALS_REFRESHED,
          UnreachableIdentityProviderPolicy.KEEP_PREVIOUS,
          start);
    } finally {
      slot.lock().unlock();
    }
  }

  /** Builds, checks and publishes the next generation. Call with the slot's lock held. */
  private ScopeReloadResult replace(
      final ScopeSlot slot,
      final ScopedSecurityDescriptor descriptor,
      final ScopeFingerprints fingerprints,
      final ScopeReloadOutcome outcome,
      final UnreachableIdentityProviderPolicy policy,
      final long start) {
    final var basePath = slot.basePath();
    final var previous = live(slot);
    final ScopeGeneration next;
    try {
      next = builder.build(slot, descriptor, slot.nextNumber(), fingerprints);
    } catch (final RuntimeException failure) {
      LOG.error(
          "Failed to build scope basePath={}; it keeps serving {}",
          basePath,
          previous != null ? "generation " + previous.number() : "nothing",
          failure);
      return result(
          basePath,
          ScopeReloadOutcome.FAILED,
          previous != null ? previous.number() : 0,
          start,
          failure);
    }
    if (previous != null && policy == UnreachableIdentityProviderPolicy.KEEP_PREVIOUS) {
      final var unreachable = IdentityProviderCheck.unreachable(next);
      if (unreachable != null) {
        next.retire();
        LOG.warn(
            "Scope basePath={} keeps serving generation {}: {}",
            basePath,
            previous.number(),
            unreachable.getMessage());
        return result(
            basePath, ScopeReloadOutcome.KEPT_PREVIOUS, previous.number(), start, unreachable);
      }
    }
    final var replaced = slot.publish(next);
    if (replaced != null) {
      retirement.retireReplaced(replaced, next, outcome, slots);
    }
    LOG.info(
        "Scope basePath={} now serves generation {} ({})",
        basePath,
        next.number(),
        outcome.name().toLowerCase().replace('_', ' '));
    return result(basePath, outcome, next.number(), start, null);
  }

  /**
   * Rejects a descriptor whose cookie names would collide with another served scope, as the startup
   * check rejects a colliding set.
   */
  private void rejectCookieNameCollision(
      final ScopedSecurityDescriptor descriptor, final String basePath) {
    ScopedSecurityChainRegistrar.rejectCookieNameCollisions(List.of(descriptor));
    final var cookieName = ScopedSecurityChainRegistrar.sessionCookieName(basePath);
    for (final var slot : slots.all()) {
      if (slot.sessionCookieName().equals(cookieName)
          && !slot.basePath().equals(basePath)
          && live(slot) != null) {
        throw new IllegalStateException(
            "basePath="
                + basePath
                + " and the served basePath="
                + slot.basePath()
                + " sanitize to the same session cookie name "
                + cookieName);
      }
    }
  }

  private ScopeSlot requireServed(final String basePath) {
    final var slot = slots.find(basePath);
    if (slot == null || live(slot) == null) {
      throw new IllegalArgumentException("No scope is served at basePath=" + basePath);
    }
    return slot;
  }

  private static ScopeGeneration requireLive(final ScopeSlot slot) {
    final var live = live(slot);
    if (live == null) {
      throw new IllegalArgumentException("No scope is served at basePath=" + slot.basePath());
    }
    return live;
  }

  /** The slot's generation, or {@code null} when it serves none or only a tombstone. */
  private static ScopeGeneration live(final ScopeSlot slot) {
    final var current = slot.current();
    return current == null || current.isTombstone() ? null : current;
  }

  private static ScopeReloadResult result(
      final String basePath,
      final ScopeReloadOutcome outcome,
      final long generation,
      final long start,
      final RuntimeException failure) {
    return new ScopeReloadResult(
        basePath, outcome, generation, Duration.ofNanos(System.nanoTime() - start), failure);
  }
}
