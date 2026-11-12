/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.AuthenticationMethod;
import io.camunda.security.api.model.scope.ScopeReloadOutcome;
import io.camunda.security.api.model.scope.ScopeReloadResult;
import io.camunda.security.api.model.scope.UnreachableIdentityProviderPolicy;
import io.camunda.security.core.port.in.PrimarySecurityReloadPort;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.oidc.ClientCredentialsCheck;
import io.camunda.security.spring.oidc.ClientCredentialsCheck.Verdict;
import io.camunda.security.spring.oidc.ScopedClientRegistrationFactory;
import io.camunda.security.spring.oidc.ScopedJwtDecoderFactory;
import io.camunda.security.spring.oidc.ScopedOidcClients;
import io.camunda.security.spring.security.ScopedWebappSecurityChainBuilder;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;

/**
 * Changes the primary chains at runtime (see {@link PrimarySecurityReloadPort}) the way {@link
 * ScopedSecurityReloadService} changes a scope: builds the next generation off to the side, checks
 * it, publishes it in one step, then releases what the previous generation owned.
 */
final class PrimarySecurityReloadService implements PrimarySecurityReloadPort {

  private static final Logger LOG = LoggerFactory.getLogger(PrimarySecurityReloadService.class);
  private static final String DESCRIPTION = "the primary chains";
  private static final SecurityFilterChain NONE = new DefaultSecurityFilterChain(request -> false);

  private final ConfigurableListableBeanFactory beanFactory;
  private final PrimaryChains primary;
  private final ScopeRetirement retirement;
  private final ClientCredentialsCheck credentialsCheck;

  PrimarySecurityReloadService(
      final ConfigurableListableBeanFactory beanFactory,
      final PrimaryChains primary,
      final ScopeRetirement retirement,
      final ClientCredentialsCheck credentialsCheck) {
    this.beanFactory = beanFactory;
    this.primary = primary;
    this.retirement = retirement;
    this.credentialsCheck = credentialsCheck;
  }

  @Override
  public ScopeReloadResult apply(final AuthenticationConfiguration authentication) {
    return apply(authentication, UnreachableIdentityProviderPolicy.KEEP_PREVIOUS);
  }

  @Override
  public ScopeReloadResult apply(
      final AuthenticationConfiguration authentication,
      final UnreachableIdentityProviderPolicy policy) {
    final long start = System.nanoTime();
    requireChangeable(authentication);
    primary.lock().lock();
    try {
      final var fingerprints = ScopeFingerprints.of(authentication);
      final var previous = primary.fingerprints();
      if (fingerprints.sameAs(previous)) {
        return result(ScopeReloadOutcome.UNCHANGED, primary.currentNumber(), start, null);
      }
      final var outcome =
          fingerprints.sameAuthenticationAs(previous)
              ? ScopeReloadOutcome.CREDENTIALS_ROTATED
              : ScopeReloadOutcome.REPLACED;
      return replace(authentication, fingerprints, outcome, policy, start);
    } finally {
      primary.lock().unlock();
    }
  }

  @Override
  public ScopeReloadResult rotateCredentials(final AuthenticationConfiguration authentication) {
    final long start = System.nanoTime();
    requireChangeable(authentication);
    primary.lock().lock();
    try {
      final var fingerprints = ScopeFingerprints.of(authentication);
      if (!fingerprints.sameAuthenticationAs(primary.fingerprints())) {
        throw new IllegalArgumentException(
            "The configuration changes more than the credentials of the primary chains; apply it"
                + " instead, which ends their sessions");
      }
      if (fingerprints.sameAs(primary.fingerprints())) {
        return result(ScopeReloadOutcome.UNCHANGED, primary.currentNumber(), start, null);
      }
      return replace(
          authentication,
          fingerprints,
          ScopeReloadOutcome.CREDENTIALS_ROTATED,
          UnreachableIdentityProviderPolicy.KEEP_PREVIOUS,
          start);
    } finally {
      primary.lock().unlock();
    }
  }

  @Override
  public ScopeReloadResult refreshCredentials() {
    final long start = System.nanoTime();
    primary.lock().lock();
    try {
      return replace(
          primary.authentication(),
          primary.fingerprints(),
          ScopeReloadOutcome.CREDENTIALS_REFRESHED,
          UnreachableIdentityProviderPolicy.KEEP_PREVIOUS,
          start);
    } finally {
      primary.lock().unlock();
    }
  }

  /** Builds, checks and publishes the next generation. Call with the lock held. */
  private ScopeReloadResult replace(
      final AuthenticationConfiguration authentication,
      final ScopeFingerprints fingerprints,
      final ScopeReloadOutcome outcome,
      final UnreachableIdentityProviderPolicy policy,
      final long start) {
    final var serving = primary.currentNumber();
    final ScopeGeneration next;
    try {
      next = build(authentication, primary.nextNumber(), fingerprints);
    } catch (final RuntimeException failure) {
      LOG.error("Failed to build {}; generation {} keeps serving", DESCRIPTION, serving, failure);
      return result(ScopeReloadOutcome.FAILED, serving, start, failure);
    }
    if (policy == UnreachableIdentityProviderPolicy.KEEP_PREVIOUS) {
      var kept = IdentityProviderCheck.unreachable(next);
      if (kept == null && outcome == ScopeReloadOutcome.CREDENTIALS_ROTATED) {
        kept = rejectedCredentials(next);
      }
      if (kept != null) {
        next.retire();
        LOG.warn("{} keep serving generation {}: {}", DESCRIPTION, serving, kept.getMessage());
        return result(ScopeReloadOutcome.KEPT_PREVIOUS, serving, start, kept);
      }
    }
    final var replaced = primary.publish(next);
    if (replaced != null) {
      retirement.retireReplaced(replaced, next, outcome, scopeSlots());
    }
    LOG.info(
        "{} now serve generation {} ({})",
        DESCRIPTION,
        next.number(),
        outcome.name().toLowerCase().replace('_', ' '));
    return result(outcome, next.number(), start, null);
  }

  /**
   * Asks the identity provider whether it accepts the credentials of every login registration of
   * {@code next}; {@code null} when it does.
   */
  private IllegalStateException rejectedCredentials(final ScopeGeneration next) {
    for (final var clients : next.oidcClients()) {
      final var registrations = clients.registrations();
      for (final var registrationId : registrations.registrationIds()) {
        final var registration = registrations.findByRegistrationId(registrationId);
        final var answer = credentialsCheck.check(registration, clients.assertionJwks());
        if (answer.verdict() != Verdict.ACCEPTED) {
          return new IllegalStateException(
              "The identity provider of registration '%s' %s the new credentials: %s"
                  .formatted(
                      registrationId,
                      answer.verdict() == Verdict.REJECTED ? "rejects" : "cannot confirm",
                      answer.detail()));
        }
      }
    }
    return null;
  }

  private ScopeGeneration build(
      final AuthenticationConfiguration authentication,
      final long number,
      final ScopeFingerprints fingerprints) {
    final var objects = new ScopeObjects(PrimaryChains.BASE_PATH);
    final List<ScopedOidcClients> oidcClients = new ArrayList<>();
    try {
      final var chains =
          ScopeCapturingObjectPostProcessor.capturing(
              objects,
              () -> {
                final var marker =
                    new ScopeGenerationMarkerFilter(
                        PrimaryChains.MARKER_KEY, number, fingerprints.authentication());
                final var clients = clients(authentication);
                oidcClients.add(clients);
                return new SecurityFilterChain[] {
                  primary.serves(ScopeChainKind.API)
                      ? apiChain(authentication, clients, marker)
                      : NONE,
                  primary.serves(ScopeChainKind.WEBAPP)
                      ? webappChain(authentication, clients, marker)
                      : NONE
                };
              });
      initializeSingletons(objects);
      return new ScopeGeneration(
          number, authentication, fingerprints, chains[0], chains[1], objects, oidcClients);
    } catch (final RuntimeException failure) {
      objects.dispose();
      throw failure;
    }
  }

  private ScopedOidcClients clients(final AuthenticationConfiguration authentication) {
    final var registrationFactory = beanFactory.getBean(ScopedClientRegistrationFactory.class);
    final var providers = registrationFactory.flatten(authentication);
    if (providers.isEmpty()) {
      throw new IllegalStateException(
          "The configuration of " + DESCRIPTION + " declares no OIDC provider");
    }
    final var managerFactory = beanFactory.getBean(OAuth2AuthorizedClientManagerFactory.class);
    return primary.serves(ScopeChainKind.WEBAPP)
        ? ScopedOidcClients.forLogin(
            registrationFactory, providers, null, DESCRIPTION, managerFactory)
        : ScopedOidcClients.withoutLoginRoutes(
            registrationFactory, providers, DESCRIPTION, managerFactory);
  }

  private SecurityFilterChain apiChain(
      final AuthenticationConfiguration authentication,
      final ScopedOidcClients clients,
      final ScopeGenerationMarkerFilter marker) {
    try {
      final var pathPort = beanFactory.getBean(SecurityPathPort.class);
      final var decoder =
          beanFactory
              .getBean(ScopedJwtDecoderFactory.class)
              .buildIssuerAwareDecoder(authentication, DESCRIPTION);
      return beanFactory
          .getBean(ScopedApiSecurityChainBuilder.class)
          .buildOidcApiChain(
              httpSecurity(marker),
              pathPort.apiPaths(),
              pathPort.unprotectedApiPaths(),
              decoder,
              null,
              primary.sessionFilter(),
              primary.serves(ScopeChainKind.WEBAPP)
                  ? ApiTokenRefreshSupport.forPrimaryChain(
                      clients.authorizedClients(), clients.authorizedClientManager())
                  : null);
    } catch (final IllegalStateException e) {
      throw e;
    } catch (final Exception e) {
      throw new IllegalStateException("Failed to build the primary API chain", e);
    }
  }

  private SecurityFilterChain webappChain(
      final AuthenticationConfiguration authentication,
      final ScopedOidcClients clients,
      final ScopeGenerationMarkerFilter marker) {
    try {
      return beanFactory
          .getBean(ScopedWebappSecurityChainBuilder.class)
          .buildOidcWebappChain(
              httpSecurity(marker), authentication, clients, primary.sessionFilter());
    } catch (final IllegalStateException e) {
      throw e;
    } catch (final Exception e) {
      throw new IllegalStateException("Failed to build the primary webapp chain", e);
    }
  }

  private HttpSecurity httpSecurity(final ScopeGenerationMarkerFilter marker) {
    final var http = beanFactory.getBean(HttpSecurity.class);
    http.addFilterBefore(marker, SecurityContextHolderFilter.class);
    return http;
  }

  private void initializeSingletons(final ScopeObjects objects) {
    final var name = ScopeObjectPostProcessorInstaller.SHARED_PROCESSOR_BEAN_NAME;
    if (beanFactory.containsBean(name)
        && beanFactory.getBean(name) instanceof final ScopeCapturingObjectPostProcessor capturing) {
      capturing.initialize(objects);
    }
  }

  private ScopeSlots scopeSlots() {
    final var scoped =
        beanFactory.getBeanProvider(ScopedSecurityReloadService.class).getIfAvailable();
    return scoped != null ? scoped.slots() : new ScopeSlots();
  }

  private void requireChangeable(final AuthenticationConfiguration authentication) {
    Objects.requireNonNull(authentication, "authentication must not be null");
    final var startupMethod = primary.authentication().getMethod();
    if (authentication.getMethod() != startupMethod) {
      throw new IllegalArgumentException(
          "The authentication method of the primary chains is "
              + startupMethod
              + " and cannot change at runtime");
    }
    if (startupMethod != AuthenticationMethod.OIDC) {
      throw new IllegalArgumentException(
          "Only OIDC primary chains change at runtime, these use " + startupMethod);
    }
    if (!primary.serves(ScopeChainKind.API) && !primary.serves(ScopeChainKind.WEBAPP)) {
      throw new IllegalStateException("No primary OIDC chain is registered");
    }
  }

  private static ScopeReloadResult result(
      final ScopeReloadOutcome outcome,
      final long generation,
      final long start,
      final RuntimeException failure) {
    return new ScopeReloadResult(
        PrimaryChains.BASE_PATH,
        outcome,
        generation,
        Duration.ofNanos(System.nanoTime() - start),
        failure);
  }
}
