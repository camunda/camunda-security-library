/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.api.model.scope.ScopeReloadOutcome;
import io.camunda.security.api.model.scope.ScopeReloadResult;
import io.camunda.security.core.port.in.OidcProviderConfigurationPort;
import io.camunda.security.core.port.in.PrimaryCredentialsReloadPort;
import io.camunda.security.spring.oidc.AssertionJwkProvider;
import io.camunda.security.spring.oidc.ClientCredentialsCheck;
import io.camunda.security.spring.oidc.ClientCredentialsCheck.Verdict;
import io.camunda.security.spring.oidc.LazyClientRegistrationRepository;
import io.camunda.security.spring.oidc.OidcAuthenticationConfigurationRepository;
import io.camunda.security.spring.oidc.ScopedClientRegistrationFactory;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Rotates the OIDC client credentials of the primary chains (see {@link
 * PrimaryCredentialsReloadPort}).
 *
 * <p>Two objects hold them: the client registrations ({@link LazyClientRegistrationRepository}),
 * which carry the client secret into every login, refresh and revocation token request, and the
 * provider configurations ({@link OidcAuthenticationConfigurationRepository}), from which {@link
 * AssertionJwkProvider} reads the {@code private_key_jwt} keystore. A session's stored authorized
 * client is rebound to the current registration when it is read ({@code
 * CurrentRegistrationAuthorizedClientRepository}), so a session created before a rotation refreshes
 * with the new credentials. Decoders, validators and claim converters do not depend on credentials
 * and are not touched.
 */
final class PrimaryCredentialsReloadService implements PrimaryCredentialsReloadPort {

  static final String BASE_PATH = "/";

  private static final Logger LOG = LoggerFactory.getLogger(PrimaryCredentialsReloadService.class);

  private final LazyClientRegistrationRepository registrations;
  private final OidcAuthenticationConfigurationRepository providers;
  private final ScopedClientRegistrationFactory factory;
  private final ClientCredentialsCheck check;
  private final ReentrantLock lock = new ReentrantLock();
  private ScopeFingerprints fingerprints;
  private long generation = 1;

  PrimaryCredentialsReloadService(
      final AuthenticationConfiguration startup,
      final LazyClientRegistrationRepository registrations,
      final OidcAuthenticationConfigurationRepository providers,
      final ScopedClientRegistrationFactory factory,
      final ClientCredentialsCheck check) {
    fingerprints = ScopeFingerprints.of(startup);
    this.registrations = registrations;
    this.providers = providers;
    this.factory = factory;
    this.check = check;
  }

  @Override
  public ScopeReloadResult rotateCredentials(final AuthenticationConfiguration authentication) {
    final long start = System.nanoTime();
    lock.lock();
    try {
      final var next = ScopeFingerprints.of(authentication);
      if (!next.sameAuthenticationAs(fingerprints)) {
        throw new IllegalArgumentException(
            "The configuration changes more than the credentials of the primary chains");
      }
      if (next.sameAs(fingerprints)) {
        return result(ScopeReloadOutcome.UNCHANGED, start, null);
      }
      final var nextProviders = factory.flatten(authentication);
      final LazyClientRegistrationRepository.Prepared prepared;
      try {
        prepared = registrations.prepareCredentials(nextProviders);
      } catch (final RuntimeException e) {
        LOG.warn("The primary chains keep their OIDC credentials: {}", e.getMessage());
        return result(ScopeReloadOutcome.KEPT_PREVIOUS, start, e);
      }
      final var jwks = new AssertionJwkProvider(portOf(nextProviders));
      for (final var registration : prepared.registrations().values()) {
        final var answer = check.check(registration, r -> jwks.createJwk(r.getRegistrationId()));
        if (answer.verdict() != Verdict.ACCEPTED) {
          final var failure =
              new IllegalStateException(
                  "The identity provider of registration '%s' %s the new credentials: %s"
                      .formatted(
                          registration.getRegistrationId(),
                          answer.verdict() == Verdict.REJECTED ? "rejects" : "cannot confirm",
                          answer.detail()));
          LOG.warn("The primary chains keep their OIDC credentials: {}", failure.getMessage());
          return result(ScopeReloadOutcome.KEPT_PREVIOUS, start, failure);
        }
      }
      registrations.publishCredentials(prepared);
      providers.replaceCredentials(nextProviders);
      fingerprints = next;
      generation++;
      final var result = result(ScopeReloadOutcome.CREDENTIALS_ROTATED, start, null);
      LOG.info(
          "The primary chains now use rotated OIDC credentials (generation {}, {} ms)",
          generation,
          result.duration().toMillis());
      return result;
    } finally {
      lock.unlock();
    }
  }

  private ScopeReloadResult result(
      final ScopeReloadOutcome outcome, final long start, final RuntimeException failure) {
    return new ScopeReloadResult(
        BASE_PATH, outcome, generation, Duration.ofNanos(System.nanoTime() - start), failure);
  }

  private static OidcProviderConfigurationPort portOf(
      final Map<String, OidcConfiguration> providers) {
    return new OidcProviderConfigurationPort() {
      @Override
      public OidcConfiguration getOidcAuthenticationConfigurationById(final String id) {
        return providers.get(id);
      }

      @Override
      public Map<String, OidcConfiguration> getOidcAuthenticationConfigurations() {
        return providers;
      }
    };
  }
}
