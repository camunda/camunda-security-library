/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static org.springframework.security.web.context.HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY;

import io.camunda.security.spring.oidc.FailureDescription;
import io.camunda.security.spring.oidc.ScopedClientRegistrationFactory;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.session.Session;

/**
 * Revokes the refresh token of a web session that expired, as logout does for a session the user
 * ends (ADR-0043, extending ADR-0036). The persistent session store calls {@link #revoke} for each
 * expired session it deletes: in the periodic expiry sweep, and when a request finds its session
 * expired.
 *
 * <p>Neither path has the request the session belonged to, so the token is read from the stored
 * session attributes rather than through an {@code OAuth2AuthorizedClientRepository}. Every OIDC
 * webapp chain {@link #register registers} its client registrations and its {@link
 * RefreshTokenRevoker}; the session goes to the chain that knows its registration ID with the same
 * client and token endpoint. Two scopes can use one registration ID for different providers, and
 * the stored client must never be sent to the wrong one.
 *
 * <p>The revocation request runs on one background thread with a bounded queue, so neither the
 * sweep nor a request waits on the IdP. When the queue is full, for example while the IdP is
 * unreachable, further revocations are dropped with a {@code WARN}; the session is deleted either
 * way. Every failure is fail-soft: {@link #revoke} never throws.
 */
public final class ExpiredSessionRefreshTokenRevocation implements AutoCloseable {

  /**
   * The session attribute {@link HttpSessionOAuth2AuthorizedClientRepository} keeps the authorized
   * clients in, keyed by registration ID. Spring does not expose the name, so it is repeated here.
   * {@code ExpiredSessionRefreshTokenRevocationTest} pins it against the repository's behaviour.
   */
  static final String AUTHORIZED_CLIENTS_ATTRIBUTE =
      HttpSessionOAuth2AuthorizedClientRepository.class.getName() + ".AUTHORIZED_CLIENTS";

  /** Bounds the memory and the IdP backlog when many sessions expire while the IdP is down. */
  static final int QUEUE_CAPACITY = 1_000;

  private static final Logger LOG =
      LoggerFactory.getLogger(ExpiredSessionRefreshTokenRevocation.class);

  private final List<Chain> chains = new CopyOnWriteArrayList<>();
  private final ExecutorService executor;
  private final AtomicBoolean saturated = new AtomicBoolean();

  public ExpiredSessionRefreshTokenRevocation() {
    this(defaultExecutor());
  }

  // Visible for testing: lets a test run revocations on the calling thread or reject them.
  ExpiredSessionRefreshTokenRevocation(final ExecutorService executor) {
    this.executor = Objects.requireNonNull(executor, "executor must not be null");
  }

  /**
   * Registers an OIDC webapp chain. Called once per chain while the chains are built.
   *
   * @param clientRegistrationRepository the client registrations of the chain
   * @param revoker the revoker the chain's logout handler uses
   */
  public void register(
      final ClientRegistrationRepository clientRegistrationRepository,
      final RefreshTokenRevoker revoker) {
    chains.add(
        new Chain(
            Objects.requireNonNull(
                clientRegistrationRepository, "clientRegistrationRepository must not be null"),
            Objects.requireNonNull(revoker, "revoker must not be null")));
  }

  /**
   * Schedules the revocation of the refresh token of {@code expiredSession}, if it holds one. Reads
   * the session on the calling thread, so the caller can delete it right after. Never throws.
   */
  public void revoke(final Session expiredSession) {
    try {
      scheduleRevocation(expiredSession);
    } catch (final RuntimeException e) {
      // Deliberately swallowed: deleting an expired session must not depend on revocation.
      LOG.warn(
          "Failed to read the refresh token of an expired web session [{}]. The session is still"
              + " deleted, but its refresh token may remain valid until it expires.",
          FailureDescription.describe(e));
    }
  }

  /** The number of registered chains. Exists so tests can assert the chain builder's wiring. */
  int registeredChainCount() {
    return chains.size();
  }

  @Override
  public void close() {
    executor.shutdown();
  }

  private void scheduleRevocation(final Session expiredSession) {
    if (chains.isEmpty()) {
      return;
    }
    final var authentication = oauth2Authentication(expiredSession);
    if (authentication == null) {
      return;
    }
    final String registrationId = authentication.getAuthorizedClientRegistrationId();
    final OAuth2AuthorizedClient authorizedClient =
        authorizedClient(expiredSession, registrationId);
    if (authorizedClient == null || authorizedClient.getRefreshToken() == null) {
      LOG.debug(
          "Expired web session holds no refresh token for OIDC registration '{}'. Nothing to"
              + " revoke.",
          ScopedClientRegistrationFactory.sanitizeForLog(registrationId));
      return;
    }
    try {
      executor.execute(() -> revokeThroughOwningChain(registrationId, authorizedClient));
      saturated.set(false);
    } catch (final RejectedExecutionException e) {
      // One WARN per backlog rather than one per session: a backlog means the IdP is slow or
      // down, and every session that expires meanwhile would repeat the same line.
      if (saturated.compareAndSet(false, true)) {
        LOG.warn(
            "Dropping refresh-token revocations of expired web sessions: {} are already queued,"
                + " likely because the identity provider is slow or unreachable. The sessions are"
                + " still deleted, but their refresh tokens may remain valid until they expire.",
            QUEUE_CAPACITY);
      }
    }
  }

  private void revokeThroughOwningChain(
      final String registrationId, final OAuth2AuthorizedClient authorizedClient) {
    final ClientRegistration stored = authorizedClient.getClientRegistration();
    for (final Chain chain : chains) {
      final ClientRegistration registration = registrationOf(chain, registrationId);
      if (registration != null && isSameClient(registration, stored)) {
        chain.revoker().revoke(registration, () -> authorizedClient);
        return;
      }
    }
    LOG.debug(
        "No OIDC webapp chain owns registration '{}' of an expired web session any more, so its"
            + " refresh token is not revoked.",
        ScopedClientRegistrationFactory.sanitizeForLog(registrationId));
  }

  private static ClientRegistration registrationOf(final Chain chain, final String registrationId) {
    try {
      return chain.clientRegistrationRepository().findByRegistrationId(registrationId);
    } catch (final RuntimeException e) {
      // A chain whose provider cannot be resolved right now cannot own the session either.
      LOG.debug(
          "Could not resolve OIDC registration '{}' while revoking the refresh token of an expired"
              + " web session [{}].",
          ScopedClientRegistrationFactory.sanitizeForLog(registrationId),
          FailureDescription.describe(e));
      return null;
    }
  }

  /**
   * Whether {@code registration} is the client the session logged in with: the same client ID at
   * the same token endpoint. The registration ID alone is not enough, see the class Javadoc.
   */
  private static boolean isSameClient(
      final ClientRegistration registration, final ClientRegistration stored) {
    return Objects.equals(registration.getClientId(), stored.getClientId())
        && Objects.equals(
            registration.getProviderDetails().getTokenUri(),
            stored.getProviderDetails().getTokenUri());
  }

  private static OAuth2AuthenticationToken oauth2Authentication(final Session session) {
    return session.getAttribute(SPRING_SECURITY_CONTEXT_KEY)
                instanceof final SecurityContext context
            && context.getAuthentication() instanceof final OAuth2AuthenticationToken token
        ? token
        : null;
  }

  private static OAuth2AuthorizedClient authorizedClient(
      final Session session, final String registrationId) {
    return session.getAttribute(AUTHORIZED_CLIENTS_ATTRIBUTE) instanceof final Map<?, ?> clients
            && clients.get(registrationId) instanceof final OAuth2AuthorizedClient client
        ? client
        : null;
  }

  private static ExecutorService defaultExecutor() {
    final var threadFactory =
        Thread.ofPlatform().name("camunda-session-expiry-revocation-", 0).daemon(true).factory();
    final var executor =
        new ThreadPoolExecutor(
            1,
            1,
            1,
            TimeUnit.MINUTES,
            new LinkedBlockingQueue<>(QUEUE_CAPACITY),
            threadFactory,
            new ThreadPoolExecutor.AbortPolicy());
    executor.allowCoreThreadTimeOut(true);
    return executor;
  }

  private record Chain(
      ClientRegistrationRepository clientRegistrationRepository, RefreshTokenRevoker revoker) {}
}
