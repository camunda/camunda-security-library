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
import io.camunda.security.spring.oidc.LazyClientRegistrationRepository;
import io.camunda.security.spring.oidc.ScopedClientRegistrationFactory;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Predicate;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.session.Session;
import org.springframework.util.StringUtils;

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
 * the stored client must never be sent to the wrong one. A chain whose configuration names another
 * client is skipped before its registration is looked up, so an unrelated provider that is down
 * cannot slow the revocation. When several chains own the client but disagree on revocation, for
 * example one scope opts out, the token is not revoked: the session does not say which scope it
 * came from, and an opt-out must hold.
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
  private final Set<String> ambiguousRegistrationIds = ConcurrentHashMap.newKeySet();
  private final Set<String> unresolvedRegistrationIds = ConcurrentHashMap.newKeySet();

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
    final Optional<List<Owner>> possibleOwners =
        owners(registrationId, authorizedClient.getClientRegistration());
    if (possibleOwners.isEmpty()) {
      return;
    }
    // Resolved again: the next failure to resolve it warns again.
    unresolvedRegistrationIds.remove(registrationId);
    final List<Owner> owners = possibleOwners.get();
    if (owners.isEmpty()) {
      LOG.debug(
          "No OIDC webapp chain owns registration '{}' of an expired web session any more, so its"
              + " refresh token is not revoked.",
          ScopedClientRegistrationFactory.sanitizeForLog(registrationId));
      return;
    }
    if (!haveSameRevocationEndpoint(owners)) {
      // One WARN per registration: the configuration stays ambiguous until it is changed.
      if (ambiguousRegistrationIds.add(registrationId)) {
        LOG.warn(
            "OIDC registration '{}' belongs to several webapp chains with different refresh-token"
                + " revocation settings, so the refresh tokens of its expired web sessions are not"
                + " revoked. Give the scopes the same revocation settings to revoke them.",
            ScopedClientRegistrationFactory.sanitizeForLog(registrationId));
      }
      return;
    }
    final Owner owner = owningChainOfTheSession(owners, authorizedClient.getClientRegistration());
    owner.chain().revoker().revoke(owner.registration(), () -> authorizedClient);
  }

  /** The chains that own the stored client, or empty when one that may own it fails to resolve. */
  private Optional<List<Owner>> owners(
      final String registrationId, final ClientRegistration stored) {
    final List<Owner> owners = new ArrayList<>();
    for (final Chain chain : chains) {
      if (!isConfiguredForClient(chain, registrationId, stored)) {
        continue;
      }
      final ClientRegistration registration;
      try {
        registration = chain.clientRegistrationRepository().findByRegistrationId(registrationId);
      } catch (final RuntimeException e) {
        // The revocation settings of this chain are unknown, and revoking through another chain
        // could ignore an opt-out of this one. One WARN per outage of a registration rather than
        // one per session; the rest go to DEBUG.
        if (unresolvedRegistrationIds.add(registrationId)) {
          LOG.warn(
              "Could not resolve OIDC registration '{}', so the refresh tokens of expired web"
                  + " sessions are not revoked until it resolves again. They may remain valid"
                  + " until they expire [{}].",
              ScopedClientRegistrationFactory.sanitizeForLog(registrationId),
              FailureDescription.describe(e));
        } else {
          LOG.debug(
              "Could not resolve OIDC registration '{}', so the refresh token of an expired web"
                  + " session is not revoked [{}].",
              ScopedClientRegistrationFactory.sanitizeForLog(registrationId),
              FailureDescription.describe(e));
        }
        return Optional.empty();
      }
      if (registration != null && isSameClient(registration, stored)) {
        owners.add(new Owner(chain, registration));
      }
    }
    return Optional.of(owners);
  }

  /**
   * The owner to revoke through. Two chains of one client can use different client authentication,
   * and a chain can lack the signing key its method needs, so the owners are tried in this order:
   * one that can authenticate the way the session's own chain did, one that can authenticate at
   * all, one with the session's method, and the first.
   */
  private static Owner owningChainOfTheSession(
      final List<Owner> owners, final ClientRegistration stored) {
    final Predicate<Owner> canAuthenticate =
        owner -> owner.chain().revoker().canAuthenticate(owner.registration());
    final Predicate<Owner> sameMethod =
        owner ->
            Objects.equals(
                owner.registration().getClientAuthenticationMethod(),
                stored.getClientAuthenticationMethod());
    return Stream.of(canAuthenticate.and(sameMethod), canAuthenticate, sameMethod)
        .flatMap(preference -> owners.stream().filter(preference).limit(1))
        .findFirst()
        .orElse(owners.getFirst());
  }

  private static boolean haveSameRevocationEndpoint(final List<Owner> owners) {
    final String first = RefreshTokenRevoker.revocationEndpoint(owners.getFirst().registration());
    return owners.stream()
        .allMatch(
            owner ->
                Objects.equals(
                    first, RefreshTokenRevoker.revocationEndpoint(owner.registration())));
  }

  /**
   * Whether the configuration of the chain can own the stored client, read without discovery: the
   * same client ID, and the same issuer or token endpoint where the configuration sets them and the
   * session records them. Only a {@link LazyClientRegistrationRepository} exposes its
   * configuration; any other repository is looked up.
   */
  private static boolean isConfiguredForClient(
      final Chain chain, final String registrationId, final ClientRegistration stored) {
    if (!(chain.clientRegistrationRepository()
        instanceof final LazyClientRegistrationRepository lazy)) {
      return true;
    }
    final var config = lazy.providers().get(registrationId);
    if (config == null) {
      return false;
    }
    final var provider = stored.getProviderDetails();
    return matchesIfConfigured(config.getClientId(), stored.getClientId())
        && matchesIfConfigured(config.getTokenUri(), provider.getTokenUri())
        // A session stored before the provider switched to issuer discovery has no issuer; the
        // client ID and token endpoint still decide after the lookup.
        && (provider.getIssuerUri() == null
            || matchesIfConfigured(
                withoutTrailingSlash(config.getIssuerUri()),
                withoutTrailingSlash(provider.getIssuerUri())));
  }

  /** A value the configuration leaves unset matches anything; a set one must be equal. */
  private static boolean matchesIfConfigured(final String configured, final String stored) {
    return !StringUtils.hasText(configured) || configured.equals(stored);
  }

  private static String withoutTrailingSlash(final String uri) {
    return uri != null && uri.endsWith("/") ? uri.substring(0, uri.length() - 1) : uri;
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

  private record Owner(Chain chain, ClientRegistration registration) {}
}
