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
import io.camunda.security.spring.oidc.UrlRedaction;
import java.time.Duration;
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
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.session.Session;
import org.springframework.util.StringUtils;

/**
 * Revokes the refresh token of a web session that expired, as logout does for a session the user
 * ends (ADR-0043, extending ADR-0036). The persistent session store calls {@link #revoke} for each
 * expired session it deletes: in the periodic expiry sweep, and when a request finds its session
 * expired.
 *
 * <p>Neither path has the request the session belonged to, so the token is read from the session
 * attribute that {@link HttpSessionOAuth2AuthorizedClientRepository} writes, rather than through
 * the chain's {@link OAuth2AuthorizedClientRepository}. A chain whose host replaces that repository
 * with another store keeps logout revocation but loses revocation on expiry; registering such a
 * chain logs a {@code WARN}. Every OIDC webapp chain {@link #register registers} its client
 * registrations and its {@link RefreshTokenRevoker}; the session goes to the chain that knows its
 * registration ID with the same client and token endpoint. Two scopes can use one registration ID
 * for different providers, and the stored client must never be sent to the wrong one. A chain whose
 * configuration names another client is skipped before its registration is looked up, so an
 * unrelated provider that is down cannot slow the revocation. When several chains own the client
 * but disagree on revocation, for example one scope opts out, the token is not revoked: the session
 * does not say which scope it came from, and an opt-out must hold.
 *
 * <p>Revocations run in the background, on one lane per provider, keyed by the stored client's
 * token endpoint. Each lane has its own thread and a bounded backlog, so a provider that is slow or
 * down cannot hold up the revocations of another. A request never waits: when its lane is full, the
 * revocation is dropped with a {@code WARN}. The expiry sweep runs on its own thread and calls
 * {@link #revokeFromSweep}, which waits for room while the provider keeps up, so a large sweep
 * against a healthy provider is not dropped. A provider that does not keep up, or a backlog that
 * has used up its waiting budget, makes the sweep drop instead, so the sweep reaches the sessions
 * of the other providers. After a registration fails to resolve, it is skipped for {@link
 * #LOOKUP_BACKOFF}, so an unreachable provider does not start a discovery for every session. The
 * session is deleted either way, and every failure is fail-soft: neither method throws.
 */
public final class ExpiredSessionRefreshTokenRevocation implements AutoCloseable {

  /**
   * The session attribute {@link HttpSessionOAuth2AuthorizedClientRepository} keeps the authorized
   * clients in, keyed by registration ID. Spring does not expose the name, so it is repeated here.
   * {@code ExpiredSessionRefreshTokenRevocationTest} pins it against the repository's behaviour.
   */
  static final String AUTHORIZED_CLIENTS_ATTRIBUTE =
      HttpSessionOAuth2AuthorizedClientRepository.class.getName() + ".AUTHORIZED_CLIENTS";

  /** Bounds the memory and the backlog of one provider when many of its sessions expire. */
  static final int QUEUE_CAPACITY = 1_000;

  /**
   * How long the sweep waits for one free place in a full lane. A provider that needs longer for a
   * revocation does not keep up, and the sweep drops the rest of the backlog.
   */
  static final Duration SWEEP_WAIT = Duration.ofSeconds(1);

  /**
   * How long the sweep waits in total for one backlog of a lane, half the sweep interval. A large
   * sweep then cannot hold up the sessions of the other providers for long.
   */
  static final Duration SWEEP_WAIT_BUDGET = Duration.ofMinutes(5);

  /** How long a registration that failed to resolve is skipped before it is looked up again. */
  static final Duration LOOKUP_BACKOFF = Duration.ofMinutes(1);

  /**
   * Bounds the lanes, whose keys come from stored sessions: at most this many providers get a lane
   * of their own, and any further providers share one more.
   */
  static final int MAX_LANES = 64;

  private static final String SHARED_LANE = "*";

  private static final Logger LOG =
      LoggerFactory.getLogger(ExpiredSessionRefreshTokenRevocation.class);

  private final List<Chain> chains = new CopyOnWriteArrayList<>();
  private final Map<String, Lane> lanes = new ConcurrentHashMap<>();
  private final Supplier<ExecutorService> laneExecutors;
  private final int laneCapacity;
  private final Duration sweepWait;
  private final Duration sweepWaitBudget;
  private final LongSupplier nanoTime;
  private final Set<String> ambiguousRegistrationIds = ConcurrentHashMap.newKeySet();
  // Deadline (System.nanoTime) until which a chain's registration is not looked up again.
  private final Map<Lookup, Long> unresolvedUntil = new ConcurrentHashMap<>();

  public ExpiredSessionRefreshTokenRevocation() {
    this(
        ExpiredSessionRefreshTokenRevocation::laneExecutor,
        QUEUE_CAPACITY,
        SWEEP_WAIT,
        SWEEP_WAIT_BUDGET,
        System::nanoTime);
  }

  // Visible for testing: a test runs revocations inline or holds them, and controls the clock.
  ExpiredSessionRefreshTokenRevocation(
      final Supplier<ExecutorService> laneExecutors,
      final int laneCapacity,
      final Duration sweepWait,
      final Duration sweepWaitBudget,
      final LongSupplier nanoTime) {
    this.laneExecutors = Objects.requireNonNull(laneExecutors, "laneExecutors must not be null");
    this.laneCapacity = laneCapacity;
    this.sweepWait = Objects.requireNonNull(sweepWait, "sweepWait must not be null");
    this.sweepWaitBudget =
        Objects.requireNonNull(sweepWaitBudget, "sweepWaitBudget must not be null");
    this.nanoTime = Objects.requireNonNull(nanoTime, "nanoTime must not be null");
  }

  /**
   * Registers an OIDC webapp chain. Called once per chain while the chains are built.
   *
   * @param clientRegistrationRepository the client registrations of the chain
   * @param authorizedClientRepository where the chain stores its authorized clients; revocation on
   *     expiry reads them only from the session, see the class Javadoc
   * @param revoker the revoker the chain's logout handler uses
   */
  public void register(
      final ClientRegistrationRepository clientRegistrationRepository,
      final OAuth2AuthorizedClientRepository authorizedClientRepository,
      final RefreshTokenRevoker revoker) {
    if (!(authorizedClientRepository instanceof HttpSessionOAuth2AuthorizedClientRepository)) {
      LOG.warn(
          "An OIDC webapp chain stores its authorized clients in {}, not in the web session, so"
              + " the refresh tokens of its expired web sessions are not revoked. Logout still"
              + " revokes them.",
          authorizedClientRepository == null
              ? "no repository"
              : authorizedClientRepository.getClass().getName());
    }
    chains.add(
        new Chain(
            Objects.requireNonNull(
                clientRegistrationRepository, "clientRegistrationRepository must not be null"),
            Objects.requireNonNull(revoker, "revoker must not be null")));
  }

  /**
   * Schedules the revocation of the refresh token of {@code expiredSession}, if it holds one, for a
   * request that found the session expired. Never waits: a full lane drops it. Reads the session on
   * the calling thread, so the caller can delete it right after. Never throws.
   */
  public void revoke(final Session expiredSession) {
    revoke(expiredSession, false);
  }

  /**
   * Like {@link #revoke}, for the expiry sweep, which runs on its own thread: waits for room in a
   * full lane while the provider frees a place within {@link #SWEEP_WAIT}, and for at most {@link
   * #SWEEP_WAIT_BUDGET} per backlog, so a large sweep is not dropped while the provider keeps up.
   * Never throws.
   */
  public void revokeFromSweep(final Session expiredSession) {
    revoke(expiredSession, true);
  }

  private void revoke(final Session expiredSession, final boolean mayWait) {
    try {
      scheduleRevocation(expiredSession, mayWait);
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

  /** The number of lanes. Exists so tests can assert the lane bound. */
  int laneCount() {
    return lanes.size();
  }

  @Override
  public void close() {
    lanes.values().forEach(lane -> lane.executor().shutdown());
  }

  private void scheduleRevocation(final Session expiredSession, final boolean mayWait) {
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
    final Lane lane = lane(laneKey(authorizedClient.getClientRegistration()));
    if (!lane.tryEnter(mayWait, sweepWait, sweepWaitBudget)) {
      // One WARN per backlog rather than one per session: the flag resets only once the lane's
      // backlog is gone.
      if (lane.saturated().compareAndSet(false, true)) {
        LOG.warn(
            "Dropping refresh-token revocations of expired web sessions for token endpoint '{}':"
                + " its revocation queue is full ({} queued). The identity provider may be slow or"
                + " unreachable, or many sessions expired at once. The sessions are still deleted,"
                + " but their refresh tokens may remain valid until they expire.",
            UrlRedaction.redact(lane.key()),
            laneCapacity);
      }
      return;
    }
    try {
      lane.executor()
          .execute(
              () -> {
                try {
                  revokeThroughOwningChain(registrationId, authorizedClient);
                } finally {
                  lane.leave();
                }
              });
    } catch (final RejectedExecutionException e) {
      // Only after close(): the lanes have unbounded queues.
      lane.leave();
    }
  }

  private Lane lane(final String key) {
    final Lane existing = lanes.get(key);
    if (existing != null) {
      return existing;
    }
    // Under the lock, so concurrent sessions of new providers cannot exceed MAX_LANES.
    synchronized (lanes) {
      final Lane created = lanes.get(key);
      if (created != null) {
        return created;
      }
      final String bounded = lanes.size() < MAX_LANES ? key : SHARED_LANE;
      return lanes.computeIfAbsent(
          bounded,
          k -> new Lane(k, laneExecutors.get(), new Semaphore(laneCapacity), laneCapacity));
    }
  }

  /** The provider of the stored client: its token endpoint, else its issuer, else its ID. */
  private static String laneKey(final ClientRegistration stored) {
    final var provider = stored.getProviderDetails();
    if (StringUtils.hasText(provider.getTokenUri())) {
      return provider.getTokenUri();
    }
    if (StringUtils.hasText(provider.getIssuerUri())) {
      return provider.getIssuerUri();
    }
    return stored.getRegistrationId();
  }

  private void revokeThroughOwningChain(
      final String registrationId, final OAuth2AuthorizedClient authorizedClient) {
    final Optional<List<Owner>> possibleOwners =
        owners(registrationId, authorizedClient.getClientRegistration());
    if (possibleOwners.isEmpty()) {
      return;
    }
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
      final Lookup lookup = new Lookup(chain, registrationId);
      final Long backoffUntil = unresolvedUntil.get(lookup);
      if (backoffUntil != null && nanoTime.getAsLong() - backoffUntil < 0) {
        // Failed to resolve a moment ago: skip it rather than start another discovery that is
        // likely to time out and hold this provider's lane.
        LOG.debug(
            "OIDC registration '{}' failed to resolve recently, so the refresh token of an expired"
                + " web session is not revoked.",
            ScopedClientRegistrationFactory.sanitizeForLog(registrationId));
        return Optional.empty();
      }
      final ClientRegistration registration;
      try {
        registration = chain.clientRegistrationRepository().findByRegistrationId(registrationId);
      } catch (final RuntimeException e) {
        // The revocation settings of this chain are unknown, and revoking through another chain
        // could ignore an opt-out of this one. One WARN per outage of a registration rather than
        // one per session; the rest go to DEBUG.
        final boolean firstFailure =
            unresolvedUntil.put(lookup, nanoTime.getAsLong() + LOOKUP_BACKOFF.toNanos()) == null;
        if (firstFailure) {
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
      // Resolved again: the next failure to resolve it warns again.
      unresolvedUntil.remove(lookup);
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

  /**
   * One thread that stops when idle. The queue is unbounded because the lane's semaphore bounds it,
   * so that a request can drop and the sweep can wait.
   */
  private static ExecutorService laneExecutor() {
    final var threadFactory =
        Thread.ofPlatform().name("camunda-session-expiry-revocation-", 0).daemon(true).factory();
    final var executor =
        new ThreadPoolExecutor(
            1, 1, 1, TimeUnit.MINUTES, new LinkedBlockingQueue<>(), threadFactory);
    executor.allowCoreThreadTimeOut(true);
    return executor;
  }

  private record Chain(
      ClientRegistrationRepository clientRegistrationRepository, RefreshTokenRevoker revoker) {}

  private record Owner(Chain chain, ClientRegistration registration) {}

  private record Lookup(Chain chain, String registrationId) {}

  /**
   * The revocations of one provider: a thread, permits for its queued and running tasks, and the
   * state of the current backlog.
   */
  private record Lane(
      String key,
      ExecutorService executor,
      Semaphore permits,
      int capacity,
      AtomicBoolean saturated,
      AtomicLong sweepWaitedNanos) {

    Lane(final String key, final ExecutorService executor, final Semaphore permits, final int cap) {
      this(key, executor, permits, cap, new AtomicBoolean(), new AtomicLong());
    }

    /**
     * Takes a permit: at once, or for the sweep by waiting up to {@code wait} for one, unless the
     * lane already drops revocations for this backlog or the backlog has used up {@code budget}.
     */
    boolean tryEnter(final boolean mayWait, final Duration wait, final Duration budget) {
      if (!mayWait || saturated.get()) {
        return permits.tryAcquire();
      }
      if (permits.tryAcquire()) {
        return true;
      }
      final long remaining = budget.toNanos() - sweepWaitedNanos.get();
      if (remaining <= 0) {
        return false;
      }
      final long start = System.nanoTime();
      try {
        return permits.tryAcquire(Math.min(wait.toNanos(), remaining), TimeUnit.NANOSECONDS);
      } catch (final InterruptedException e) {
        Thread.currentThread().interrupt();
        return false;
      } finally {
        sweepWaitedNanos.addAndGet(System.nanoTime() - start);
      }
    }

    /** Returns the permit, and ends the backlog once nothing is queued or running. */
    void leave() {
      permits.release();
      if (permits.availablePermits() == capacity) {
        saturated.set(false);
        sweepWaitedNanos.set(0);
      }
    }
  }
}
