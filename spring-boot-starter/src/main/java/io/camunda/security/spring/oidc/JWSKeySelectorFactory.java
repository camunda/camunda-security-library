/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.CachingJWKSetSource;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.jwk.source.RefreshAheadCachingJWKSetSource.ScheduledRefreshFailed;
import com.nimbusds.jose.jwk.source.RefreshAheadCachingJWKSetSource.UnableToRefreshAheadOfExpirationEvent;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.events.EventListener;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * Factory for creating {@link JWSKeySelector} instances based on a configured set of allowed {@link
 * JWSAlgorithm} values and a JWK Set URI.
 *
 * <p>This class provides a default set of secure algorithms (RSA and EC families).
 */
public class JWSKeySelectorFactory {

  /** Name of the shared scheduler thread, so a thread dump identifies it. */
  static final String REFRESH_SCHEDULER_THREAD_NAME = "csl-jwks-refresh-scheduler";

  /** Name prefix of the virtual threads that run the background fetches. */
  static final String REFRESH_FETCH_THREAD_NAME_PREFIX = "csl-jwks-refresh-fetch-";

  private static final Logger LOG = LoggerFactory.getLogger(JWSKeySelectorFactory.class);

  private static final String ERROR_MISSING_JWK_SET_URI = "Missing or empty 'jwkSetUri'";
  private static final String ERROR_INVALID_JWK_SET_URI =
      "Invalid 'jwkSetUri' provided: '%s'. It could not be converted to a valid URL. Cause: %s";

  private static final Set<JWSAlgorithm> DEFAULT_JWS_ALGORITHMS =
      Set.of(
          // JWS Algorithm Family: RSA
          JWSAlgorithm.RS256,
          JWSAlgorithm.RS384,
          JWSAlgorithm.RS512,
          // JWS Algorithm Family: EC
          JWSAlgorithm.ES256,
          JWSAlgorithm.ES384,
          JWSAlgorithm.ES512);

  /**
   * HTTP connect/read timeout for JWK Set retrieval, in milliseconds. Nimbus's 500ms default
   * ({@link JWKSourceBuilder#DEFAULT_HTTP_CONNECT_TIMEOUT}) is tight for a real IdP under ordinary
   * load. See ADR-0032.
   */
  private static final int HTTP_CONNECT_TIMEOUT_MILLIS = 3_000;

  /**
   * @see #HTTP_CONNECT_TIMEOUT_MILLIS
   */
  private static final int HTTP_READ_TIMEOUT_MILLIS = 3_000;

  /**
   * Maximum time a cached JWK Set is trusted before a fresh fetch is forced: the staleness bound of
   * ADR-0032. Nimbus's default ({@link JWKSourceBuilder#DEFAULT_CACHE_TIME_TO_LIVE}), made
   * explicit.
   */
  private static final long CACHE_TIME_TO_LIVE_MILLIS = JWKSourceBuilder.DEFAULT_CACHE_TIME_TO_LIVE;

  /**
   * How long a caller waits for another thread's in-flight refresh — Nimbus's lock-wait limit; the
   * fetch itself is bounded by the HTTP timeouts. Nimbus's default ({@link
   * JWKSourceBuilder#DEFAULT_CACHE_REFRESH_TIMEOUT}).
   */
  private static final long CACHE_REFRESH_TIMEOUT_MILLIS =
      JWKSourceBuilder.DEFAULT_CACHE_REFRESH_TIMEOUT;

  /**
   * How far ahead of expiry the cache is refreshed in the background, so requests read a warm
   * cache. Nimbus's default ({@link JWKSourceBuilder#DEFAULT_REFRESH_AHEAD_TIME}).
   */
  private static final long REFRESH_AHEAD_TIME_MILLIS = JWKSourceBuilder.DEFAULT_REFRESH_AHEAD_TIME;

  /**
   * Shared by every {@link JWKSource} this class builds, so the footprint does not grow with the
   * number of issuers. Nimbus's scheduled task only dispatches the fetch to the refresh executor
   * below, so a single thread suffices. Daemon, so it cannot keep a host's JVM from exiting; never
   * shut down, which is why the sources are built with {@code shutdownOnClose = false}.
   */
  private static final ScheduledExecutorService REFRESH_SCHEDULER =
      Executors.newSingleThreadScheduledExecutor(
          runnable -> {
            final var thread = new Thread(runnable, REFRESH_SCHEDULER_THREAD_NAME);
            thread.setDaemon(true);
            return thread;
          });

  /**
   * Runs the blocking background fetches, one virtual thread per fetch. Virtual threads are always
   * daemon, and unlike Nimbus's default non-daemon pools, nothing keeps a host's JVM alive.
   */
  private static final ExecutorService REFRESH_FETCH_EXECUTOR =
      Executors.newThreadPerTaskExecutor(
          Thread.ofVirtual().name(REFRESH_FETCH_THREAD_NAME_PREFIX, 0).factory());

  private final Set<JWSAlgorithm> jwsAlgorithms;

  public JWSKeySelectorFactory() {
    this(DEFAULT_JWS_ALGORITHMS);
  }

  public JWSKeySelectorFactory(final Set<JWSAlgorithm> jwsAlgorithms) {
    this.jwsAlgorithms = Set.copyOf(jwsAlgorithms);
  }

  /**
   * Creates a {@link JWSKeySelector} for the given JWK Set URI.
   *
   * @param jwkSetUri the URI of the JWK Set used to verify token signatures
   * @return a {@link JWSVerificationKeySelector} configured with the allowed algorithms
   * @throws IllegalArgumentException if the URI is malformed
   */
  public JWSKeySelector<SecurityContext> createJWSKeySelector(final String jwkSetUri) {
    if (!StringUtils.hasText(jwkSetUri)) {
      throw new IllegalArgumentException(ERROR_MISSING_JWK_SET_URI);
    }

    final var url = toURL(jwkSetUri);
    final var jwkSource = createJWKSource(url);
    final var jwsAlgorithms = getJWSAlgorithms();
    return new JWSVerificationKeySelector<>(jwsAlgorithms, jwkSource);
  }

  /**
   * Creates a {@link JWSKeySelector} for the given primary JWK Set URI and optional additional
   * URIs. When additional URIs are provided, a {@link CompositeJWKSource} is used to aggregate keys
   * from all sources.
   *
   * @param jwkSetUri the primary JWK Set URI
   * @param additionalJwkSetUris additional JWK Set URIs to query for key resolution
   * @return a {@link JWSVerificationKeySelector} configured with the allowed algorithms
   * @throws IllegalArgumentException if the primary URI is malformed
   */
  public JWSKeySelector<SecurityContext> createJWSKeySelector(
      final String jwkSetUri, final List<String> additionalJwkSetUris) {
    if (CollectionUtils.isEmpty(additionalJwkSetUris)) {
      return createJWSKeySelector(jwkSetUri);
    }

    if (!StringUtils.hasText(jwkSetUri)) {
      throw new IllegalArgumentException(ERROR_MISSING_JWK_SET_URI);
    }

    final var sources =
        Stream.concat(
                Stream.of(jwkSetUri), additionalJwkSetUris.stream().filter(StringUtils::hasText))
            .map(uri -> createJWKSource(toURL(uri)))
            .toList();

    final var compositeSource = new CompositeJWKSource<>(sources);
    return new JWSVerificationKeySelector<>(getJWSAlgorithms(), compositeSource);
  }

  /**
   * Converts a JWK Set URI to a {@link URL}, with validation.
   *
   * @param jwkSetUri the URI as a string
   * @return the corresponding {@link URL}
   * @throws IllegalArgumentException if the URI is not a valid URL
   */
  protected URL toURL(final String jwkSetUri) {
    try {
      return URI.create(jwkSetUri).toURL();
    } catch (final MalformedURLException | IllegalArgumentException ex) {
      // Redacted, and not chained: the URI is operator-supplied and may carry user-info or a query
      // secret, and the parser's own message (and so the cause) quotes it back verbatim.
      throw new IllegalArgumentException(
          ERROR_INVALID_JWK_SET_URI.formatted(
              UrlRedaction.redact(jwkSetUri), ex.getClass().getSimpleName()));
    }
  }

  /**
   * Creates a {@link JWKSource} for the given JWK Set URL.
   *
   * <p>Configures scheduled refresh-ahead caching (background refresh, independent of request
   * timing — see ADR-0032) and an explicit, longer-than-Nimbus-default HTTP connect/read timeout,
   * so that a slow or briefly unavailable JWKS endpoint does not block every concurrent decode
   * request at once. Rate limiting stays disabled; whether to enable it is a separate design
   * question (see ADR-0032's "Alternatives Considered").
   *
   * <p>The refresh executors are supplied explicitly (and shared across all sources) rather than
   * left to Nimbus, whose own defaults are <em>non-daemon</em> single-thread pools per source that
   * nothing shuts down — they would keep a host's JVM from exiting after its Spring context closes.
   *
   * @see org.springframework.security.oauth2.jwt.NimbusJwtDecoder.JwkSetUriJwtDecoderBuilder
   * @param jwkSetUri the JWK Set URI
   * @return a {@link JWKSource} for use in verifying JWT signatures
   */
  protected JWKSource<SecurityContext> createJWKSource(final URL jwkSetUri) {
    final var retriever =
        new DefaultResourceRetriever(
            getHttpConnectTimeoutMillis(),
            getHttpReadTimeoutMillis(),
            JWKSourceBuilder.DEFAULT_HTTP_SIZE_LIMIT);
    // Read once, so the check below sees exactly what Nimbus is built with.
    final var timeToLive = getCacheTimeToLiveMillis();
    final var refreshTimeout = getCacheRefreshTimeoutMillis();
    final var refreshAhead = getRefreshAheadTimeMillis();
    requireRefreshToBeScheduled(timeToLive, refreshTimeout, refreshAhead);
    return JWKSourceBuilder.<SecurityContext>create(jwkSetUri, retriever)
        .cache(timeToLive, refreshTimeout)
        .refreshAheadCache(
            refreshAhead,
            refreshFailureListener(jwkSetUri),
            REFRESH_FETCH_EXECUTOR,
            false,
            REFRESH_SCHEDULER,
            false)
        .rateLimited(false)
        .build();
  }

  /**
   * Nimbus rejects a refresh-ahead time plus refresh timeout above the TTL, but accepts equality
   * and then computes a zero scheduling delay, which it does not schedule — silently reverting to
   * request-driven refresh, the behaviour this class exists to replace. Reject equality too.
   */
  private static void requireRefreshToBeScheduled(
      final long timeToLive, final long refreshTimeout, final long refreshAhead) {
    if (refreshAhead + refreshTimeout >= timeToLive) {
      throw new IllegalArgumentException(
          "The refresh-ahead time (%dms) plus the cache refresh timeout (%dms) must be less than the"
                  .formatted(refreshAhead, refreshTimeout)
              + " cache time-to-live (%dms), or the background refresh is never scheduled"
                  .formatted(timeToLive));
    }
  }

  /**
   * Logs the background refresh failures Nimbus reports only through its event listener; without it
   * an IdP outage is invisible until the cache expires and decoding starts failing.
   *
   * <p>The JWK Set URI is the only identifier logged, redacted ({@link UrlRedaction}); no token
   * data.
   */
  private static EventListener<CachingJWKSetSource<SecurityContext>, SecurityContext>
      refreshFailureListener(final URL jwkSetUri) {
    final var redactedUri = UrlRedaction.redact(jwkSetUri.toString());
    return event -> {
      if (event instanceof ScheduledRefreshFailed<SecurityContext> failed) {
        LOG.warn(
            "Scheduling the background refresh of the JWK Set at '{}' failed ({}); the cached keys"
                + " will expire unrefreshed unless a later refresh succeeds",
            redactedUri,
            describe(failed.getException()));
      } else if (event instanceof UnableToRefreshAheadOfExpirationEvent<SecurityContext>) {
        LOG.warn(
            "Background refresh of the JWK Set at '{}' failed; keeps serving the cached keys until"
                + " they expire, after which decoding fails if the endpoint is still unavailable",
            redactedUri);
      }
    };
  }

  /**
   * The exception types in a cause chain, outermost first, e.g. {@code JWKSetRetrievalException <-
   * SocketTimeoutException}. Types only: an HTTP client's message and stack can embed the full URL,
   * but the types are what tell a timeout from a refused connection or a bad certificate.
   */
  private static String describe(final Throwable failure) {
    final var types = new ArrayList<String>();
    for (var cause = failure; cause != null && types.size() < 5; cause = cause.getCause()) {
      types.add(cause.getClass().getSimpleName());
    }
    return String.join(" <- ", types);
  }

  /** The HTTP connect timeout for JWK Set retrieval, in milliseconds. */
  protected int getHttpConnectTimeoutMillis() {
    return HTTP_CONNECT_TIMEOUT_MILLIS;
  }

  /** The HTTP read timeout for JWK Set retrieval, in milliseconds. */
  protected int getHttpReadTimeoutMillis() {
    return HTTP_READ_TIMEOUT_MILLIS;
  }

  /**
   * The maximum staleness of a cached JWK Set, in milliseconds.
   *
   * <p>An override must keep {@code getRefreshAheadTimeMillis() + getCacheRefreshTimeoutMillis() <
   * getCacheTimeToLiveMillis()}, strictly, or {@link #createJWKSource(URL)} throws an {@link
   * IllegalArgumentException} when the source for a URL is built (with several issuers, on the
   * first token for each, not at startup): a sum at the TTL never schedules the background refresh,
   * and one near it polls the IdP continuously.
   */
  protected long getCacheTimeToLiveMillis() {
    return CACHE_TIME_TO_LIVE_MILLIS;
  }

  /**
   * How long a caller waits for another thread's in-flight refresh, in milliseconds. Subject to the
   * invariant on {@link #getCacheTimeToLiveMillis()}.
   */
  protected long getCacheRefreshTimeoutMillis() {
    return CACHE_REFRESH_TIMEOUT_MILLIS;
  }

  /**
   * How far ahead of expiry the cache is refreshed in the background, in milliseconds. Subject to
   * the invariant on {@link #getCacheTimeToLiveMillis()}.
   */
  protected long getRefreshAheadTimeMillis() {
    return REFRESH_AHEAD_TIME_MILLIS;
  }

  /**
   * Returns the set of supported JWS algorithms.
   *
   * @return the configured set of allowed {@link JWSAlgorithm} values
   */
  public Set<JWSAlgorithm> getJWSAlgorithms() {
    return jwsAlgorithms;
  }
}
