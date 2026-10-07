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
   * HTTP connect/read timeout for JWK Set retrieval, in milliseconds. Nimbus's own default is 500ms
   * ({@link JWKSourceBuilder#DEFAULT_HTTP_CONNECT_TIMEOUT}), which a real external IdP can exceed
   * under ordinary load, not just during an outage. Raised to comfortably exceed realistic
   * network/IdP latency while still failing fast. See ADR-0032.
   */
  private static final int HTTP_CONNECT_TIMEOUT_MILLIS = 3_000;

  /**
   * @see #HTTP_CONNECT_TIMEOUT_MILLIS
   */
  private static final int HTTP_READ_TIMEOUT_MILLIS = 3_000;

  /**
   * Maximum time a cached JWK Set is trusted before a fresh, bounded fetch is forced — the
   * staleness bound discussed in ADR-0032. Matches Nimbus's own default ({@link
   * JWKSourceBuilder#DEFAULT_CACHE_TIME_TO_LIVE}), set explicitly here so the bound is documented
   * rather than an implicit library default.
   */
  private static final long CACHE_TIME_TO_LIVE_MILLIS = JWKSourceBuilder.DEFAULT_CACHE_TIME_TO_LIVE;

  /**
   * Upper bound on a single synchronous JWK Set fetch — reached only when the background
   * refresh-ahead has not kept the cache current (e.g. a sustained IdP outage) or an unrecognized
   * {@code kid} forces an immediate refresh. Matches Nimbus's own default ({@link
   * JWKSourceBuilder#DEFAULT_CACHE_REFRESH_TIMEOUT}).
   */
  private static final long CACHE_REFRESH_TIMEOUT_MILLIS =
      JWKSourceBuilder.DEFAULT_CACHE_REFRESH_TIMEOUT;

  /**
   * How far ahead of its expiry the cached JWK Set is refreshed in the background, so live decode
   * requests read an already-warm cache instead of blocking on the refresh. Matches Nimbus's own
   * default ({@link JWKSourceBuilder#DEFAULT_REFRESH_AHEAD_TIME}).
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
      throw new IllegalArgumentException(
          ERROR_INVALID_JWK_SET_URI.formatted(jwkSetUri, ex.getMessage()), ex);
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
    return JWKSourceBuilder.<SecurityContext>create(jwkSetUri, retriever)
        .cache(getCacheTimeToLiveMillis(), getCacheRefreshTimeoutMillis())
        .refreshAheadCache(
            getRefreshAheadTimeMillis(),
            refreshFailureLogger(jwkSetUri),
            REFRESH_FETCH_EXECUTOR,
            false,
            REFRESH_SCHEDULER,
            false)
        .rateLimited(false)
        .build();
  }

  /**
   * Nimbus reports failed background refreshes only through its event listener and otherwise
   * swallows them, so without this an IdP outage is silent until the cache expires and decoding
   * starts failing. Logs at {@code WARN}; the JWK Set URI is the only identifier, and no token data
   * is ever involved.
   */
  private static EventListener<CachingJWKSetSource<SecurityContext>, SecurityContext>
      refreshFailureLogger(final URL jwkSetUri) {
    return event -> {
      if (event instanceof ScheduledRefreshFailed<SecurityContext> failed) {
        LOG.warn(
            "Scheduling the background refresh of the JWK Set at '{}' failed; the cached keys will"
                + " expire unrefreshed unless a later refresh succeeds",
            jwkSetUri,
            failed.getException());
      } else if (event instanceof UnableToRefreshAheadOfExpirationEvent<SecurityContext>) {
        LOG.warn(
            "Background refresh of the JWK Set at '{}' failed; keeps serving the cached keys until"
                + " they expire, after which decoding fails if the endpoint is still unavailable",
            jwkSetUri);
      }
    };
  }

  /**
   * The HTTP connect timeout for JWK Set retrieval, in milliseconds. Overridable by a host (or a
   * test) that needs a different value than {@link #HTTP_CONNECT_TIMEOUT_MILLIS}.
   */
  protected int getHttpConnectTimeoutMillis() {
    return HTTP_CONNECT_TIMEOUT_MILLIS;
  }

  /**
   * The HTTP read timeout for JWK Set retrieval, in milliseconds. Overridable by a host (or a test)
   * that needs a different value than {@link #HTTP_READ_TIMEOUT_MILLIS}.
   */
  protected int getHttpReadTimeoutMillis() {
    return HTTP_READ_TIMEOUT_MILLIS;
  }

  /**
   * The maximum staleness of a cached JWK Set, in milliseconds, before a fresh fetch is forced.
   * Overridable by a host (or a test) that needs a different value than {@link
   * #CACHE_TIME_TO_LIVE_MILLIS}.
   *
   * <p>An override must keep {@code getRefreshAheadTimeMillis() + getCacheRefreshTimeoutMillis() <=
   * getCacheTimeToLiveMillis()}, or Nimbus rejects the configuration with an {@link
   * IllegalArgumentException} at bean creation; and the closer that sum gets to the TTL, the more
   * the background refresh cadence collapses towards continuously polling the IdP.
   */
  protected long getCacheTimeToLiveMillis() {
    return CACHE_TIME_TO_LIVE_MILLIS;
  }

  /**
   * The upper bound on a single synchronous JWK Set fetch, in milliseconds. Overridable by a host
   * (or a test) that needs a different value than {@link #CACHE_REFRESH_TIMEOUT_MILLIS}.
   *
   * <p>Subject to the same invariant as {@link #getCacheTimeToLiveMillis()}.
   */
  protected long getCacheRefreshTimeoutMillis() {
    return CACHE_REFRESH_TIMEOUT_MILLIS;
  }

  /**
   * How far ahead of expiry the cached JWK Set is refreshed in the background, in milliseconds.
   * Overridable by a host (or a test) that needs a different value than {@link
   * #REFRESH_AHEAD_TIME_MILLIS}.
   *
   * <p>Subject to the same invariant as {@link #getCacheTimeToLiveMillis()}.
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
