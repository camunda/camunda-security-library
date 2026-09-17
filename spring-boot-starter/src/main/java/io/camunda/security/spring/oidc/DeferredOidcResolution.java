/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.time.Duration;
import java.util.Comparator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

/**
 * Runs an OIDC resolution step at its first use, and limits the rate at which failures of that step
 * reach the log.
 *
 * <p>The step runs on a request thread, so an unreachable identity provider fails one request after
 * another. One entry per failure would fill the log. The class therefore writes one warning per
 * minute for each subject, and the other failures at debug level.
 *
 * <p>The original exception is thrown again without a change, so Spring Security reports an
 * unreachable provider as a server error, and not as a refused credential.
 */
public final class DeferredOidcResolution {

  static final int MAX_TRACKED_SUBJECTS = 256;

  private static final Logger LOG = LoggerFactory.getLogger(DeferredOidcResolution.class);
  private static final long WARN_INTERVAL_NANOS = Duration.ofMinutes(1).toNanos();
  private static final Map<String, AtomicLong> LAST_WARN_NANOS = new ConcurrentHashMap<>();
  private static final ThreadLocal<Nesting> NESTING = ThreadLocal.withInitial(Nesting::new);

  private DeferredOidcResolution() {}

  /**
   * Calls {@code resolution}. If it throws a {@link RuntimeException}, the method writes a log
   * entry and throws the exception again.
   *
   * <p>One resolution can run inside another one. The decoder of a cluster resolves the
   * registrations of the repository, and each of those lookups is a resolution of its own. Only the
   * innermost step reports such a failure, because it names the provider that failed. The outer
   * steps write it at debug level, and they take no rate-limit state, so one failure costs one
   * warning.
   *
   * @param subject what the step resolves. The log message names it, and the rate limit counts per
   *     subject (for example {@code client registration 'camunda' (issuer
   *     https://idp/realms/camunda)}).
   */
  public static <T> T resolve(final String subject, final Supplier<T> resolution) {
    final var nesting = NESTING.get();
    nesting.depth++;
    try {
      return resolution.get();
    } catch (final RuntimeException failed) {
      if (nesting.reported == failed) {
        LOG.debug("Failed to resolve {}.", subject, failed);
      } else {
        nesting.reported = failed;
        report(subject, failed);
      }
      throw failed;
    } finally {
      if (--nesting.depth == 0) {
        NESTING.remove();
      }
    }
  }

  private static void report(final String subject, final RuntimeException failed) {
    if (shouldWarn(subject)) {
      LOG.warn(
          "Failed to resolve {}. This request is rejected, and the next request makes a new"
              + " attempt. An unreachable identity provider therefore needs no restart, and a"
              + " configuration error repeats until the configuration changes.",
          subject,
          failed);
    } else {
      LOG.debug("Failed to resolve {}.", subject, failed);
    }
  }

  /**
   * A supplier that calls {@code resolution} until it succeeds, and returns that result from then
   * on.
   *
   * <p>The supplier holds no lock across the resolution, unlike {@code SingletonSupplier}. A burst
   * of requests for an unreachable provider would otherwise wait one discovery timeout after
   * another, and the request threads would run out. Each caller therefore makes its own attempt,
   * and the first result wins.
   */
  public static <T> Supplier<T> memoizeOnSuccess(final Supplier<T> resolution) {
    final var resolved = new AtomicReference<T>();
    return () -> {
      final var cached = resolved.get();
      if (cached != null) {
        return cached;
      }
      final var result = resolution.get();
      return resolved.compareAndSet(null, result) ? result : resolved.get();
    };
  }

  /**
   * Names one provider, as {@code 'camunda' (issuer https://idp/realms/camunda)}. The name holds
   * the issuer, because that is the endpoint a failed resolution could not reach.
   */
  public static String describeProvider(
      final String registrationId, final OidcConfiguration config) {
    final var issuerUri = config.getIssuerUri();
    return "'"
        + registrationId
        + "'"
        + (StringUtils.hasText(issuerUri) ? " (issuer " + issuerUri + ")" : "");
  }

  /**
   * Names each provider that one resolution covers, see {@link #describeProvider(String,
   * OidcConfiguration)}.
   */
  public static String describeProviders(final Map<String, OidcConfiguration> providers) {
    return providers.entrySet().stream()
        .map(provider -> describeProvider(provider.getKey(), provider.getValue()))
        .collect(Collectors.joining(", "));
  }

  /**
   * The rate-limit state of a subject. A known subject needs no lock. A new subject enters the
   * state under a lock, because the limit holds only while one thread at a time adds an entry.
   */
  private static AtomicLong trackedSubject(final String subject, final long now) {
    final var tracked = LAST_WARN_NANOS.get(subject);
    if (tracked != null) {
      return tracked;
    }
    synchronized (LAST_WARN_NANOS) {
      removeIdleSubjects(now);
      dropLeastRecentSubjects();
      return LAST_WARN_NANOS.computeIfAbsent(
          subject, key -> new AtomicLong(now - WARN_INTERVAL_NANOS - 1));
    }
  }

  /**
   * Drops each subject whose last warning is older than the interval. Such a subject permits a
   * warning at once, so its entry holds no information.
   */
  static void removeIdleSubjects(final long now) {
    LAST_WARN_NANOS.values().removeIf(lastWarn -> now - lastWarn.get() >= WARN_INTERVAL_NANOS);
  }

  /**
   * Drops the subject that warned least recently, until the state is below the limit. A host that
   * gives a new subject for each scope could otherwise pass the limit inside one interval. A
   * dropped subject permits one warning more than the interval allows, which is the cost of the
   * bound.
   */
  private static void dropLeastRecentSubjects() {
    while (LAST_WARN_NANOS.size() >= MAX_TRACKED_SUBJECTS) {
      final var leastRecent =
          LAST_WARN_NANOS.entrySet().stream()
              .min(Comparator.comparingLong(subject -> subject.getValue().get()))
              .orElse(null);
      if (leastRecent == null || LAST_WARN_NANOS.remove(leastRecent.getKey()) == null) {
        return;
      }
    }
  }

  /** The number of subjects the rate limit holds state for. */
  static int trackedSubjectCount() {
    return LAST_WARN_NANOS.size();
  }

  private static boolean shouldWarn(final String subject) {
    final long now = System.nanoTime();
    final var lastWarn = trackedSubject(subject, now);
    final long previous = lastWarn.get();
    return now - previous >= WARN_INTERVAL_NANOS && lastWarn.compareAndSet(previous, now);
  }

  /** The resolutions that run on one thread, and the failure the innermost one reported. */
  private static final class Nesting {
    private int depth;
    private RuntimeException reported;
  }
}
