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
import java.util.function.Supplier;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

/**
 * Runs an OIDC resolution step that the application makes after it starts, and limits the rate at
 * which failures of that step reach the log.
 *
 * <p>Such a step runs on a request thread. An identity provider the application cannot reach
 * therefore causes one failure per request, and not one failure per start. A log entry for each
 * failure lets one unreachable issuer fill the log at the rate of the requests. This class
 * therefore writes one warning per minute for each subject, and writes the other failures at debug
 * level.
 *
 * <p>The method throws the original exception again, and does not change it. Spring Security
 * therefore reports a provider it cannot reach as a server error, and not as a credential it
 * refuses. That holds for the resource-server chain and for the login flow.
 */
public final class DeferredOidcResolution {

  static final int MAX_TRACKED_SUBJECTS = 256;

  private static final Logger LOG = LoggerFactory.getLogger(DeferredOidcResolution.class);
  private static final long WARN_INTERVAL_NANOS = Duration.ofMinutes(1).toNanos();
  private static final Map<String, AtomicLong> LAST_WARN_NANOS = new ConcurrentHashMap<>();

  private DeferredOidcResolution() {}

  /**
   * Calls {@code resolution}. If it throws a {@link RuntimeException}, the method writes a log
   * entry and throws the exception again.
   *
   * @param subject what the step resolves. The log message names it, and the rate limit counts per
   *     subject (for example {@code client registration 'camunda' (issuer
   *     https://idp/realms/camunda)}).
   */
  public static <T> T resolve(final String subject, final Supplier<T> resolution) {
    try {
      return resolution.get();
    } catch (final RuntimeException failed) {
      if (shouldWarn(subject)) {
        LOG.warn(
            "Failed to resolve {}. This request is rejected. The next request makes a new"
                + " attempt. A failure that an unreachable identity provider causes therefore"
                + " ends without a restart as soon as that provider answers again. A failure that"
                + " the configuration causes repeats until the configuration changes.",
            subject,
            failed);
      } else {
        LOG.debug("Failed to resolve {}.", subject, failed);
      }
      throw failed;
    }
  }

  /**
   * Names one provider for a resolution subject, in the form {@code 'camunda' (issuer
   * https://idp/realms/camunda)}. The name holds the issuer, because the issuer is the endpoint a
   * failed resolution could not reach.
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
   * The rate-limit state of a subject. A subject the state holds already needs no lock, so a
   * failure of a known subject costs one map lookup. A subject the state does not hold yet enters
   * it under a lock, because the limit holds only while one thread at a time adds an entry.
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
   * Drops the subject that warned least recently, until the state holds fewer subjects than the
   * limit. The state therefore stays bounded while more subjects than the limit fail inside one
   * interval, which a host that gives a new subject for each scope it creates can reach. The
   * dropped subject permits one more warning than the interval allows, and that is the cost of the
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
}
