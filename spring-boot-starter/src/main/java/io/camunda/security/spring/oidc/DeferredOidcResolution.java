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
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

/**
 * Runs an OIDC resolution step that was deferred out of application startup and reports its
 * failures at a bounded rate.
 *
 * <p>Deferred resolution happens on a request thread, so an unreachable IdP fails once per request
 * rather than once per boot. Logging every failure would let a single unreachable issuer fill the
 * log at request rate, so the warning is emitted at most once per minute per subject and the rest
 * are logged at debug level. The original exception is always rethrown unchanged, so the caller's
 * error handling stays what it was before resolution was deferred: Spring Security reports a
 * provider it cannot reach as a server error rather than as a rejected credential, on the
 * resource-server chain as much as on the login flow.
 */
public final class DeferredOidcResolution {

  private static final Logger LOG = LoggerFactory.getLogger(DeferredOidcResolution.class);
  private static final long WARN_INTERVAL_NANOS = Duration.ofMinutes(1).toNanos();
  private static final Map<String, AtomicLong> LAST_WARN_NANOS = new ConcurrentHashMap<>();

  private DeferredOidcResolution() {}

  /**
   * Invokes {@code resolution}, logging and rethrowing any {@link RuntimeException} it throws.
   *
   * @param subject what is being resolved, used as the log message's subject and as the rate-limit
   *     key (e.g. {@code client registration 'camunda' (issuer https://idp/realms/camunda)})
   */
  public static <T> T resolve(final String subject, final Supplier<T> resolution) {
    try {
      return resolution.get();
    } catch (final RuntimeException failed) {
      if (shouldWarn(subject)) {
        LOG.warn(
            "Failed to resolve {}. This request is rejected; the next one retries, so the"
                + " deployment recovers on its own once the identity provider answers again.",
            subject,
            failed);
      } else {
        LOG.debug("Failed to resolve {}.", subject, failed);
      }
      throw failed;
    }
  }

  /**
   * Names a single provider for use in a resolution subject, as {@code 'camunda' (issuer
   * https://idp/realms/camunda)}. The issuer is included because it is the endpoint the failed
   * resolution could not reach.
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
   * Names every provider a resolution covers, see {@link #describeProvider(String,
   * OidcConfiguration)}.
   */
  public static String describeProviders(final Map<String, OidcConfiguration> providers) {
    return providers.entrySet().stream()
        .map(provider -> describeProvider(provider.getKey(), provider.getValue()))
        .collect(Collectors.joining(", "));
  }

  private static boolean shouldWarn(final String subject) {
    final long now = System.nanoTime();
    final var lastWarn =
        LAST_WARN_NANOS.computeIfAbsent(
            subject, key -> new AtomicLong(now - WARN_INTERVAL_NANOS - 1));
    final long previous = lastWarn.get();
    return now - previous >= WARN_INTERVAL_NANOS && lastWarn.compareAndSet(previous, now);
  }
}
