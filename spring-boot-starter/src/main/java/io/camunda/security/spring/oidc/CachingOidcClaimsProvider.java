/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import io.camunda.security.api.context.OidcClaimsProvider;
import io.camunda.security.api.model.config.oidc.OidcUserInfoAugmentationConfiguration;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link OidcClaimsProvider} that enriches JWT claims with additional claims from the OIDC UserInfo
 * endpoint. Claims are cached per token value using Caffeine; a negative cache entry is stored on
 * any fetch failure so a degraded IdP does not hammer retries. JWT claims always win on conflict
 * (JWT-wins invariant, see ADR-0019).
 */
public final class CachingOidcClaimsProvider implements OidcClaimsProvider {

  /** Sentinel key stored in negative cache entries. Never present in real JWT claims. */
  static final String NEGATIVE_SENTINEL = "__csl_negative";

  private static final Logger LOG = LoggerFactory.getLogger(CachingOidcClaimsProvider.class);

  private final OidcUserInfoFetcher fetcher;
  private final Map<String, String> userInfoUriByIssuer;
  private final Cache<String, Map<String, Object>> cache;
  private final MeterRegistry meterRegistry; // nullable — metrics are optional

  CachingOidcClaimsProvider(
      final OidcUserInfoFetcher fetcher,
      final Map<String, String> userInfoUriByIssuer,
      final OidcUserInfoAugmentationConfiguration config,
      final MeterRegistry meterRegistry) {
    this.fetcher = fetcher;
    this.userInfoUriByIssuer = Map.copyOf(userInfoUriByIssuer);
    this.meterRegistry = meterRegistry;
    this.cache =
        Caffeine.newBuilder()
            .maximumSize(config.getCacheMaxSize())
            .expireAfter(
                new Expiry<String, Map<String, Object>>() {
                  @Override
                  public long expireAfterCreate(
                      final String key, final Map<String, Object> value, final long currentTime) {
                    return isNegative(value)
                        ? config.getNegativeCacheTtl().toNanos()
                        : config.getCacheTtl().toNanos();
                  }

                  @Override
                  public long expireAfterUpdate(
                      final String key,
                      final Map<String, Object> value,
                      final long currentTime,
                      final long currentDuration) {
                    return currentDuration;
                  }

                  @Override
                  public long expireAfterRead(
                      final String key,
                      final Map<String, Object> value,
                      final long currentTime,
                      final long currentDuration) {
                    return currentDuration;
                  }
                })
            .build();
  }

  @Override
  public Map<String, Object> claimsFor(
      final Map<String, Object> jwtClaims, final String tokenValue) {
    final String issuer = (String) jwtClaims.get("iss");
    if (issuer == null) {
      LOG.warn("JWT has no 'iss' claim; returning JWT claims unchanged");
      return jwtClaims;
    }

    final String userInfoUri = userInfoUriByIssuer.get(issuer);

    if (userInfoUri == null || userInfoUri.isBlank()) {
      LOG.warn(
          "No UserInfo URI configured for issuer '{}'; returning JWT claims unchanged", issuer);
      return jwtClaims;
    }

    final Map<String, Object> cached = cache.getIfPresent(tokenValue);
    if (cached != null) {
      if (isNegative(cached)) {
        recordCacheResult(issuer, "negative_hit");
        return jwtClaims;
      }
      recordCacheResult(issuer, "hit");
      return cached;
    }

    recordCacheResult(issuer, "miss");
    return fetchAndCache(jwtClaims, tokenValue, issuer, userInfoUri);
  }

  private Map<String, Object> fetchAndCache(
      final Map<String, Object> jwtClaims,
      final String tokenValue,
      final String issuer,
      final String userInfoUri) {
    final long startNanos = System.nanoTime();
    try {
      final Map<String, Object> userInfoClaims = fetcher.fetch(userInfoUri, tokenValue);
      validateSub(jwtClaims, userInfoClaims, issuer);
      final Map<String, Object> merged = merge(jwtClaims, userInfoClaims);
      recordFetch(issuer, "success", System.nanoTime() - startNanos);
      cache.put(tokenValue, merged);
      return merged;
    } catch (final Exception e) {
      LOG.error(
          "UserInfo fetch failed for issuer '{}' at '{}': {}; returning JWT claims unchanged",
          issuer,
          userInfoUri,
          e.getMessage(),
          e);
      recordFetch(issuer, "failure", System.nanoTime() - startNanos);
      storeNegativeEntry(tokenValue, jwtClaims);
      return jwtClaims;
    }
  }

  private void storeNegativeEntry(final String tokenValue, final Map<String, Object> jwtClaims) {
    final Map<String, Object> negative = new HashMap<>(jwtClaims);
    negative.put(NEGATIVE_SENTINEL, Boolean.TRUE);
    cache.put(tokenValue, negative);
  }

  private static void validateSub(
      final Map<String, Object> jwtClaims,
      final Map<String, Object> userInfoClaims,
      final String issuer) {
    final Object jwtSub = jwtClaims.get("sub");
    final Object userInfoSub = userInfoClaims.get("sub");
    if (jwtSub != null && !jwtSub.equals(userInfoSub)) {
      throw new IllegalStateException(
          "OIDC §5.3.2 sub mismatch for issuer '"
              + issuer
              + "': JWT sub='"
              + jwtSub
              + "' but UserInfo sub='"
              + userInfoSub
              + "'");
    }
  }

  private static Map<String, Object> merge(
      final Map<String, Object> jwtClaims, final Map<String, Object> userInfoClaims) {
    final Map<String, Object> merged = new HashMap<>(userInfoClaims);
    merged.putAll(jwtClaims); // JWT always wins on conflict
    return merged;
  }

  private static boolean isNegative(final Map<String, Object> entry) {
    return Boolean.TRUE.equals(entry.get(NEGATIVE_SENTINEL));
  }

  private void recordCacheResult(final String issuer, final String result) {
    if (meterRegistry == null) {
      return;
    }
    meterRegistry
        .counter(
            "camunda.oidc.userinfo.cache",
            "issuer",
            issuer != null ? issuer : "unknown",
            "result",
            result)
        .increment();
  }

  private void recordFetch(final String issuer, final String outcome, final long durationNanos) {
    if (meterRegistry == null) {
      return;
    }
    meterRegistry
        .timer(
            "camunda.oidc.userinfo.fetch",
            "issuer",
            issuer != null ? issuer : "unknown",
            "outcome",
            outcome)
        .record(durationNanos, TimeUnit.NANOSECONDS);
  }
}
