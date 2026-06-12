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
import com.github.benmanes.caffeine.cache.Ticker;
import io.camunda.security.api.context.OidcClaimsProvider;
import io.camunda.security.api.model.config.oidc.OidcUserInfoAugmentationConfiguration;
import io.micrometer.core.instrument.MeterRegistry;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link OidcClaimsProvider} that enriches JWT claims with additional claims from the OIDC UserInfo
 * endpoint. Claims are cached by token identity ({@code iss+jti}, falling back to {@code
 * iss+sub+iat+exp}) so no bearer-token material is held in cache key space. A negative cache entry
 * is stored on any fetch failure so a degraded IdP does not hammer retries. JWT claims always win
 * on conflict (JWT-wins invariant, see ADR-0026).
 */
public final class CachingOidcClaimsProvider implements OidcClaimsProvider {

  /**
   * Singleton negative-cache entry. Detected by reference equality ({@code entry ==
   * NEGATIVE_ENTRY}), so there is no collision risk with real claim keys from a UserInfo response.
   */
  static final Map<String, Object> NEGATIVE_ENTRY = Collections.unmodifiableMap(new HashMap<>());

  private static final Logger LOG = LoggerFactory.getLogger(CachingOidcClaimsProvider.class);

  private final OidcUserInfoFetcher fetcher;
  private final Map<String, String> userInfoUriByIssuer;
  private final Cache<String, Map<String, Object>> cache;
  private final MeterRegistry meterRegistry; // nullable — metrics are optional
  private final long cacheTtlNanos;
  private final long negativeCacheTtlNanos;

  CachingOidcClaimsProvider(
      final OidcUserInfoFetcher fetcher,
      final Map<String, String> userInfoUriByIssuer,
      final OidcUserInfoAugmentationConfiguration config,
      final MeterRegistry meterRegistry) {
    this(fetcher, userInfoUriByIssuer, config, meterRegistry, Ticker.systemTicker());
  }

  /**
   * Package-private — for tests only. Accepts a custom {@link Ticker} to enable virtual-time TTL
   * testing.
   */
  CachingOidcClaimsProvider(
      final OidcUserInfoFetcher fetcher,
      final Map<String, String> userInfoUriByIssuer,
      final OidcUserInfoAugmentationConfiguration config,
      final MeterRegistry meterRegistry,
      final Ticker ticker) {
    this.fetcher = fetcher;
    this.userInfoUriByIssuer = Map.copyOf(userInfoUriByIssuer);
    this.meterRegistry = meterRegistry;
    this.cacheTtlNanos =
        Objects.requireNonNull(config.getCacheTtl(), "cache-ttl must not be null").toNanos();
    this.negativeCacheTtlNanos =
        Objects.requireNonNull(config.getNegativeCacheTtl(), "negative-cache-ttl must not be null")
            .toNanos();
    this.cache =
        Caffeine.newBuilder()
            .maximumSize(config.getCacheMaxSize())
            .ticker(ticker)
            .expireAfter(
                new Expiry<String, Map<String, Object>>() {
                  @Override
                  public long expireAfterCreate(
                      final String key, final Map<String, Object> value, final long currentTime) {
                    return isNegative(value) ? negativeCacheTtlNanos : cacheTtlNanos;
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
    if (tokenValue == null || tokenValue.isBlank()) {
      LOG.debug("Token value is absent; returning JWT claims unchanged");
      return jwtClaims;
    }
    final String issuer = jwtClaims.get("iss") instanceof final String s ? s : null;
    if (issuer == null) {
      LOG.debug("JWT has no 'iss' claim; returning JWT claims unchanged");
      return jwtClaims;
    }

    if (!hasOpenidScope(jwtClaims)) {
      LOG.debug("JWT for issuer '{}' has no openid scope; skipping UserInfo augmentation", issuer);
      return jwtClaims;
    }

    final String userInfoUri = userInfoUriByIssuer.get(issuer);

    if (userInfoUri == null || userInfoUri.isBlank()) {
      LOG.debug(
          "No UserInfo URI configured for issuer '{}'; returning JWT claims unchanged", issuer);
      return jwtClaims;
    }

    final String key = cacheKey(jwtClaims);
    if (key == null) {
      // JWT has no jti and lacks sub+iat+exp — no stable key available; bypass cache and
      // fetch once for this request. Rare in practice; every mainstream IdP includes at
      // least sub+iat+exp on access tokens.
      recordCacheResult(issuer, "miss");
      final Map<String, Object> result = fetchEntry(jwtClaims, tokenValue, userInfoUri, issuer);
      return isNegative(result) ? jwtClaims : result;
    }

    final Map<String, Object> cached = cache.getIfPresent(key);
    if (cached != null) {
      if (isNegative(cached)) {
        recordCacheResult(issuer, "negative_hit");
        return jwtClaims;
      }
      recordCacheResult(issuer, "hit");
      return cached;
    }

    // Miss: cache.get() is atomic per key — at most one fetch in flight per token identity,
    // preventing stampedes when many concurrent requests arrive with the same bearer token.
    recordCacheResult(issuer, "miss");
    final Map<String, Object> entry =
        cache.get(key, k -> fetchEntry(jwtClaims, tokenValue, userInfoUri, issuer));
    return isNegative(entry) ? jwtClaims : entry;
  }

  private Map<String, Object> fetchEntry(
      final Map<String, Object> jwtClaims,
      final String tokenValue,
      final String userInfoUri,
      final String issuer) {
    final long startNanos = System.nanoTime();
    try {
      final Map<String, Object> userInfoClaims = fetcher.fetch(userInfoUri, tokenValue);
      validateSub(jwtClaims, userInfoClaims, issuer);
      // unmodifiableMap instead of Map.copyOf: preserves null claim values from
      // UserInfo responses that Map.copyOf would reject with NullPointerException.
      final Map<String, Object> merged =
          Collections.unmodifiableMap(merge(jwtClaims, userInfoClaims));
      recordFetch(issuer, "success", System.nanoTime() - startNanos);
      return merged;
    } catch (final Exception e) {
      LOG.error(
          "UserInfo fetch failed for issuer '{}' at '{}': {}; returning JWT claims unchanged",
          issuer,
          userInfoUri,
          e.getMessage(),
          e);
      recordFetch(issuer, "failure", System.nanoTime() - startNanos);
      return NEGATIVE_ENTRY;
    }
  }

  private static void validateSub(
      final Map<String, Object> jwtClaims,
      final Map<String, Object> userInfoClaims,
      final String issuer) {
    final Object jwtSub = jwtClaims.get("sub");
    final Object userInfoSub = userInfoClaims.get("sub");
    if (jwtSub == null && userInfoSub != null) {
      throw new IllegalStateException(
          "UserInfo sub='"
              + userInfoSub
              + "' for issuer '"
              + issuer
              + "' but JWT has no 'sub'; rejecting to prevent subject injection");
    }
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

  /**
   * Derives a cache key from JWT claims without storing any bearer-token material. The {@code iss}
   * prefix is required because {@code jti} is only unique per issuer (RFC 7519 §4.1.7); two
   * providers can legitimately issue tokens with identical {@code jti} values. Returns {@code null}
   * when neither {@code jti} nor the {@code sub+iat+exp} fallback tuple are usable; callers should
   * bypass the cache for that request.
   */
  private static String cacheKey(final Map<String, Object> jwtClaims) {
    final Object iss = jwtClaims.get("iss");
    if (!(iss instanceof final String issuer) || issuer.isBlank()) {
      return null;
    }
    final Object jti = jwtClaims.get("jti");
    if (jti instanceof final String s && !s.isBlank()) {
      // \0 separator: JWT claim values are JSON-decoded strings and cannot contain literal null
      // bytes, so this delimiter is collision-free regardless of issuer or jti content.
      return "jti\0" + issuer + "\0" + s;
    }
    final Object sub = jwtClaims.get("sub");
    final Long iat = epochSecond(jwtClaims.get("iat"));
    final Long exp = epochSecond(jwtClaims.get("exp"));
    if (sub instanceof String && iat != null && exp != null) {
      return "sie\0" + issuer + "\0" + sub + "\0" + iat + "\0" + exp;
    }
    return null;
  }

  private static Long epochSecond(final Object value) {
    if (value instanceof final Instant i) {
      return i.getEpochSecond();
    }
    if (value instanceof final Number n) {
      return n.longValue();
    }
    return null;
  }

  /**
   * Returns {@code true} when the JWT carries the {@code openid} scope. OIDC §5.3 only defines the
   * UserInfo endpoint for openid-scoped tokens; M2M / client-credentials tokens typically lack it.
   * Skipping augmentation for out-of-scope tokens avoids guaranteed-to-fail fetches and the ERROR
   * noise and negative-cache churn they produce.
   *
   * <p>Checks {@code scope} (space-separated string, RFC 8693) and {@code scp} (list, used by some
   * IdPs including Microsoft) so that both claim shapes are handled.
   */
  static boolean hasOpenidScope(final Map<String, Object> jwtClaims) {
    final Object scope = jwtClaims.get("scope");
    if (scope instanceof final String s) {
      for (final String part : s.split("\\s+")) {
        if ("openid".equals(part)) {
          return true;
        }
      }
    }
    final Object scp = jwtClaims.get("scp");
    if (scp instanceof final Iterable<?> list) {
      for (final Object item : list) {
        if ("openid".equals(item)) {
          return true;
        }
      }
    }
    return false;
  }

  private static boolean isNegative(final Map<String, Object> entry) {
    return entry == NEGATIVE_ENTRY;
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
