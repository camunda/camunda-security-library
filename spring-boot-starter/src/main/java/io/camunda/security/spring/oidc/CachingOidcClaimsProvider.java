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
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.api.model.config.oidc.OidcUserInfoAugmentationConfiguration;
import io.micrometer.core.instrument.MeterRegistry;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.util.StringUtils;

/**
 * {@link OidcClaimsProvider} that enriches JWT claims with additional claims from the OIDC UserInfo
 * endpoint. Claims are cached by token identity ({@code iss+jti}, falling back to {@code
 * iss+sub+iat+exp}) so no bearer-token material is held in cache key space. A negative cache entry
 * is stored on any fetch failure so a degraded IdP does not hammer retries. JWT claims always win
 * on conflict (JWT-wins invariant, see ADR-0007).
 */
public final class CachingOidcClaimsProvider implements OidcClaimsProvider {

  /**
   * Singleton negative-cache entry. Detected by reference equality ({@code entry ==
   * NEGATIVE_ENTRY}), so there is no collision risk with real claim keys from a UserInfo response.
   */
  static final Map<String, Object> NEGATIVE_ENTRY = Collections.unmodifiableMap(new HashMap<>());

  private static final Logger LOG = LoggerFactory.getLogger(CachingOidcClaimsProvider.class);

  private final OidcUserInfoFetcher fetcher;
  private final Function<String, String> userInfoUriByIssuer;
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

  CachingOidcClaimsProvider(
      final OidcUserInfoFetcher fetcher,
      final Function<String, String> userInfoUriByIssuer,
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
    this(fetcher, Map.copyOf(userInfoUriByIssuer)::get, config, meterRegistry, ticker);
  }

  /**
   * Package-private — for tests only. Accepts a custom {@link Ticker} to enable virtual-time TTL
   * testing.
   */
  CachingOidcClaimsProvider(
      final OidcUserInfoFetcher fetcher,
      final Function<String, String> userInfoUriByIssuer,
      final OidcUserInfoAugmentationConfiguration config,
      final MeterRegistry meterRegistry,
      final Ticker ticker) {
    this.fetcher = fetcher;
    this.userInfoUriByIssuer = userInfoUriByIssuer;
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

  /**
   * Builds a provider for wiring that has decided augmentation should run, requiring at least one
   * issuer→userInfoUri mapping. Throws {@link IllegalStateException} on an empty map — augmentation
   * is enabled yet nothing could ever be augmented, a config mismatch the operator must notice
   * rather than have the setup silently run un-augmented.
   *
   * <p>The constructors deliberately stay tolerant of an empty map (a token whose issuer is
   * unmapped is passed through unaugmented); this factory layers the "must be usefully configured"
   * policy on top, so both the cluster and per-scope wiring share one check.
   */
  static CachingOidcClaimsProvider forConfiguredMappings(
      final OidcUserInfoFetcher fetcher,
      final Map<String, String> userInfoUriByIssuer,
      final OidcUserInfoAugmentationConfiguration config,
      final MeterRegistry meterRegistry) {
    if (userInfoUriByIssuer.isEmpty()) {
      throw new IllegalStateException(
          "UserInfo augmentation is enabled but no OIDC provider yields an issuer→userInfoUri"
              + " mapping, so no claims can be augmented — the setup would silently run without"
              + " augmentation. A mapping is derived only when a provider has BOTH an issuer-uri AND"
              + " a userInfoUri (userinfo endpoint); a provider missing either is skipped. Ensure"
              + " each provider has an issuer-uri and that UserInfo is enabled"
              + " (camunda.security.authentication.oidc.user-info-enabled=true, the default, or the"
              + " per-provider camunda.security.authentication.providers.oidc.<id>.user-info-enabled"
              + " flag in multi-provider setups) and that the IdP's discovery document includes a"
              + " userinfo_endpoint, or disable"
              + " userinfo augmentation.");
    }
    return new CachingOidcClaimsProvider(fetcher, userInfoUriByIssuer, config, meterRegistry);
  }

  /**
   * Resolves the endpoint of one issuer at a time, through {@code registrations}, so an identity
   * provider that does not answer fails the tokens of its own issuer only.
   *
   * <p>An unknown issuer, and an issuer whose owner disables UserInfo, give no endpoint, and the
   * token passes unaugmented. The configuration answers them, so their tokens also stay up while
   * their provider is unreachable. A provider that enables UserInfo and exposes no endpoint fails
   * its tokens, because the claims would otherwise lose the attributes that authorization needs.
   * Such a failure, and a failed resolution, are server errors, because the token is not the
   * reason.
   *
   * @throws IllegalStateException if no provider can ever give an endpoint. The configuration shows
   *     this, so such a setup stops the start instead of running without augmentation.
   */
  static Function<String, String> userInfoUriByIssuer(
      final IssuerRegistrations registrations, final Map<String, OidcConfiguration> providers) {
    final var issuersWithUserInfo = issuersWithUserInfo(registrations, providers);
    if (issuersWithUserInfo.isEmpty()) {
      throw new IllegalStateException(
          "UserInfo augmentation is enabled but no OIDC provider can yield an issuer→userInfoUri"
              + " mapping, so no claims can be augmented — the setup would silently run without"
              + " augmentation. A provider yields a mapping only when it declares an issuer-uri AND"
              + " UserInfo is enabled for it"
              + " (camunda.security.authentication.oidc.user-info-enabled=true, the default, or the"
              + " per-provider camunda.security.authentication.providers.oidc.<id>.user-info-enabled"
              + " flag in multi-provider setups). Give each provider an issuer-uri, or disable"
              + " userinfo augmentation.");
    }
    return issuer -> {
      if (!issuersWithUserInfo.contains(issuer)) {
        // An unknown issuer, and an issuer whose owner disables UserInfo, need no endpoint. To
        // answer them here keeps their tokens up while their provider is unreachable, because the
        // resolution below makes OIDC discovery.
        return null;
      }
      final ClientRegistration registration;
      try {
        registration = registrations.forIssuer(issuer);
      } catch (final AuthenticationException alreadyClassified) {
        throw alreadyClassified;
      } catch (final RuntimeException unresolved) {
        throw new AuthenticationServiceException(
            "Failed to resolve the UserInfo endpoint of issuer '%s': %s"
                .formatted(issuer, unresolved.getMessage()),
            unresolved);
      }
      if (registration == null) {
        return null;
      }
      final var userInfoUri = registration.getProviderDetails().getUserInfoEndpoint().getUri();
      if (!StringUtils.hasText(userInfoUri)) {
        throw new AuthenticationServiceException(
            ("UserInfo augmentation is enabled for issuer '%s' but the provider exposes no"
                    + " userInfoUri, so its claims cannot be augmented. Ensure the discovery"
                    + " document of the issuer includes a userinfo_endpoint, or configure"
                    + " user-info-uri explicitly, or turn UserInfo off for the provider"
                    + " (user-info-enabled=false).")
                .formatted(issuer));
      }
      return userInfoUri;
    };
  }

  /**
   * The issuers whose owning provider must expose a UserInfo endpoint. The owner answers for its
   * issuer, because {@code registrations} resolves the registration of that provider alone, and a
   * request reads no UserInfo flag of an ignored duplicate. The configuration gives the answer, so
   * the method needs no network access.
   */
  private static Set<String> issuersWithUserInfo(
      final IssuerRegistrations registrations, final Map<String, OidcConfiguration> providers) {
    return registrations.issuers().stream()
        .filter(
            issuer -> {
              final var owner = providers.get(registrations.resolutionKeyOf(issuer));
              return owner != null && owner.isUserInfoEnabled();
            })
        .collect(Collectors.toSet());
  }

  /**
   * Whether a UserInfo endpoint can augment this token at all. No provider configuration takes part
   * in the answer, so a caller asks this before it resolves an endpoint.
   */
  static boolean canAugment(final Map<String, Object> jwtClaims, final String tokenValue) {
    if (tokenValue == null || tokenValue.isBlank()) {
      LOG.debug("Token value is absent; returning JWT claims unchanged");
      return false;
    }
    final String issuer = jwtClaims.get("iss") instanceof final String s ? s : null;
    if (issuer == null) {
      LOG.debug("JWT has no 'iss' claim; returning JWT claims unchanged");
      return false;
    }
    if (!hasOpenidScope(jwtClaims)) {
      LOG.debug("JWT for issuer '{}' has no openid scope; skipping UserInfo augmentation", issuer);
      return false;
    }
    return true;
  }

  @Override
  public Map<String, Object> claimsFor(
      final Map<String, Object> jwtClaims, final String tokenValue) {
    if (!canAugment(jwtClaims, tokenValue)) {
      return jwtClaims;
    }
    final String issuer = (String) jwtClaims.get("iss");

    final String userInfoUri = userInfoUriByIssuer.apply(issuer);

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
    if (userInfoSub == null) {
      // OIDC §5.3.2 requires the UserInfo response to contain sub. A missing sub means we cannot
      // bind the response to any subject — reject to prevent merging unbounded claims.
      throw new IllegalStateException(
          "UserInfo response from issuer '"
              + issuer
              + "' is missing the required 'sub' claim (OIDC §5.3.2)");
    }
    if (jwtSub == null) {
      throw new IllegalStateException(
          "UserInfo sub='"
              + userInfoSub
              + "' for issuer '"
              + issuer
              + "' but JWT has no 'sub'; rejecting to prevent subject injection");
    }
    if (!jwtSub.equals(userInfoSub)) {
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
      // Two distinct tokens for the same subject issued within the same second with no jti will
      // share this key. The window is extremely narrow and the behaviour is identical to the
      // monorepo reference; the worst outcome is serving a cached merged map from one token to
      // the other for the same user, which is acceptable given the short TTL.
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
   * <p>Checks {@code scope} as a space-separated string (RFC 8693) or as a {@link
   * java.util.Collection} (non-standard but seen in the wild), and {@code scp} as an {@link
   * Iterable} (used by some IdPs including Microsoft).
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
    if (scope instanceof final Iterable<?> list) {
      for (final Object item : list) {
        if ("openid".equals(item)) {
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
