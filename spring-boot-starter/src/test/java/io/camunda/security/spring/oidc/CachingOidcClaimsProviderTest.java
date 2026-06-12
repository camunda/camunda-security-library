/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import io.camunda.security.api.model.config.oidc.OidcUserInfoAugmentationConfiguration;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class CachingOidcClaimsProviderTest {

  private static final String ISSUER = "https://idp.example";
  private static final String USER_INFO_URI = "https://idp.example/userinfo";
  private static final Map<String, String> URI_BY_ISSUER = Map.of(ISSUER, USER_INFO_URI);

  @Mock private OidcUserInfoFetcher fetcher;

  private CachingOidcClaimsProvider provider(final Map<String, String> uriByIssuer) {
    return new CachingOidcClaimsProvider(fetcher, uriByIssuer, defaultConfig(), null);
  }

  private static OidcUserInfoAugmentationConfiguration defaultConfig() {
    return new OidcUserInfoAugmentationConfiguration();
  }

  // --- Merge logic ---

  @Test
  void jwtClaimsWinOnConflictWithUserInfoClaims() {
    when(fetcher.fetch(any(), any()))
        .thenReturn(Map.of("sub", "alice", "groups", List.of("eng"), "exp", 1111L));
    final Map<String, Object> jwt = Map.of("sub", "alice", "iss", ISSUER, "exp", 9999L);

    final Map<String, Object> result = provider(URI_BY_ISSUER).claimsFor(jwt, "tok");

    assertThat(result).containsEntry("sub", "alice"); // JWT wins
    assertThat(result).containsEntry("exp", 9999L); // JWT-only claim preserved
    assertThat(result).containsKey("groups"); // UserInfo-only claim contributed
  }

  @Test
  void userInfoResponseWithNullClaimValueDoesNotThrow() {
    final Map<String, Object> userInfoWithNull = new HashMap<>();
    userInfoWithNull.put("sub", "alice");
    userInfoWithNull.put("department", null); // JSON null — valid in UserInfo responses
    when(fetcher.fetch(any(), any())).thenReturn(userInfoWithNull);
    final Map<String, Object> jwt = Map.of("sub", "alice", "iss", ISSUER);

    final Map<String, Object> result = provider(URI_BY_ISSUER).claimsFor(jwt, "tok");

    assertThat(result).containsEntry("sub", "alice");
    // null-valued UserInfo claims are included without throwing NullPointerException
    assertThat(result).containsKey("department");
  }

  @Test
  void userInfoOnlyClaimsAreAddedToJwtClaims() {
    when(fetcher.fetch(any(), any()))
        .thenReturn(Map.of("sub", "alice", "groups", List.of("eng"), "org", "acme"));
    final Map<String, Object> jwt = Map.of("sub", "alice", "iss", ISSUER);

    final Map<String, Object> result = provider(URI_BY_ISSUER).claimsFor(jwt, "tok");

    assertThat(result).containsEntry("groups", List.of("eng"));
    assertThat(result).containsEntry("org", "acme");
  }

  // --- Cache ---

  @Test
  void cacheHitDoesNotCallFetcherAgain() {
    when(fetcher.fetch(any(), any())).thenReturn(Map.of("sub", "alice", "groups", List.of("eng")));
    final Map<String, Object> jwt = Map.of("sub", "alice", "iss", ISSUER);
    final var p = provider(URI_BY_ISSUER);

    p.claimsFor(jwt, "tok1");
    p.claimsFor(jwt, "tok1");

    verify(fetcher, times(1)).fetch(any(), any());
  }

  @Test
  void differentTokensAreFetchedSeparately() {
    when(fetcher.fetch(any(), any())).thenReturn(Map.of("sub", "alice", "groups", List.of("eng")));
    final Map<String, Object> jwt = Map.of("sub", "alice", "iss", ISSUER);
    final var p = provider(URI_BY_ISSUER);

    p.claimsFor(jwt, "tok1");
    p.claimsFor(jwt, "tok2");

    verify(fetcher, times(2)).fetch(any(), any());
  }

  // --- Per-issuer routing ---

  @Test
  void tokenFromIssuerAIsRoutedToIssuerAUserInfoUri() {
    final String issuerA = "https://idp-a.example";
    final String issuerB = "https://idp-b.example";
    when(fetcher.fetch(eq("https://idp-a.example/userinfo"), any()))
        .thenReturn(Map.of("sub", "alice", "groups", List.of("a")));
    final Map<String, String> uriMap =
        Map.of(
            issuerA, "https://idp-a.example/userinfo",
            issuerB, "https://idp-b.example/userinfo");
    final Map<String, Object> jwtA = Map.of("sub", "alice", "iss", issuerA);

    provider(uriMap).claimsFor(jwtA, "tok-a");

    verify(fetcher).fetch("https://idp-a.example/userinfo", "tok-a");
    verify(fetcher, never()).fetch(eq("https://idp-b.example/userinfo"), any());
  }

  @Test
  void unknownIssuerReturnsJwtClaimsWithoutFetching() {
    final Map<String, Object> jwt = Map.of("sub", "alice", "iss", "https://unknown.idp.example");

    final Map<String, Object> result = provider(URI_BY_ISSUER).claimsFor(jwt, "tok");

    assertThat(result).isSameAs(jwt);
    verifyNoInteractions(fetcher);
  }

  @Test
  void missingIssuerClaimReturnsJwtClaimsWithoutFetching() {
    final Map<String, Object> jwt = Map.of("sub", "alice"); // no iss

    final Map<String, Object> result = provider(URI_BY_ISSUER).claimsFor(jwt, "tok");

    assertThat(result).isSameAs(jwt);
    verifyNoInteractions(fetcher);
  }

  @Test
  void nullTokenValueReturnsJwtClaimsWithoutFetching() {
    final Map<String, Object> jwt = Map.of("sub", "alice", "iss", ISSUER);

    final Map<String, Object> result = provider(URI_BY_ISSUER).claimsFor(jwt, null);

    assertThat(result).isSameAs(jwt);
    verifyNoInteractions(fetcher);
  }

  @Test
  void blankTokenValueReturnsJwtClaimsWithoutFetching() {
    final Map<String, Object> jwt = Map.of("sub", "alice", "iss", ISSUER);

    assertThat(provider(URI_BY_ISSUER).claimsFor(jwt, "")).isSameAs(jwt);
    assertThat(provider(URI_BY_ISSUER).claimsFor(jwt, "   ")).isSameAs(jwt);
    verifyNoInteractions(fetcher);
  }

  // --- Fail-open and sub validation ---

  @Test
  void failOpenOnFetchException() {
    when(fetcher.fetch(any(), any())).thenThrow(new OidcUserInfoFetchException("IdP is down"));
    final Map<String, Object> jwt = Map.of("sub", "alice", "iss", ISSUER);

    final Map<String, Object> result = provider(URI_BY_ISSUER).claimsFor(jwt, "tok");

    assertThat(result).isSameAs(jwt);
  }

  @Test
  void subMismatchTriggersFailOpen() {
    when(fetcher.fetch(any(), any()))
        .thenReturn(Map.of("sub", "mallory", "groups", List.of("admin")));
    final Map<String, Object> jwt = Map.of("sub", "alice", "iss", ISSUER);

    final Map<String, Object> result = provider(URI_BY_ISSUER).claimsFor(jwt, "tok");

    assertThat(result).isSameAs(jwt);
    assertThat(result).doesNotContainKey("groups");
  }

  @Test
  void userInfoSubInjectionWhenJwtHasNoSubTriggersFailOpen() {
    when(fetcher.fetch(any(), any()))
        .thenReturn(Map.of("sub", "injected", "groups", List.of("admin")));
    final Map<String, Object> jwt = Map.of("iss", ISSUER); // no sub in JWT

    final Map<String, Object> result = provider(URI_BY_ISSUER).claimsFor(jwt, "tok");

    assertThat(result).isSameAs(jwt);
    assertThat(result).doesNotContainKey("sub");
    assertThat(result).doesNotContainKey("groups");
  }

  // --- Negative caching ---

  @Test
  void negativeCachePreventsFetchRetryWithinTtl() {
    when(fetcher.fetch(any(), any())).thenThrow(new OidcUserInfoFetchException("IdP is down"));
    final Map<String, Object> jwt = Map.of("sub", "alice", "iss", ISSUER);
    final var p = provider(URI_BY_ISSUER);

    p.claimsFor(jwt, "tok1"); // first call → fails, stores negative entry
    p.claimsFor(jwt, "tok1"); // second call → hits negative cache

    verify(fetcher, times(1)).fetch(any(), any()); // only one real fetch
  }

  @Test
  void negativeCacheReturnsJwtClaimsUnchanged() {
    when(fetcher.fetch(any(), any())).thenThrow(new OidcUserInfoFetchException("down"));
    final Map<String, Object> jwt = Map.of("sub", "alice", "iss", ISSUER);
    final var p = provider(URI_BY_ISSUER);

    p.claimsFor(jwt, "tok1"); // populates negative cache
    final Map<String, Object> second = p.claimsFor(jwt, "tok1"); // negative cache hit

    assertThat(second).isSameAs(jwt);
    assertThat(second).isNotSameAs(CachingOidcClaimsProvider.NEGATIVE_ENTRY);
  }

  // --- Micrometer metrics ---

  @Test
  void recordsCacheMissCounterOnFirstCall() {
    when(fetcher.fetch(any(), any())).thenReturn(Map.of("sub", "alice"));
    final var registry = new SimpleMeterRegistry();
    final var p = new CachingOidcClaimsProvider(fetcher, URI_BY_ISSUER, defaultConfig(), registry);
    final Map<String, Object> jwt = Map.of("sub", "alice", "iss", ISSUER);

    p.claimsFor(jwt, "tok1");

    assertThat(
            registry
                .counter("camunda.oidc.userinfo.cache", "issuer", ISSUER, "result", "miss")
                .count())
        .isEqualTo(1.0);
  }

  @Test
  void recordsCacheHitCounterOnSecondCallWithSameToken() {
    when(fetcher.fetch(any(), any())).thenReturn(Map.of("sub", "alice"));
    final var registry = new SimpleMeterRegistry();
    final var p = new CachingOidcClaimsProvider(fetcher, URI_BY_ISSUER, defaultConfig(), registry);
    final Map<String, Object> jwt = Map.of("sub", "alice", "iss", ISSUER);

    p.claimsFor(jwt, "tok1");
    p.claimsFor(jwt, "tok1");

    assertThat(
            registry
                .counter("camunda.oidc.userinfo.cache", "issuer", ISSUER, "result", "hit")
                .count())
        .isEqualTo(1.0);
  }

  @Test
  void recordsNegativeHitCounterOnNegativeCacheHit() {
    when(fetcher.fetch(any(), any())).thenThrow(new OidcUserInfoFetchException("down"));
    final var registry = new SimpleMeterRegistry();
    final var p = new CachingOidcClaimsProvider(fetcher, URI_BY_ISSUER, defaultConfig(), registry);
    final Map<String, Object> jwt = Map.of("sub", "alice", "iss", ISSUER);

    p.claimsFor(jwt, "tok1"); // miss + fail → negative
    p.claimsFor(jwt, "tok1"); // negative_hit

    assertThat(
            registry
                .counter("camunda.oidc.userinfo.cache", "issuer", ISSUER, "result", "negative_hit")
                .count())
        .isEqualTo(1.0);
  }

  @Test
  void recordsFetchSuccessTimer() {
    when(fetcher.fetch(any(), any())).thenReturn(Map.of("sub", "alice"));
    final var registry = new SimpleMeterRegistry();
    final var p = new CachingOidcClaimsProvider(fetcher, URI_BY_ISSUER, defaultConfig(), registry);
    final Map<String, Object> jwt = Map.of("sub", "alice", "iss", ISSUER);

    p.claimsFor(jwt, "tok1");

    assertThat(
            registry
                .timer("camunda.oidc.userinfo.fetch", "issuer", ISSUER, "outcome", "success")
                .count())
        .isEqualTo(1);
  }

  @Test
  void recordsFetchFailureTimer() {
    when(fetcher.fetch(any(), any())).thenThrow(new OidcUserInfoFetchException("down"));
    final var registry = new SimpleMeterRegistry();
    final var p = new CachingOidcClaimsProvider(fetcher, URI_BY_ISSUER, defaultConfig(), registry);
    final Map<String, Object> jwt = Map.of("sub", "alice", "iss", ISSUER);

    p.claimsFor(jwt, "tok1");

    assertThat(
            registry
                .timer("camunda.oidc.userinfo.fetch", "issuer", ISSUER, "outcome", "failure")
                .count())
        .isEqualTo(1);
  }

  @Test
  void worksWithoutMeterRegistry() {
    when(fetcher.fetch(any(), any())).thenReturn(Map.of("sub", "alice"));
    final var p = provider(URI_BY_ISSUER); // null registry
    final Map<String, Object> jwt = Map.of("sub", "alice", "iss", ISSUER);

    assertThatNoException().isThrownBy(() -> p.claimsFor(jwt, "tok1"));
  }
}
