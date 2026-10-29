/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static io.camunda.security.spring.scope.OidcScopeRuntimeTest.deliverCode;
import static io.camunda.security.spring.scope.OidcScopeRuntimeTest.logIn;
import static io.camunda.security.spring.scope.OidcScopeRuntimeTest.runner;
import static io.camunda.security.spring.scope.OidcScopeRuntimeTest.sessionCookie;
import static io.camunda.security.spring.scope.OidcScopeRuntimeTest.startLogIn;
import static io.camunda.security.spring.scope.ScopeRuntimeTestSupport.proxy;
import static io.camunda.security.spring.scope.ScopeRuntimeTestSupport.reloadPort;
import static java.nio.file.StandardCopyOption.ATOMIC_MOVE;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import io.camunda.security.api.model.config.AssertionConfiguration;
import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.AuthenticationMethod;
import io.camunda.security.api.model.config.KeystoreConfiguration;
import io.camunda.security.api.model.config.ScopedSecurityDescriptor;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.api.model.scope.ScopeReloadOutcome;
import io.camunda.security.spring.scope.MockIdentityProvider.TokenRequest;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * {@code private_key_jwt} credentials of a scope rotated at runtime: a keystore replaced at the
 * same path, and a keystore at a new path.
 */
class AssertionKeyRotationTest {

  private static final String SCOPE = "/tenants/assertion";
  private static final String ALIAS = "camunda-standalone";
  private static final char[] PASSWORD = "password".toCharArray();

  @TempDir Path keystores;
  private MockIdentityProvider idp;

  @BeforeEach
  void startIdp() throws Exception {
    idp = MockIdentityProvider.start();
  }

  @AfterEach
  void stopIdp() {
    idp.close();
  }

  @Test
  void shouldSignWithTheKeystoreReplacedAtTheSamePathOnceRefreshed() throws Exception {
    // given
    final var path = keystores.resolve("client.p12");
    final var firstKey = writeKeystore(path, "keystore.p12", "camunda-standalone");
    idp.acceptAssertionKeys("app", firstKey);
    idp.setAccessTokenLifetimeSeconds(1);
    runner()
        .run(
            ctx -> {
              reloadPort(ctx).apply(privateKeyJwt(path)).orThrow();
              final var existingSession = new TestBrowser(proxy(ctx));
              logIn(existingSession, idp, SCOPE, "app");
              final var secondKey = writeKeystore(path, "keystore-second.p12", "camunda-second");
              idp.acceptAssertionKeys("app", secondKey);
              final var beforeRefresh = new TestBrowser(proxy(ctx));
              deliverCode(
                  beforeRefresh, idp, SCOPE, "app", startLogIn(beforeRefresh, idp, SCOPE, "oidc"));

              // when
              final var result = reloadPort(ctx).refreshCredentials(SCOPE);

              // then
              assertThat(beforeRefresh.get(SCOPE + "/app/home").served())
                  .as("the generation keeps the key it read")
                  .isFalse();
              assertThat(result.outcome()).isEqualTo(ScopeReloadOutcome.CREDENTIALS_REFRESHED);
              final var afterRefresh = new TestBrowser(proxy(ctx));
              logIn(afterRefresh, idp, SCOPE, "app");
              assertThat(afterRefresh.get(SCOPE + "/app/home").status()).isEqualTo(200);
              final var session = existingSession.cookie(sessionCookie(SCOPE));
              await()
                  .atMost(Duration.ofSeconds(10))
                  .pollInterval(Duration.ofMillis(250))
                  .untilAsserted(
                      () -> {
                        assertThat(existingSession.get(SCOPE + "/app/home").status())
                            .isEqualTo(200);
                        assertThat(grantedRefreshes()).isNotEmpty();
                      });
              assertThat(existingSession.cookie(sessionCookie(SCOPE))).isEqualTo(session);
              assertThat(idp.tokenRequests())
                  .filteredOn(request -> !request.granted())
                  .hasSize(1)
                  .allMatch(request -> "authorization_code".equals(request.grantType()));
            });
  }

  @Test
  void shouldSignWithAKeystoreAtANewPathWithoutEndingSessions() throws Exception {
    // given
    final var firstPath = keystores.resolve("first.p12");
    final var secondPath = keystores.resolve("second.p12");
    idp.acceptAssertionKeys("app", writeKeystore(firstPath, "keystore.p12", "camunda-standalone"));
    final var secondKey = writeKeystore(secondPath, "keystore-second.p12", "camunda-second");
    runner()
        .run(
            ctx -> {
              reloadPort(ctx).apply(privateKeyJwt(firstPath)).orThrow();
              final var browser = new TestBrowser(proxy(ctx));
              logIn(browser, idp, SCOPE, "app");
              idp.acceptAssertionKeys("app", secondKey);

              // when
              final var result = reloadPort(ctx).rotateCredentials(privateKeyJwt(secondPath));

              // then
              assertThat(result.outcome()).isEqualTo(ScopeReloadOutcome.CREDENTIALS_ROTATED);
              assertThat(browser.get(SCOPE + "/app/home").status()).isEqualTo(200);
              final var next = new TestBrowser(proxy(ctx));
              logIn(next, idp, SCOPE, "app");
              assertThat(idp.tokenRequests()).allMatch(TokenRequest::granted);
            });
  }

  private List<TokenRequest> grantedRefreshes() {
    return idp.tokenRequests().stream()
        .filter(request -> "refresh_token".equals(request.grantType()) && request.granted())
        .toList();
  }

  private ScopedSecurityDescriptor privateKeyJwt(final Path keystore) {
    final var auth = new AuthenticationConfiguration();
    auth.setMethod(AuthenticationMethod.OIDC);
    auth.setOidc(
        OidcConfiguration.builder()
            .issuerUri(idp.issuer())
            .clientId("app")
            .scope(List.of("openid"))
            .clientAuthenticationMethod(
                OidcConfiguration.CLIENT_AUTHENTICATION_METHOD_PRIVATE_KEY_JWT)
            .assertionConfiguration(
                AssertionConfiguration.builder()
                    .keystoreConfiguration(
                        KeystoreConfiguration.builder()
                            .path(keystore.toString())
                            .password("password")
                            .keyAlias(ALIAS)
                            .keyPassword("password")
                            .build())
                    .build())
            .build());
    return new ScopedSecurityDescriptor(SCOPE, auth);
  }

  /**
   * Writes the key of a test keystore under {@link #ALIAS} to {@code target}, replacing what is
   * there, and returns its public key.
   */
  private static RSAPublicKey writeKeystore(
      final Path target, final String resource, final String sourceAlias) throws Exception {
    final var source = KeyStore.getInstance("PKCS12");
    try (final var in =
        Objects.requireNonNull(
            AssertionKeyRotationTest.class.getClassLoader().getResourceAsStream(resource))) {
      source.load(in, PASSWORD);
    }
    final var chain = source.getCertificateChain(sourceAlias);
    final var keystore = KeyStore.getInstance("PKCS12");
    keystore.load(null, null);
    keystore.setKeyEntry(ALIAS, source.getKey(sourceAlias, PASSWORD), PASSWORD, chain);
    final var written = target.resolveSibling(target.getFileName() + ".tmp");
    try (final var out = Files.newOutputStream(written)) {
      keystore.store(out, PASSWORD);
    }
    Files.move(written, target, REPLACE_EXISTING, ATOMIC_MOVE);
    return (RSAPublicKey) chain[0].getPublicKey();
  }
}
