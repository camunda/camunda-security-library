/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.model.config.AssertionConfiguration;
import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.AuthenticationMethod;
import io.camunda.security.api.model.config.KeystoreConfiguration;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;

class ScopeFingerprintsTest {

  @Test
  void shouldTreatTheClientSecretAsACredential() {
    // when
    final var before = ScopeFingerprints.of(oidc(o -> o.setClientSecret("one")));
    final var after = ScopeFingerprints.of(oidc(o -> o.setClientSecret("two")));

    // then
    assertThat(after.sameAuthenticationAs(before)).isTrue();
    assertThat(after.sameAs(before)).isFalse();
  }

  @Test
  void shouldTreatTheAssertionKeystoreAsACredential() {
    // when
    final var before = ScopeFingerprints.of(oidc(o -> o.setAssertion(assertion("a.p12", "pw"))));
    final var after = ScopeFingerprints.of(oidc(o -> o.setAssertion(assertion("b.p12", "pw2"))));

    // then
    assertThat(after.sameAuthenticationAs(before)).isTrue();
    assertThat(after.sameAs(before)).isFalse();
  }

  @Test
  void shouldTreatTheIssuerAsAuthenticationRelevant() {
    assertAuthenticationChanges(o -> o.setIssuerUri("https://other-idp"));
  }

  @Test
  void shouldTreatTheClientIdAsAuthenticationRelevant() {
    assertAuthenticationChanges(o -> o.setClientId("other-client"));
  }

  @Test
  void shouldTreatTheAudiencesAsAuthenticationRelevant() {
    assertAuthenticationChanges(o -> o.setAudiences(Set.of("other-audience")));
  }

  @Test
  void shouldTreatTheClaimMappingAsAuthenticationRelevant() {
    assertAuthenticationChanges(o -> o.setUsernameClaim("email"));
    assertAuthenticationChanges(o -> o.setGroupsClaim("roles"));
  }

  @Test
  void shouldTreatTheMethodAsAuthenticationRelevant() {
    // given
    final var oidc = oidc(o -> {});
    final var basic = oidc(o -> {});
    basic.setMethod(AuthenticationMethod.BASIC);

    // when / then
    assertThat(ScopeFingerprints.of(basic).sameAuthenticationAs(ScopeFingerprints.of(oidc)))
        .isFalse();
  }

  @Test
  void shouldTreatANamedProviderAsAuthenticationRelevant() {
    // given
    final var before = oidc(o -> {});
    final var after = oidc(o -> {});
    after.getProviders().setOidc(Map.of("second", provider("https://second-idp")));

    // when / then
    assertThat(ScopeFingerprints.of(after).sameAuthenticationAs(ScopeFingerprints.of(before)))
        .isFalse();
  }

  @Test
  void shouldNotDependOnTheOrderOfASet() {
    // given
    final var ab = new LinkedHashSet<>(List.of("a", "b"));
    final var ba = new LinkedHashSet<>(List.of("b", "a"));

    // when
    final var first = ScopeFingerprints.of(oidc(o -> o.setAudiences(ab)));
    final var second = ScopeFingerprints.of(oidc(o -> o.setAudiences(ba)));

    // then
    assertThat(second.sameAs(first)).isTrue();
  }

  @Test
  void shouldBeEqualForEqualConfigurations() {
    // when / then
    assertThat(ScopeFingerprints.of(oidc(o -> {}))).isEqualTo(ScopeFingerprints.of(oidc(o -> {})));
  }

  @Test
  void shouldNotCarryTheSecretInEitherDigest() {
    // when
    final var fingerprints = ScopeFingerprints.of(oidc(o -> o.setClientSecret("hunter2")));

    // then
    assertThat(fingerprints.authentication()).doesNotContain("hunter2").hasSize(64);
    assertThat(fingerprints.complete()).doesNotContain("hunter2").hasSize(64);
  }

  private static void assertAuthenticationChanges(final Consumer<OidcConfiguration> change) {
    final var before = ScopeFingerprints.of(oidc(o -> {}));
    final var after = ScopeFingerprints.of(oidc(change));
    assertThat(after.sameAuthenticationAs(before)).isFalse();
    assertThat(after.sameAs(before)).isFalse();
  }

  private static AuthenticationConfiguration oidc(final Consumer<OidcConfiguration> change) {
    final var configuration = new AuthenticationConfiguration();
    configuration.setMethod(AuthenticationMethod.OIDC);
    final var oidc = provider("https://idp");
    oidc.setClientSecret("secret");
    change.accept(oidc);
    configuration.setOidc(oidc);
    return configuration;
  }

  private static OidcConfiguration provider(final String issuer) {
    return OidcConfiguration.builder().issuerUri(issuer).clientId("client").build();
  }

  private static AssertionConfiguration assertion(final String path, final String password) {
    return AssertionConfiguration.builder()
        .keystoreConfiguration(
            KeystoreConfiguration.builder()
                .path(path)
                .password(password)
                .keyAlias("alias")
                .keyPassword(password)
                .build())
        .build();
  }
}
