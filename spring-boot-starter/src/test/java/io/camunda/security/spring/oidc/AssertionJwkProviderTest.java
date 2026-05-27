/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.params.provider.Arguments.of;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.jwk.RSAKey;
import io.camunda.security.api.model.config.AssertionConfiguration;
import io.camunda.security.api.model.config.AssertionConfiguration.KidCase;
import io.camunda.security.api.model.config.AssertionConfiguration.KidDigestAlgorithm;
import io.camunda.security.api.model.config.AssertionConfiguration.KidEncoding;
import io.camunda.security.api.model.config.AssertionConfiguration.KidSource;
import io.camunda.security.api.model.config.KeystoreConfiguration;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.core.port.in.OidcProviderConfigurationPort;
import java.net.URISyntaxException;
import java.nio.file.Paths;
import java.util.Objects;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class AssertionJwkProviderTest {

  private static final String REGISTRATION_ID = "test";

  @Mock private OidcProviderConfigurationPort oidcProviderConfigurationPort;
  @InjectMocks private AssertionJwkProvider assertionJwkProvider;

  private KeystoreConfiguration keystoreConfig;

  @BeforeEach
  void setUp() throws URISyntaxException {
    final var keystorePath =
        Paths.get(
                Objects.requireNonNull(
                        AssertionJwkProviderTest.class.getClassLoader().getResource("keystore.p12"))
                    .toURI())
            .toString();
    keystoreConfig =
        KeystoreConfiguration.builder()
            .path(keystorePath)
            .password("password")
            .keyAlias("camunda-standalone")
            .keyPassword("password")
            .build();
  }

  private void stubPortWith(final AssertionConfiguration assertionConfig) {
    final var oidcConfig =
        OidcConfiguration.builder().assertionConfiguration(assertionConfig).build();
    when(oidcProviderConfigurationPort.getOidcAuthenticationConfigurationById(REGISTRATION_ID))
        .thenReturn(oidcConfig);
  }

  @Test
  void createJwkReturnsValidRsaKeyWithX5cAndThumbprint() {
    stubPortWith(AssertionConfiguration.builder().keystoreConfiguration(keystoreConfig).build());

    final var jwk = assertionJwkProvider.createJwk(REGISTRATION_ID);

    assertThat(jwk).isInstanceOf(RSAKey.class);
    final var rsaKey = (RSAKey) jwk;
    assertThat(rsaKey.isPrivate()).isTrue();
    assertThat(rsaKey.getX509CertChain()).isNotEmpty();
    assertThat(rsaKey.getX509CertSHA256Thumbprint()).isNotNull();
    assertThat(rsaKey.getKeyID()).isEqualTo("opaYc1PqzH6XYGbL3KF4BK1rkNRS4IuMAfh3qPZILHo");
  }

  @Test
  void createJwkThrowsForUnknownRegistrationId() {
    when(oidcProviderConfigurationPort.getOidcAuthenticationConfigurationById("unknown"))
        .thenReturn(null);

    assertThatThrownBy(() -> assertionJwkProvider.createJwk("unknown"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("unknown");
  }

  @Test
  void createJwkThrowsWhenAssertionConfigIsNull() {
    final var oidcConfig = new OidcConfiguration();
    oidcConfig.setAssertion(null);
    when(oidcProviderConfigurationPort.getOidcAuthenticationConfigurationById(REGISTRATION_ID))
        .thenReturn(oidcConfig);

    assertThatThrownBy(() -> assertionJwkProvider.createJwk(REGISTRATION_ID))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining(REGISTRATION_ID);
  }

  @Test
  void createJwkThrowsWhenKeyAliasIsBlank() {
    final var badKeystoreConfig =
        KeystoreConfiguration.builder()
            .path(keystoreConfig.getPath())
            .password("password")
            .keyAlias("  ")
            .keyPassword("password")
            .build();
    stubPortWith(AssertionConfiguration.builder().keystoreConfiguration(badKeystoreConfig).build());

    assertThatThrownBy(() -> assertionJwkProvider.createJwk(REGISTRATION_ID))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("keyAlias");
  }

  @Test
  void createJwkThrowsWhenKeyPasswordIsBlank() {
    final var badKeystoreConfig =
        KeystoreConfiguration.builder()
            .path(keystoreConfig.getPath())
            .password("password")
            .keyAlias("camunda-standalone")
            .keyPassword("")
            .build();
    stubPortWith(AssertionConfiguration.builder().keystoreConfiguration(badKeystoreConfig).build());

    assertThatThrownBy(() -> assertionJwkProvider.createJwk(REGISTRATION_ID))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("keyPassword");
  }

  @ParameterizedTest(name = "{index}: {0} {1} {2} {3}")
  @MethodSource("kidGenerationSettings")
  void createJwkGeneratesExpectedKid(
      final KidSource kidSource,
      final KidDigestAlgorithm kidDigestAlgorithm,
      final KidEncoding kidEncoding,
      final KidCase kidCase,
      final String expectedKid) {
    final var assertionConfig =
        AssertionConfiguration.builder()
            .keystoreConfiguration(keystoreConfig)
            .kidSource(kidSource)
            .kidDigestAlgorithm(kidDigestAlgorithm)
            .kidEncoding(kidEncoding)
            .kidCase(kidCase)
            .build();
    stubPortWith(assertionConfig);

    final var jwk = assertionJwkProvider.createJwk(REGISTRATION_ID);

    assertThat(((RSAKey) jwk).getKeyID()).isEqualTo(expectedKid);
  }

  static Stream<Arguments> kidGenerationSettings() {
    return Stream.of(
        of(
            KidSource.CERTIFICATE,
            KidDigestAlgorithm.SHA1,
            KidEncoding.BASE64URL,
            (KidCase) null,
            "3qC6yDtfSqnrgI1SgvyrAxcILBI"),
        of(
            KidSource.CERTIFICATE,
            KidDigestAlgorithm.SHA1,
            KidEncoding.HEX,
            KidCase.UPPER,
            "DEA0BAC83B5F4AA9EB808D5282FCAB0317082C12"),
        of(
            KidSource.CERTIFICATE,
            KidDigestAlgorithm.SHA1,
            KidEncoding.HEX,
            KidCase.LOWER,
            "dea0bac83b5f4aa9eb808d5282fcab0317082c12"),
        of(
            KidSource.CERTIFICATE,
            KidDigestAlgorithm.SHA256,
            KidEncoding.BASE64URL,
            (KidCase) null,
            "gCC_MwKDLUCxMYUlm95bDX8ol6nNHhCohhudSkJAJhQ"),
        of(
            KidSource.CERTIFICATE,
            KidDigestAlgorithm.SHA256,
            KidEncoding.HEX,
            KidCase.UPPER,
            "8020BF3302832D40B13185259BDE5B0D7F2897A9CD1E10A8861B9D4A42402614"),
        of(
            KidSource.CERTIFICATE,
            KidDigestAlgorithm.SHA256,
            KidEncoding.HEX,
            KidCase.LOWER,
            "8020bf3302832d40b13185259bde5b0d7f2897a9cd1e10a8861b9d4a42402614"),
        of(
            KidSource.PUBLIC_KEY,
            KidDigestAlgorithm.SHA1,
            KidEncoding.BASE64URL,
            (KidCase) null,
            "c3_39mARI3tpCxRcmhiGylohUYQ"),
        of(
            KidSource.PUBLIC_KEY,
            KidDigestAlgorithm.SHA1,
            KidEncoding.HEX,
            KidCase.UPPER,
            "737FF7F66011237B690B145C9A1886CA5A215184"),
        of(
            KidSource.PUBLIC_KEY,
            KidDigestAlgorithm.SHA1,
            KidEncoding.HEX,
            KidCase.LOWER,
            "737ff7f66011237b690b145c9a1886ca5a215184"),
        of(
            KidSource.PUBLIC_KEY,
            KidDigestAlgorithm.SHA256,
            KidEncoding.BASE64URL,
            (KidCase) null,
            "opaYc1PqzH6XYGbL3KF4BK1rkNRS4IuMAfh3qPZILHo"),
        of(
            KidSource.PUBLIC_KEY,
            KidDigestAlgorithm.SHA256,
            KidEncoding.HEX,
            KidCase.UPPER,
            "A296987353EACC7E976066CBDCA17804AD6B90D452E08B8C01F877A8F6482C7A"),
        of(
            KidSource.PUBLIC_KEY,
            KidDigestAlgorithm.SHA256,
            KidEncoding.HEX,
            KidCase.LOWER,
            "a296987353eacc7e976066cbdca17804ad6b90d452e08b8c01f877a8f6482c7a"));
  }
}
