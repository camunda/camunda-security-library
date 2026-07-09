/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config.oidc;

import static io.camunda.security.api.model.config.oidc.OidcConfiguration.CLIENT_AUTHENTICATION_METHOD_CLIENT_SECRET_BASIC;
import static io.camunda.security.api.model.config.oidc.OidcConfiguration.DEFAULT_CLOCK_SKEW;
import static io.camunda.security.api.model.config.oidc.OidcConfiguration.DEFAULT_GRANT_TYPE;
import static io.camunda.security.api.model.config.oidc.OidcConfiguration.DEFAULT_ID_TOKEN_ALGORITHM;
import static io.camunda.security.api.model.config.oidc.OidcConfiguration.DEFAULT_SCOPE;
import static io.camunda.security.api.model.config.oidc.OidcConfiguration.DEFAULT_USERNAME_CLAIM;

import io.camunda.security.api.model.config.AssertionConfiguration;
import io.camunda.security.api.model.config.AssertionConfiguration.KidDigestAlgorithm;
import io.camunda.security.api.model.config.AssertionConfiguration.KidEncoding;
import io.camunda.security.api.model.config.KeystoreConfiguration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class OidcConfigurationTest {

  @ParameterizedTest(name = "{index}: {0}")
  @MethodSource("oidcAuthentications")
  @DisplayName("Check OIDC configuration any property is set")
  void testIsAnyPropertySet(
      final String description,
      final OidcConfiguration oidcAuthenticationConfiguration,
      final boolean expected) {
    Assertions.assertThat(oidcAuthenticationConfiguration.isAnyPropertySet())
        .withFailMessage(description)
        .isEqualTo(expected);
  }

  static Stream<Arguments> oidcAuthentications() {
    return Stream.of(
        Arguments.of(
            "audience is set", OidcConfiguration.builder().audiences(Set.of("aud")).build(), true),
        Arguments.of(
            "authorizationUri is set",
            OidcConfiguration.builder().authorizationUri("auth-uri").build(),
            true),
        Arguments.of(
            "endSessionEndpointUri is set",
            OidcConfiguration.builder().endSessionEndpointUri("end-session-endpoint-uri").build(),
            true),
        Arguments.of("clientId is set", OidcConfiguration.builder().clientId("cid").build(), true),
        Arguments.of(
            "clientName is set",
            OidcConfiguration.builder().clientName("clientName").build(),
            true),
        Arguments.of(
            "clientSecret is set", OidcConfiguration.builder().clientSecret("cs").build(), true),
        Arguments.of(
            "idTokenAlgorithm is set",
            OidcConfiguration.builder().idTokenAlgorithm("PS256").build(),
            true),
        Arguments.of(
            "default idTokenAlgorithm is set",
            OidcConfiguration.builder().idTokenAlgorithm(DEFAULT_ID_TOKEN_ALGORITHM).build(),
            false),
        Arguments.of(
            "authorizeRequestConfiguration is set to null",
            OidcConfiguration.builder().authorizeRequestConfiguration(null).build(),
            true),
        Arguments.of(
            "authorizeRequestConfiguration has additional parameters",
            OidcConfiguration.builder()
                .authorizeRequestConfiguration(
                    AuthorizeRequestConfiguration.builder().additionalParameter("k1", "v1").build())
                .build(),
            true),
        Arguments.of(
            "grantType is set to empty", OidcConfiguration.builder().grantType("").build(), true),
        Arguments.of(
            "clientIdClaim is set",
            OidcConfiguration.builder().clientIdClaim("cclaim").build(),
            true),
        Arguments.of(
            "groupsClaim is set", OidcConfiguration.builder().groupsClaim("gclaim").build(), true),
        Arguments.of(
            "usernameClaim is set to null",
            OidcConfiguration.builder().usernameClaim(null).build(),
            true),
        Arguments.of(
            "usernameClaim is set empty",
            OidcConfiguration.builder().usernameClaim("").build(),
            true),
        Arguments.of(
            "usernameClaim is set",
            OidcConfiguration.builder().usernameClaim("sub1").build(),
            true),
        Arguments.of(
            "preferUsernameClaim is set",
            OidcConfiguration.builder().preferUsernameClaim(true).build(),
            true),
        Arguments.of("preferUsernameClaim is not set", OidcConfiguration.builder().build(), false),
        Arguments.of(
            "issuerUri is set", OidcConfiguration.builder().issuerUri("issuer").build(), true),
        Arguments.of(
            "jwk-url is set", OidcConfiguration.builder().jwkSetUri("jwk-url").build(), true),
        Arguments.of("scope is set to null", OidcConfiguration.builder().scope(null).build(), true),
        Arguments.of(
            "scope is set to empty",
            OidcConfiguration.builder().scope(new ArrayList<>()).build(),
            true),
        Arguments.of(
            "scope is set", OidcConfiguration.builder().scope(List.of("profile")).build(), true),
        Arguments.of(
            "redirectUri is set",
            OidcConfiguration.builder().redirectUri("redirect").build(),
            true),
        Arguments.of(
            "tokenUri is set", OidcConfiguration.builder().tokenUri("token").build(), true),
        Arguments.of(
            "organizationId is set",
            OidcConfiguration.builder().organizationId("org").build(),
            true),
        Arguments.of(
            "clientAuthenticationMethod is set",
            OidcConfiguration.builder().clientAuthenticationMethod("private_key_jwt").build(),
            true),
        Arguments.of(
            "AssertionConfiguration.path is set",
            OidcConfiguration.builder()
                .assertionConfiguration(
                    AssertionConfiguration.builder()
                        .keystoreConfiguration(
                            KeystoreConfiguration.builder().path("/path/to/keystore.p12").build())
                        .build())
                .build(),
            true),
        Arguments.of(
            "AssertionConfiguration.password is set",
            OidcConfiguration.builder()
                .assertionConfiguration(
                    AssertionConfiguration.builder()
                        .keystoreConfiguration(
                            KeystoreConfiguration.builder().password("keystorepass").build())
                        .build())
                .build(),
            true),
        Arguments.of(
            "AssertionConfiguration.keyAlias is set",
            OidcConfiguration.builder()
                .assertionConfiguration(
                    AssertionConfiguration.builder()
                        .keystoreConfiguration(
                            KeystoreConfiguration.builder().keyAlias("keyalias").build())
                        .build())
                .build(),
            true),
        Arguments.of(
            "AssertionConfiguration.keyPassword is set",
            OidcConfiguration.builder()
                .assertionConfiguration(
                    AssertionConfiguration.builder()
                        .keystoreConfiguration(
                            KeystoreConfiguration.builder().keyPassword("keypass").build())
                        .build())
                .build(),
            true),
        Arguments.of(
            "AssertionConfiguration.kidSource is set",
            OidcConfiguration.builder()
                .assertionConfiguration(
                    AssertionConfiguration.builder()
                        .kidSource(AssertionConfiguration.KidSource.CERTIFICATE)
                        .build())
                .build(),
            true),
        Arguments.of(
            "AssertionConfiguration.kidDigestAlgorithm is set",
            OidcConfiguration.builder()
                .assertionConfiguration(
                    AssertionConfiguration.builder()
                        .kidDigestAlgorithm(KidDigestAlgorithm.SHA1)
                        .build())
                .build(),
            true),
        Arguments.of(
            "AssertionConfiguration.kidEncoding is set",
            OidcConfiguration.builder()
                .assertionConfiguration(
                    AssertionConfiguration.builder().kidEncoding(KidEncoding.HEX).build())
                .build(),
            true),
        Arguments.of(
            "AssertionConfiguration.kidCase is set",
            OidcConfiguration.builder()
                .assertionConfiguration(
                    AssertionConfiguration.builder()
                        .kidEncoding(KidEncoding.HEX)
                        .kidCase(AssertionConfiguration.KidCase.LOWER)
                        .build())
                .build(),
            true),
        Arguments.of(
            "AssertionConfiguration is set to null",
            OidcConfiguration.builder().assertionConfiguration(null).build(),
            true),
        Arguments.of(
            "AssertionConfiguration.keystore is set to null",
            OidcConfiguration.builder()
                .assertionConfiguration(
                    AssertionConfiguration.builder().keystoreConfiguration(null).build())
                .build(),
            true),
        Arguments.of(
            "clockSkew is set",
            OidcConfiguration.builder().clockSkew(DEFAULT_CLOCK_SKEW.plusSeconds(1)).build(),
            true),
        Arguments.of("default", new OidcConfiguration(), false),
        Arguments.of(
            "default authorizeRequestConfiguration is set",
            OidcConfiguration.builder()
                .authorizeRequestConfiguration(new AuthorizeRequestConfiguration())
                .build(),
            false),
        Arguments.of(
            "default grantType is set",
            OidcConfiguration.builder().grantType(DEFAULT_GRANT_TYPE).build(),
            false),
        Arguments.of(
            "default usernameClaim is set",
            OidcConfiguration.builder().usernameClaim(DEFAULT_USERNAME_CLAIM).build(),
            false),
        Arguments.of(
            "default scope is set",
            OidcConfiguration.builder().scope(DEFAULT_SCOPE).build(),
            false),
        Arguments.of(
            "default clientAuthenticationMethod is set",
            OidcConfiguration.builder()
                .clientAuthenticationMethod(CLIENT_AUTHENTICATION_METHOD_CLIENT_SECRET_BASIC)
                .build(),
            false),
        Arguments.of(
            "default clockSkew is set",
            OidcConfiguration.builder().clockSkew(DEFAULT_CLOCK_SKEW).build(),
            false),
        Arguments.of(
            "AssertionConfiguration values are not set",
            OidcConfiguration.builder()
                .assertionConfiguration(AssertionConfiguration.builder().build())
                .build(),
            false),
        Arguments.of("diagnostics.enabled is set", oidcConfigWithEnabledDiagnostics(), true));
  }

  private static OidcConfiguration oidcConfigWithEnabledDiagnostics() {
    final var diagnostics = new OidcDiagnosticsConfiguration();
    diagnostics.setEnabled(true);
    final var config = new OidcConfiguration();
    config.setDiagnostics(diagnostics);
    return config;
  }
}
