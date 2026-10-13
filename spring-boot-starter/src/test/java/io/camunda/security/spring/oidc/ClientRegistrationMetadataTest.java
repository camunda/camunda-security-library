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

import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

class ClientRegistrationMetadataTest {

  @Test
  void shouldWriteEveryEntryAlsoWhenTheScopeSetsNothing() {
    // given
    final Map<String, Object> metadata = new LinkedHashMap<>();

    // when
    ClientRegistrationMetadata.write(metadata, new OidcConfiguration());

    // then
    assertThat(metadata)
        .containsEntry(ClientRegistrationMetadata.ISSUER, "")
        .containsEntry(ClientRegistrationMetadata.ADDITIONAL_JWK_SET_URIS, List.of())
        .containsEntry(ClientRegistrationMetadata.PREFER_ID_TOKEN_CLAIMS, false);
  }

  @Test
  void shouldReadBackWhatItWrites() {
    // given
    final var oidc = new OidcConfiguration();
    oidc.setIssuerUri("https://idp");
    oidc.setAdditionalJwkSetUris(List.of("https://idp/extra", " "));
    oidc.setPreferIdTokenClaims(true);
    final Map<String, Object> metadata = new LinkedHashMap<>();
    ClientRegistrationMetadata.write(metadata, oidc);

    // when
    final var registration = registration(metadata);

    // then
    assertThat(ClientRegistrationMetadata.issuer(registration)).contains("https://idp");
    assertThat(ClientRegistrationMetadata.additionalJwkSetUris(registration))
        .contains(List.of("https://idp/extra"));
    assertThat(ClientRegistrationMetadata.preferIdTokenClaims(registration)).contains(true);
  }

  @Test
  void shouldReturnEmptyWhenTheRegistrationHasNoEntry() {
    // when
    final var registration = registration(Map.of());

    // then
    assertThat(ClientRegistrationMetadata.issuer(registration)).isEmpty();
    assertThat(ClientRegistrationMetadata.additionalJwkSetUris(registration)).isEmpty();
    assertThat(ClientRegistrationMetadata.preferIdTokenClaims(registration)).isEmpty();
  }

  @Test
  void shouldFailClosedOnAnIssuerThatIsNotAString() {
    final var registration = registration(Map.of(ClientRegistrationMetadata.ISSUER, 42));

    assertThatThrownBy(() -> ClientRegistrationMetadata.issuer(registration))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining(ClientRegistrationMetadata.ISSUER);
  }

  @Test
  void shouldFailClosedOnAdditionalJwkSetUrisThatAreNotACollection() {
    final var registration =
        registration(Map.of(ClientRegistrationMetadata.ADDITIONAL_JWK_SET_URIS, "https://idp"));

    assertThatThrownBy(() -> ClientRegistrationMetadata.additionalJwkSetUris(registration))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining(ClientRegistrationMetadata.ADDITIONAL_JWK_SET_URIS);
  }

  @Test
  void shouldFailClosedOnAdditionalJwkSetUrisWithANonStringElement() {
    final var registration =
        registration(Map.of(ClientRegistrationMetadata.ADDITIONAL_JWK_SET_URIS, Set.of(42)));

    assertThatThrownBy(() -> ClientRegistrationMetadata.additionalJwkSetUris(registration))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining(ClientRegistrationMetadata.ADDITIONAL_JWK_SET_URIS);
  }

  @Test
  void shouldFailClosedOnAPreferIdTokenClaimsFlagThatIsNotABoolean() {
    final var registration =
        registration(Map.of(ClientRegistrationMetadata.PREFER_ID_TOKEN_CLAIMS, "true"));

    assertThatThrownBy(() -> ClientRegistrationMetadata.preferIdTokenClaims(registration))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining(ClientRegistrationMetadata.PREFER_ID_TOKEN_CLAIMS);
  }

  private static ClientRegistration registration(final Map<String, Object> metadata) {
    return ClientRegistration.withRegistrationId("oidc")
        .clientId("client")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/sso-callback")
        .authorizationUri("https://idp/auth")
        .tokenUri("https://idp/token")
        .providerConfigurationMetadata(metadata)
        .build();
  }
}
