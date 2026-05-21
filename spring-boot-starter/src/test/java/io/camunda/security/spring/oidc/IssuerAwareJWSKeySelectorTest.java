/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jwt.JWTClaimsSet;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistration.ProviderDetails;

@ExtendWith(MockitoExtension.class)
class IssuerAwareJWSKeySelectorTest {

  @Mock private JWSKeySelectorFactory jwsKeySelectorFactory;
  @Mock private ClientRegistration clientRegistration;
  @Mock private ProviderDetails providerDetails;

  @Test
  void shouldThrowKeySourceExceptionForUnknownIssuer() {
    when(clientRegistration.getProviderDetails()).thenReturn(providerDetails);
    when(providerDetails.getIssuerUri()).thenReturn("https://known-issuer");

    final var selector =
        new IssuerAwareJWSKeySelector(List.of(clientRegistration), jwsKeySelectorFactory);
    final var claims = new JWTClaimsSet.Builder().issuer("https://other-issuer").build();
    final var header = new JWSHeader(JWSAlgorithm.RS256);

    // The internal lookup throws IllegalArgumentException for unknown issuers, but the
    // selectKeys contract is to throw KeySourceException so NimbusJwtDecoder maps it to
    // invalid_token. Wrapping is verified here.
    assertThatThrownBy(() -> selector.selectKeys(header, claims, null))
        .isInstanceOf(KeySourceException.class)
        .hasMessageContaining("https://other-issuer");
  }

  @Test
  void shouldThrowKeySourceExceptionForMissingIssuer() {
    final var selector = new IssuerAwareJWSKeySelector(List.of(), jwsKeySelectorFactory);
    final var claims = new JWTClaimsSet.Builder().build();
    final var header = new JWSHeader(JWSAlgorithm.RS256);

    assertThatThrownBy(() -> selector.selectKeys(header, claims, null))
        .isInstanceOf(KeySourceException.class)
        .hasMessageContaining("Missing or empty");
  }
}
