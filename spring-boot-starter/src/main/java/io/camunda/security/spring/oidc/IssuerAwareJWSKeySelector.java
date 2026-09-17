/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.JWTClaimsSetAwareJWSKeySelector;
import java.security.Key;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

/**
 * A {@link JWSKeySelector} implementation that dynamically selects the appropriate key selector
 * based on the {@code iss} (issuer) claim in a JWT.
 *
 * <p>This is used to support multi-tenant setups where each identity provider (issuer) may have its
 * own JWK Set URI for verifying token signatures.
 *
 * <p>Where two registrations declare the same issuer, the selector takes the keys of the
 * registration that {@link IssuerOwnership} names the owner of that issuer, and warns about the
 * keys it therefore does not read.
 */
public class IssuerAwareJWSKeySelector implements JWTClaimsSetAwareJWSKeySelector<SecurityContext> {

  private static final Logger LOG = LoggerFactory.getLogger(IssuerAwareJWSKeySelector.class);
  private static final String ERROR_UNKNOWN_ISSUER =
      "Unknown issuer '%s'. No matching client registration found.";
  private static final String ERROR_MISSING_ISSUER =
      "Missing or empty 'iss' (issuer) claim in JWT.";

  private final Map<String, ClientRegistration> registrationsByIssuer;
  private final JWSKeySelectorFactory jwsKeySelectorFactory;
  private final Map<String, List<String>> additionalJwkSetUrisByIssuer;
  private final Map<String, JWSKeySelector<SecurityContext>> selectors;

  public IssuerAwareJWSKeySelector(
      final List<ClientRegistration> clientRegistrations,
      final JWSKeySelectorFactory jwsKeySelectorFactory) {
    this(clientRegistrations, jwsKeySelectorFactory, Collections.emptyMap());
  }

  public IssuerAwareJWSKeySelector(
      final List<ClientRegistration> clientRegistrations,
      final JWSKeySelectorFactory jwsKeySelectorFactory,
      final Map<String, List<String>> additionalJwkSetUrisByIssuer) {
    registrationsByIssuer = IssuerOwnership.byIssuer(clientRegistrations, LOG, "the JWK Set URI");
    this.jwsKeySelectorFactory = jwsKeySelectorFactory;
    this.additionalJwkSetUrisByIssuer =
        additionalJwkSetUrisByIssuer != null
            ? Map.copyOf(additionalJwkSetUrisByIssuer)
            : Collections.emptyMap();
    selectors = new ConcurrentHashMap<>();
  }

  @Override
  public List<? extends Key> selectKeys(
      final JWSHeader jwsHeader,
      final JWTClaimsSet jwtClaimsSet,
      final SecurityContext securityContext)
      throws KeySourceException {
    final var issuer = jwtClaimsSet.getIssuer();

    if (issuer == null || issuer.isBlank()) {
      // Token-level fault (the token doesn't carry an issuer) — use the marker subtype so
      // OidcAccessTokenDecoderFactory remaps to BadJwtException → 401 invalid_token.
      throw new BadJwtKeySourceException(ERROR_MISSING_ISSUER);
    }

    try {
      return selectors
          .computeIfAbsent(issuer, this::createJWSKeySelector)
          .selectJWSKeys(jwsHeader, securityContext);
    } catch (final IllegalArgumentException ex) {
      // getClientRegistrationByIssuer throws IllegalArgumentException for unknown issuers.
      // selectKeys is declared to throw KeySourceException; using the BadJwtKeySourceException
      // marker subtype lets OidcAccessTokenDecoderFactory distinguish this client-fault case
      // from infrastructure-fault KeySourceExceptions (e.g. JWKS outage) and map only the
      // former to BadJwtException → 401 invalid_token.
      throw new BadJwtKeySourceException(ex.getMessage(), ex);
    }
  }

  /**
   * Finds the {@link ClientRegistration} that matches the given issuer URI.
   *
   * @param issuer the issuer URI from the JWT claims
   * @return the matching client registration, or {@code null} if not found
   */
  private ClientRegistration getClientRegistrationByIssuer(final String issuer) {
    final var registration = registrationsByIssuer.get(issuer);
    if (registration == null) {
      throw new IllegalArgumentException(ERROR_UNKNOWN_ISSUER.formatted(issuer));
    }
    return registration;
  }

  /**
   * Lazily creates a {@link JWSKeySelector} for the given issuer.
   *
   * @param issuer the issuer URI
   * @return a key selector for the issuer
   */
  private JWSKeySelector<SecurityContext> createJWSKeySelector(final String issuer) {
    final var clientRegistration = getClientRegistrationByIssuer(issuer);
    final var providerDetails = clientRegistration.getProviderDetails();
    final var jwkSetUri = providerDetails.getJwkSetUri();
    final var additionalUris = additionalJwkSetUrisByIssuer.get(issuer);
    return jwsKeySelectorFactory.createJWSKeySelector(jwkSetUri, additionalUris);
  }
}
