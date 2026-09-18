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
import org.springframework.security.oauth2.client.registration.ClientRegistration;

/**
 * Selects the verification keys of a token by its {@code iss} claim, so each identity provider of a
 * multi-tenant setup verifies its own tokens with its own JWK Set URI.
 *
 * <p>{@link IssuerRegistrations} resolves the registration of an issuer at the first token of that
 * issuer. A provider that does not answer therefore fails the tokens of its own issuer only, as a
 * {@link KeySourceException}, which the resource server answers with a server error. A token of an
 * issuer that no provider declares is a refused credential instead, see {@link
 * BadJwtKeySourceException}.
 */
public class IssuerAwareJWSKeySelector implements JWTClaimsSetAwareJWSKeySelector<SecurityContext> {

  private static final String ERROR_UNKNOWN_ISSUER =
      "Unknown issuer '%s'. No matching client registration found.";
  private static final String ERROR_MISSING_ISSUER =
      "Missing or empty 'iss' (issuer) claim in JWT.";

  private static final String ERROR_UNRESOLVED_ISSUER =
      "Failed to resolve the client registration of issuer '%s'.";
  private static final String ERROR_INVALID_JWK_SET_URI =
      "The client registration of issuer '%s' gives no usable 'jwkSetUri'.";

  private final IssuerRegistrations issuerRegistrations;
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
    this(
        IssuerRegistrations.ofResolved(clientRegistrations),
        jwsKeySelectorFactory,
        additionalJwkSetUrisByIssuer);
  }

  public IssuerAwareJWSKeySelector(
      final IssuerRegistrations issuerRegistrations,
      final JWSKeySelectorFactory jwsKeySelectorFactory,
      final Map<String, List<String>> additionalJwkSetUrisByIssuer) {
    this.issuerRegistrations = issuerRegistrations;
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

    return keySelectorFor(issuer).selectJWSKeys(jwsHeader, securityContext);
  }

  /**
   * The key selector of {@code issuer}, kept after a successful resolution only. The resolution
   * runs outside the lock of a map entry, because it can hold a request thread for the discovery
   * timeout of the provider, and the tokens of the other issuers must keep their answer meanwhile.
   */
  private JWSKeySelector<SecurityContext> keySelectorFor(final String issuer)
      throws KeySourceException {
    final var cached = selectors.get(issuer);
    if (cached != null) {
      return cached;
    }
    final var selector = createJWSKeySelector(issuer);
    final var winner = selectors.putIfAbsent(issuer, selector);
    return winner != null ? winner : selector;
  }

  /**
   * The registration of {@code issuer}, resolved where that needs OIDC discovery.
   *
   * @throws BadJwtKeySourceException if no configured provider declares the issuer. The token is
   *     the reason, so the marker subtype gives 401 {@code invalid_token}.
   * @throws KeySourceException if the resolution fails. The infrastructure is the reason, so the
   *     base type keeps the server error, as a JWKS outage does.
   */
  private ClientRegistration getClientRegistrationByIssuer(final String issuer)
      throws KeySourceException {
    final ClientRegistration clientRegistration;
    try {
      clientRegistration = issuerRegistrations.forIssuer(issuer);
    } catch (final RuntimeException unresolved) {
      throw new KeySourceException(ERROR_UNRESOLVED_ISSUER.formatted(issuer), unresolved);
    }
    if (clientRegistration == null) {
      throw new BadJwtKeySourceException(ERROR_UNKNOWN_ISSUER.formatted(issuer));
    }
    return clientRegistration;
  }

  /**
   * @throws KeySourceException if the registration of the issuer gives no usable JWK Set URI. The
   *     token is not the reason, so the base type keeps the server error.
   */
  private JWSKeySelector<SecurityContext> createJWSKeySelector(final String issuer)
      throws KeySourceException {
    final var clientRegistration = getClientRegistrationByIssuer(issuer);
    final var providerDetails = clientRegistration.getProviderDetails();
    final var jwkSetUri = providerDetails.getJwkSetUri();
    final var additionalUris = additionalJwkSetUrisByIssuer.get(issuer);
    try {
      return jwsKeySelectorFactory.createJWSKeySelector(jwkSetUri, additionalUris);
    } catch (final IllegalArgumentException invalidJwkSetUri) {
      throw new KeySourceException(ERROR_INVALID_JWK_SET_URI.formatted(issuer), invalidJwkSetUri);
    }
  }
}
