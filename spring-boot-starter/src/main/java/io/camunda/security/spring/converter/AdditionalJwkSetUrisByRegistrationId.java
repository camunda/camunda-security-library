/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.converter;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Per-registration {@code additional-jwk-set-uris} lookup for {@link
 * OidcUserAuthenticationConverter}. See <a
 * href="https://github.com/camunda/camunda-security-library/blob/main/docs/adr/0030-additional-jwk-set-uris-by-registration-id.md">ADR-0030</a>
 * for the design rationale.
 *
 * <p>Keyed by registration ID, not by issuer URI: a provider configured with explicit endpoints
 * ({@code jwk-set-uri}/{@code authorization-uri}/{@code token-uri}) and no {@code issuer-uri} has
 * no issuer to key on, so an issuer-keyed lookup silently resolves nothing for it and its
 * supplementary key sets are dropped. {@code OAuth2AuthenticationToken} carries the registration ID
 * of the login that produced it, so the login flow always has that key available.
 *
 * <p>Exposed as a dedicated type rather than a bare {@code Map<String, List<String>>}: Spring
 * intercepts any injection point whose declared type is exactly {@code java.util.Map}, collecting
 * all beans of the value type keyed by <em>bean name</em> instead of ever looking for a bean of
 * that {@code Map} type itself, the same reason {@link TokenClaimsConvertersByIssuer} is a record.
 * A distinct type also keeps this lookup from sharing an erasure with the issuer-keyed map it
 * replaces, so a host that has not migrated fails to compile instead of silently keying by the
 * wrong thing.
 */
public record AdditionalJwkSetUrisByRegistrationId(Map<String, List<String>> byRegistrationId) {

  public AdditionalJwkSetUrisByRegistrationId {
    byRegistrationId =
        byRegistrationId != null
            ? byRegistrationId.entrySet().stream()
                .collect(
                    Collectors.toUnmodifiableMap(Map.Entry::getKey, e -> List.copyOf(e.getValue())))
            : Map.of();
  }

  /** An empty lookup, for a caller that has no supplementary key sets to declare. */
  public static AdditionalJwkSetUrisByRegistrationId empty() {
    return new AdditionalJwkSetUrisByRegistrationId(Map.of());
  }

  /**
   * @param registrationId the client registration whose supplementary key sets are wanted
   * @return the additional JWK Set URIs of that registration, or {@code null} when it declares
   *     none. {@code null} and an empty list are equivalent to every caller downstream
   */
  public List<String> get(final String registrationId) {
    return registrationId == null ? null : byRegistrationId.get(registrationId);
  }
}
