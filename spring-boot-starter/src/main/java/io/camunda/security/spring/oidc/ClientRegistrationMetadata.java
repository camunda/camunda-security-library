/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.util.StringUtils;

/**
 * The login settings that a {@link ClientRegistration} built by {@link
 * ScopedClientRegistrationFactory} carries for its own scope. Scopes can use the same registration
 * ID with different settings, so these entries win over any lookup by registration ID. A
 * registration without an entry, for example one that a host builds itself, falls back to that
 * lookup. See <a
 * href="https://github.com/camunda/camunda-security-library/blob/main/docs/adr/0033-login-settings-carried-by-the-registration.md">ADR-0033</a>.
 */
public final class ClientRegistrationMetadata {

  /** The issuer of the scope, an empty {@code String} when the scope sets none. */
  public static final String ISSUER = "camunda.security.oidc.issuer";

  /** The additional JWK Set URIs of the scope, a collection of {@code String}. */
  public static final String ADDITIONAL_JWK_SET_URIS =
      "camunda.security.oidc.additional-jwk-set-uris";

  /** The {@code prefer-id-token-claims} flag of the scope, a {@code Boolean}. */
  public static final String PREFER_ID_TOKEN_CLAIMS =
      "camunda.security.oidc.prefer-id-token-claims";

  private ClientRegistrationMetadata() {}

  /** Writes the entries of {@code oidc} into {@code metadata}, also when they are empty. */
  static void write(final Map<String, Object> metadata, final OidcConfiguration oidc) {
    metadata.put(ISSUER, StringUtils.hasText(oidc.getIssuerUri()) ? oidc.getIssuerUri() : "");
    metadata.put(
        ADDITIONAL_JWK_SET_URIS,
        oidc.getAdditionalJwkSetUris() != null
            ? oidc.getAdditionalJwkSetUris().stream().filter(StringUtils::hasText).toList()
            : List.of());
    metadata.put(PREFER_ID_TOKEN_CLAIMS, oidc.isPreferIdTokenClaims());
  }

  /**
   * @return the issuer of the scope, an empty string when the scope sets none, or empty when the
   *     registration has no entry
   * @throws IllegalStateException if the entry is not a {@code String}
   */
  public static Optional<String> issuer(final ClientRegistration registration) {
    return read(registration, ISSUER, String.class, "a String");
  }

  /**
   * @return the additional JWK Set URIs of the scope, possibly an empty list, or empty when the
   *     registration has no entry
   * @throws IllegalStateException if the entry is not a collection of {@code String}
   */
  public static Optional<List<String>> additionalJwkSetUris(final ClientRegistration registration) {
    return read(registration, ADDITIONAL_JWK_SET_URIS, Collection.class, "a collection of String")
        .map(values -> toStrings(ADDITIONAL_JWK_SET_URIS, values));
  }

  /**
   * @return the audiences of the registration's {@link
   *     TokenValidatorFactory#AUDIENCES_METADATA_KEY} entry, possibly empty, or empty when the
   *     registration has no entry
   * @throws IllegalStateException if the entry is not a collection of {@code String}
   */
  public static Optional<Set<String>> audiences(final ClientRegistration registration) {
    return read(
            registration,
            TokenValidatorFactory.AUDIENCES_METADATA_KEY,
            Collection.class,
            "a collection of String")
        .map(values -> Set.copyOf(toStrings(TokenValidatorFactory.AUDIENCES_METADATA_KEY, values)));
  }

  /**
   * @return the {@code prefer-id-token-claims} flag of the scope, or empty when the registration
   *     has no entry
   * @throws IllegalStateException if the entry is not a {@code Boolean}
   */
  public static Optional<Boolean> preferIdTokenClaims(final ClientRegistration registration) {
    return read(registration, PREFER_ID_TOKEN_CLAIMS, Boolean.class, "a Boolean");
  }

  private static <T> Optional<T> read(
      final ClientRegistration registration,
      final String key,
      final Class<T> type,
      final String expected) {
    final var details = registration.getProviderDetails();
    final var metadata = details != null ? details.getConfigurationMetadata() : null;
    if (metadata == null || !metadata.containsKey(key)) {
      return Optional.empty();
    }
    final var value = metadata.get(key);
    if (!type.isInstance(value)) {
      throw invalid(key, expected, value);
    }
    return Optional.of(type.cast(value));
  }

  private static List<String> toStrings(final String key, final Collection<?> values) {
    for (final var value : values) {
      if (!(value instanceof String)) {
        throw invalid(key, "a collection of String", value);
      }
    }
    return values.stream().map(String.class::cast).toList();
  }

  private static IllegalStateException invalid(
      final String key, final String expected, final Object actual) {
    return new IllegalStateException(
        "Metadata key '"
            + key
            + "' must hold "
            + expected
            + " but had: "
            + (actual == null ? "null" : actual.getClass().getName()));
  }
}
