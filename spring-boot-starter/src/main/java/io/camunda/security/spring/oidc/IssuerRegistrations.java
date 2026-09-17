/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

/**
 * The client registrations that an issuer-aware {@link
 * org.springframework.security.oauth2.jwt.JwtDecoder} verifies tokens against, addressed by the
 * {@code iss} claim of a token.
 *
 * <p>{@link #ofConfiguration(Map, Function)} keys the registrations by the configured issuer-uri,
 * so an issuer is looked up without network access, and the registration of that issuer alone is
 * resolved at the first token that carries it. An identity provider that does not answer therefore
 * fails the tokens of its own issuer alone, and leaves the tokens of the other providers untouched.
 * Two providers can declare the same issuer, and the first of them in the iteration order of the
 * provider map then verifies its tokens, see {@link IssuerOwnership}.
 *
 * <p>{@link #ofResolved(List)} takes registrations that a caller resolved already, for a host that
 * supplies its own repository.
 *
 * <p>A registration is kept after a successful resolution only, so the next token of that issuer
 * makes a new attempt after a failed one. Two tokens of the same issuer can resolve it at the same
 * time, because a single-flight lock would hold one request thread for the complete discovery
 * timeout of the other attempt. The first result wins.
 */
public final class IssuerRegistrations {

  private static final Logger LOG = LoggerFactory.getLogger(IssuerRegistrations.class);

  private static final String IGNORED_CONFIGURATION = "the keys and the token validation rules";

  private static final String ERROR_NO_REGISTRATION =
      "The resolution of OIDC provider '%s' gave no client registration, although its"
          + " configuration declares issuer '%s'.";

  /** The key of the resolution of an issuer: a registrationId, or the issuer itself. */
  private final Map<String, String> resolutionKeyByIssuer;

  private final Function<String, ClientRegistration> resolve;
  private final Map<String, ClientRegistration> resolved = new ConcurrentHashMap<>();

  private IssuerRegistrations(
      final Map<String, String> resolutionKeyByIssuer,
      final Function<String, ClientRegistration> resolve) {
    this.resolutionKeyByIssuer = Map.copyOf(resolutionKeyByIssuer);
    this.resolve = Objects.requireNonNull(resolve, "resolve must not be null");
  }

  /**
   * Takes the accepted issuers from the provider configuration, and resolves one registration
   * through {@code resolveByRegistrationId}. A provider that sets no issuer-uri accepts no token,
   * which is why {@link OidcAccessTokenDecoderFactory#validateProvidersHaveIssuer(Map)} rejects
   * such a configuration of several providers while the application starts.
   *
   * @param providers the provider configuration, keyed by registrationId, in the order of the
   *     configuration: where two providers declare the same issuer, {@link IssuerOwnership} gives
   *     it to the first of them
   * @param resolveByRegistrationId gives the registration of a registrationId, and makes OIDC
   *     discovery where the provider needs it
   */
  public static IssuerRegistrations ofConfiguration(
      final Map<String, OidcConfiguration> providers,
      final Function<String, ClientRegistration> resolveByRegistrationId) {
    return new IssuerRegistrations(
        IssuerOwnership.registrationIdByIssuer(providers, LOG, IGNORED_CONFIGURATION),
        resolveByRegistrationId);
  }

  /** Takes the accepted issuers and the registrations from resolved registrations. */
  public static IssuerRegistrations ofResolved(final List<ClientRegistration> registrations) {
    final var registrationByIssuer =
        IssuerOwnership.byIssuer(registrations, LOG, IGNORED_CONFIGURATION);
    final var keyByIssuer = new LinkedHashMap<String, String>();
    registrationByIssuer.keySet().forEach(issuer -> keyByIssuer.put(issuer, issuer));
    return new IssuerRegistrations(keyByIssuer, registrationByIssuer::get);
  }

  /**
   * The registration of {@code issuer}, or {@code null} when no configured provider declares that
   * issuer. A caller answers such a token as a refused credential, and not as a server error.
   *
   * @throws IllegalStateException if a provider declares the issuer, and its resolution gives no
   *     registration. The token names an accepted issuer, so the repository is the reason, and a
   *     caller must not read the token as the refused credential of an unknown issuer.
   * @throws RuntimeException what the resolution of the registration throws, such as the {@link
   *     IllegalArgumentException} that OIDC discovery of an unreachable issuer gives
   */
  public ClientRegistration forIssuer(final String issuer) {
    final var resolutionKey = resolutionKeyByIssuer.get(issuer);
    if (resolutionKey == null) {
      return null;
    }
    final var cached = resolved.get(resolutionKey);
    if (cached != null) {
      return cached;
    }
    final var registration = resolve.apply(resolutionKey);
    if (registration == null) {
      throw new IllegalStateException(ERROR_NO_REGISTRATION.formatted(resolutionKey, issuer));
    }
    final var winner = resolved.putIfAbsent(resolutionKey, registration);
    return winner != null ? winner : registration;
  }

  /** The issuers whose tokens the decoder accepts. Resolves nothing. */
  public Set<String> issuers() {
    return resolutionKeyByIssuer.keySet();
  }
}
