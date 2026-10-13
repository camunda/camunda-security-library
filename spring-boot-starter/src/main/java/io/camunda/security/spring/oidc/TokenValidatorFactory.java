/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.time.Duration;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.util.StringUtils;

/**
 * A factory for creating {@link OAuth2TokenValidator} instances for validating {@link Jwt} tokens.
 *
 * <p>The factory composes a validator from:
 *
 * <ul>
 *   <li>A {@link JwtTimestampValidator} using the configured clock skew
 *   <li>A {@link JwtIssuerValidator} for the issuer that the registration carries (see {@link
 *       ClientRegistrationMetadata#issuer}). If it carries none, it uses the issuer URI of the
 *       matched {@link OidcConfiguration}. An empty issuer entry turns the check off
 *   <li>An {@link AudienceValidator} when the matched {@link OidcConfiguration} declares audiences
 *   <li>Any extra validators supplied by the host (e.g. SaaS organization/cluster validators)
 * </ul>
 *
 * <p>Hosts wire SaaS-specific or other deployment-specific validators by supplying a list of {@link
 * OAuth2TokenValidator}. These are applied to every client registration.
 */
public class TokenValidatorFactory {

  /**
   * Key under which a {@link ClientRegistration} carries its scope-specific audiences in {@code
   * providerDetails.configurationMetadata}. When present, these take precedence over the audiences
   * resolved from the {@code providers} map by registration ID, so scoped registrations that share
   * a registration ID still validate their own audiences.
   */
  public static final String AUDIENCES_METADATA_KEY = "camunda.security.oidc.audiences";

  private final Map<String, OidcConfiguration> providers;
  private final Duration clockSkew;
  private final List<OAuth2TokenValidator<Jwt>> extraValidators;

  /**
   * @param providers OIDC provider configurations keyed by registration ID
   * @param clockSkew clock skew applied to the {@link JwtTimestampValidator}
   * @param extraValidators host-supplied validators added to every composed validator (may be
   *     empty)
   */
  public TokenValidatorFactory(
      final Map<String, OidcConfiguration> providers,
      final Duration clockSkew,
      final List<OAuth2TokenValidator<Jwt>> extraValidators) {
    // ScopedClientRegistrationFactory#withoutBlankRegistrationIds: Map.copyOf below rejects a
    // null key outright, and a blank registrationId is warn-only, not rejected, elsewhere.
    this.providers =
        Map.copyOf(ScopedClientRegistrationFactory.withoutBlankRegistrationIds(providers));
    this.clockSkew = Objects.requireNonNull(clockSkew, "clockSkew");
    this.extraValidators = extraValidators == null ? List.of() : List.copyOf(extraValidators);
  }

  /**
   * Creates a new {@link OAuth2TokenValidator} for the given {@link ClientRegistration}.
   *
   * @param clientRegistration the client registration associated with the JWT issuer
   * @return a composed {@code OAuth2TokenValidator} instance
   */
  public OAuth2TokenValidator<Jwt> createTokenValidator(
      final ClientRegistration clientRegistration) {
    final var registrationId = clientRegistration.getRegistrationId();
    final var providerConfig = providers.get(registrationId);
    final var validators = new LinkedList<OAuth2TokenValidator<Jwt>>();

    validators.add(new JwtTimestampValidator(clockSkew));

    final var issuerUri = resolveIssuerUri(clientRegistration, providerConfig);
    if (StringUtils.hasText(issuerUri)) {
      validators.add(new JwtIssuerValidator(issuerUri));
    }

    final var audiences = resolveAudiences(clientRegistration, providerConfig);
    if (!audiences.isEmpty()) {
      validators.add(new AudienceValidator(audiences));
    }

    validators.addAll(extraValidators);

    return new DelegatingOAuth2TokenValidator<>(validators);
  }

  /**
   * Returns the issuer that the tokens of a registration must have. The issuer that the
   * registration carries wins over the {@code providers} map, because scopes with the same
   * registration ID can have different issuers. An empty issuer entry does not fall back to the
   * map, so a scope without an issuer never uses the issuer of another scope.
   */
  private static String resolveIssuerUri(
      final ClientRegistration clientRegistration, final OidcConfiguration providerConfig) {
    return ClientRegistrationMetadata.issuer(clientRegistration)
        .orElse(providerConfig != null ? providerConfig.getIssuerUri() : null);
  }

  /**
   * Resolves a registration's expected audiences: the {@link #AUDIENCES_METADATA_KEY} metadata
   * entry when present (authoritative, even when empty — an empty set disables audience
   * validation), otherwise the {@code providers}-map audiences.
   */
  private Set<String> resolveAudiences(
      final ClientRegistration clientRegistration, final OidcConfiguration providerConfig) {
    return ClientRegistrationMetadata.audiences(clientRegistration)
        .orElseGet(
            () ->
                providerConfig != null && providerConfig.getAudiences() != null
                    ? providerConfig.getAudiences()
                    : Set.of());
  }
}
