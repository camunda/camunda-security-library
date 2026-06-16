/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static com.nimbusds.jose.JOSEObjectType.JWT;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtTypeValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.util.StringUtils;

/**
 * Factory for creating {@link JwtDecoder} instances tailored for decoding access tokens issued by
 * OpenID Connect (OIDC) Identity Providers.
 *
 * <p>This factory supports both single-issuer and multi-issuer (issuer-aware) setups, and enforces
 * proper configuration of issuer URIs and JWK Set URIs.
 */
public class OidcAccessTokenDecoderFactory {

  // We explicitly support the "at+jwt" JWT 'typ' header defined in
  // https://datatracker.ietf.org/doc/html/rfc9068#name-header
  static final JOSEObjectType AT_JWT = new JOSEObjectType("at+jwt");
  private static final Logger LOG = LoggerFactory.getLogger(OidcAccessTokenDecoderFactory.class);
  private static final String ERROR_MISSING_ISSUER =
      "The following OIDC Providers are missing 'issuerUri': %s";
  private static final String ERROR_MISSING_JWK =
      "OIDC Provider '%s' is missing a valid 'jwk-set-uri'. Issuer URI: %s";
  private final JWSKeySelectorFactory jwsKeySelectorFactory;
  private final TokenValidatorFactory tokenValidatorFactory;

  public OidcAccessTokenDecoderFactory(
      final JWSKeySelectorFactory jwsKeySelectorFactory,
      final TokenValidatorFactory tokenValidatorFactory) {
    this.jwsKeySelectorFactory = jwsKeySelectorFactory;
    this.tokenValidatorFactory = tokenValidatorFactory;
  }

  /**
   * Creates a {@link JwtDecoder} that supports multiple OIDC Providers by resolving issuer-specific
   * keys and validation logic at runtime.
   *
   * @param clientRegistrations the list of client registrations to support
   * @return a {@link JwtDecoder} capable of handling multiple issuers
   * @throws IllegalArgumentException if any registration is missing an issuer URI
   */
  public JwtDecoder createIssuerAwareAccessTokenDecoder(
      final List<ClientRegistration> clientRegistrations) {
    return createIssuerAwareAccessTokenDecoder(clientRegistrations, Collections.emptyMap());
  }

  /**
   * Creates a {@link JwtDecoder} that supports multiple OIDC Providers by resolving issuer-specific
   * keys and validation logic at runtime, with support for additional JWK Set URIs per issuer.
   *
   * <p>Uses the injected singleton {@link TokenValidatorFactory}. Callers that need validators
   * built from a specific provider map should use {@link #createIssuerAwareAccessTokenDecoder(List,
   * Map, TokenValidatorFactory)} instead.
   *
   * @param clientRegistrations the list of client registrations to support
   * @param additionalJwkSetUrisByIssuer a map of issuer URI to additional JWK Set URIs
   * @return a {@link JwtDecoder} capable of handling multiple issuers with multi-JWKS support
   * @throws IllegalArgumentException if any registration is missing an issuer URI
   */
  public JwtDecoder createIssuerAwareAccessTokenDecoder(
      final List<ClientRegistration> clientRegistrations,
      final Map<String, List<String>> additionalJwkSetUrisByIssuer) {
    return createIssuerAwareAccessTokenDecoder(
        clientRegistrations, additionalJwkSetUrisByIssuer, tokenValidatorFactory);
  }

  /**
   * Creates a {@link JwtDecoder} that supports multiple OIDC Providers by resolving issuer-specific
   * keys and validation logic at runtime, with support for additional JWK Set URIs per issuer,
   * using the supplied {@link TokenValidatorFactory} for building token validators.
   *
   * @param clientRegistrations the list of client registrations to support
   * @param additionalJwkSetUrisByIssuer a map of issuer URI to additional JWK Set URIs
   * @param validatorFactory the {@link TokenValidatorFactory} to use for building token validators
   * @return a {@link JwtDecoder} capable of handling multiple issuers with multi-JWKS support
   * @throws IllegalArgumentException if any registration is missing an issuer URI
   */
  public JwtDecoder createIssuerAwareAccessTokenDecoder(
      final List<ClientRegistration> clientRegistrations,
      final Map<String, List<String>> additionalJwkSetUrisByIssuer,
      final TokenValidatorFactory validatorFactory) {
    LOG.debug(
        "Creating an Issuer Aware JwtDecoder for multiple OIDC Providers: {}",
        clientRegistrations.size());
    validateClientRegistrationsHaveIssuer(clientRegistrations);
    final var jwtProcessor =
        createIssuerAwareJwtProcessor(clientRegistrations, additionalJwkSetUrisByIssuer);
    final var jwtValidator = createIssuerAwareJwtValidator(clientRegistrations, validatorFactory);
    return wrapKeySourceFailuresAsBadJwt(createNimbusJwtDecoder(jwtProcessor, jwtValidator));
  }

  /**
   * Validates that all provided {@link ClientRegistration} entries have a configured issuer URI.
   *
   * @param clientRegistrations the list of client registrations to validate
   * @throws IllegalArgumentException if any registration is missing a valid issuer URI
   */
  protected void validateClientRegistrationsHaveIssuer(
      final List<ClientRegistration> clientRegistrations) {
    final var invalidProviders =
        clientRegistrations.stream()
            .filter(
                r -> {
                  final var issuerUri = r.getProviderDetails().getIssuerUri();
                  return issuerUri == null || issuerUri.isBlank();
                })
            .map(ClientRegistration::getRegistrationId)
            .toList();

    if (!invalidProviders.isEmpty()) {
      throw new IllegalArgumentException(
          ERROR_MISSING_ISSUER.formatted(String.join(", ", invalidProviders)));
    }
  }

  /**
   * Creates a {@link JwtDecoder} for a single OIDC Identity Provider.
   *
   * @param clientRegistration the client registration to use
   * @return a {@link JwtDecoder} for that client
   * @throws IllegalArgumentException if the registration is missing a JWK Set URI
   */
  public JwtDecoder createAccessTokenDecoder(final ClientRegistration clientRegistration) {
    return createAccessTokenDecoder(clientRegistration, null);
  }

  /**
   * Creates a {@link JwtDecoder} for a single OIDC Identity Provider with optional additional JWK
   * Set URIs.
   *
   * <p>Uses the injected singleton {@link TokenValidatorFactory}. Callers that need validators
   * built from a specific provider map should use {@link
   * #createAccessTokenDecoder(ClientRegistration, List, TokenValidatorFactory)} instead.
   *
   * @param clientRegistration the client registration to use
   * @param additionalJwkSetUris additional JWK Set URIs for key resolution
   * @return a {@link JwtDecoder} for that client
   * @throws IllegalArgumentException if the registration is missing a JWK Set URI
   */
  public JwtDecoder createAccessTokenDecoder(
      final ClientRegistration clientRegistration, final List<String> additionalJwkSetUris) {
    return createAccessTokenDecoder(
        clientRegistration, additionalJwkSetUris, tokenValidatorFactory);
  }

  /**
   * Creates a {@link JwtDecoder} for a single OIDC Identity Provider with optional additional JWK
   * Set URIs, using the supplied {@link TokenValidatorFactory} for building the token validator.
   *
   * @param clientRegistration the client registration to use
   * @param additionalJwkSetUris additional JWK Set URIs for key resolution
   * @param validatorFactory the {@link TokenValidatorFactory} to use for building the token
   *     validator
   * @return a {@link JwtDecoder} for that client
   * @throws IllegalArgumentException if the registration is missing a JWK Set URI
   */
  public JwtDecoder createAccessTokenDecoder(
      final ClientRegistration clientRegistration,
      final List<String> additionalJwkSetUris,
      final TokenValidatorFactory validatorFactory) {
    LOG.debug("Creating JwtDecoder for OIDC Provider {}", clientRegistration.getRegistrationId());
    LOG.debug("Additional JWK Set URIs: {}", additionalJwkSetUris);
    final var jwtProcessor = createJwtProcessor(clientRegistration, additionalJwkSetUris);
    final var jwtValidator = createJwtValidator(clientRegistration, validatorFactory);
    return wrapKeySourceFailuresAsBadJwt(createNimbusJwtDecoder(jwtProcessor, jwtValidator));
  }

  /**
   * Selects between a single-issuer and an issuer-aware multi-issuer {@link JwtDecoder} based on
   * the number of registrations — the single authoritative place for this decision.
   *
   * <p>Delegates to {@link #createAccessTokenDecoder(ClientRegistration, List)} for a single
   * registration, and to {@link #createIssuerAwareAccessTokenDecoder(List, Map)} for multiple
   * registrations. Per-provider {@code additional-jwk-set-uris} are forwarded in both cases.
   *
   * <p>Uses the injected singleton {@link TokenValidatorFactory} for building token validators.
   * Callers that need validators built from a specific provider map (e.g. a per-scope factory)
   * should use {@link #selectAccessTokenDecoder(List, Map, TokenValidatorFactory)} instead.
   *
   * @param registrations the list of client registrations; must not be empty
   * @param providersById the provider configuration map keyed by registrationId, used to resolve
   *     per-provider {@code additional-jwk-set-uris}
   * @return a {@link JwtDecoder} appropriate for the given registrations
   * @throws IllegalStateException if {@code registrations} is empty
   */
  public JwtDecoder selectAccessTokenDecoder(
      final List<ClientRegistration> registrations,
      final Map<String, OidcConfiguration> providersById) {
    return selectAccessTokenDecoder(registrations, providersById, tokenValidatorFactory);
  }

  /**
   * Selects between a single-issuer and an issuer-aware multi-issuer {@link JwtDecoder} based on
   * the number of registrations, using the supplied {@link TokenValidatorFactory} for building
   * token validators.
   *
   * <p>This overload allows callers to provide a scope-specific {@link TokenValidatorFactory} so
   * that audience and issuer-claim validation are performed against the scope's own provider
   * configuration rather than a global singleton. The global path (via {@link
   * #selectAccessTokenDecoder(List, Map)}) delegates here with the singleton factory.
   *
   * @param registrations the list of client registrations; must not be empty
   * @param providersById the provider configuration map keyed by registrationId, used to resolve
   *     per-provider {@code additional-jwk-set-uris}
   * @param validatorFactory the {@link TokenValidatorFactory} to use for building token validators
   * @return a {@link JwtDecoder} appropriate for the given registrations
   * @throws IllegalStateException if {@code registrations} is empty
   */
  public JwtDecoder selectAccessTokenDecoder(
      final List<ClientRegistration> registrations,
      final Map<String, OidcConfiguration> providersById,
      final TokenValidatorFactory validatorFactory) {
    if (registrations.isEmpty()) {
      throw new IllegalStateException(
          "ClientRegistrationRepository is empty — at least one OIDC provider must be configured."
              + " Set camunda.security.authentication.oidc.* (flat) or one or more"
              + " camunda.security.authentication.providers.oidc.<id>.* entries.");
    }
    if (registrations.size() == 1) {
      final var reg = registrations.get(0);
      final var config = providersById.get(reg.getRegistrationId());
      final var additional = config != null ? config.getAdditionalJwkSetUris() : null;
      return createAccessTokenDecoder(reg, additional, validatorFactory);
    }
    return createIssuerAwareAccessTokenDecoder(
        registrations,
        buildAdditionalJwkSetUrisByIssuer(registrations, providersById),
        validatorFactory);
  }

  /**
   * Wraps a {@link JwtDecoder} so failures caused by {@link BadJwtKeySourceException} are mapped
   * from the generic {@link JwtException} that {@link NimbusJwtDecoder} produces to a {@link
   * BadJwtException}.
   *
   * <p>Why this matters: Spring Security's {@code JwtAuthenticationProvider} only translates {@link
   * BadJwtException} (and its {@code InvalidBearerTokenException} sibling) into the {@code
   * invalid_token} response. A plain {@link JwtException} becomes {@code
   * AuthenticationServiceException} and surfaces as HTTP 500. {@link IssuerAwareJWSKeySelector}
   * throws {@link BadJwtKeySourceException} for token-level faults (unknown or missing {@code iss}
   * claim) — semantically those are bad tokens and the resource server should answer with HTTP 401
   * {@code invalid_token}.
   *
   * <p>The wrap deliberately matches only the {@link BadJwtKeySourceException} marker, not the
   * generic {@link KeySourceException} base type. Plain {@link KeySourceException} is reused by
   * other parts of the stack (e.g. {@link CompositeJWKSource} for JWKS retrieval failures, Nimbus's
   * {@code RemoteJWKSet} for I/O errors); those are infrastructure faults and should keep their
   * {@link JwtException} mapping so an IdP outage surfaces as a 500 rather than a misleading 401.
   *
   * <p>{@link NimbusJwtDecoder} catches {@link KeySourceException} (a {@code JOSEException}) and
   * rewraps it as a {@link JwtException} rather than a {@link BadJwtException}; this wrap restores
   * the correct response code at the boundary every adopter of CSL consumes, without disguising
   * outages as authentication failures.
   */
  static JwtDecoder wrapKeySourceFailuresAsBadJwt(final JwtDecoder delegate) {
    return token -> {
      try {
        return delegate.decode(token);
      } catch (final BadJwtException ex) {
        throw ex;
      } catch (final JwtException ex) {
        if (ex.getCause() instanceof BadJwtKeySourceException) {
          throw new BadJwtException(ex.getMessage(), ex.getCause());
        }
        throw ex;
      }
    };
  }

  /**
   * Extracts the JWK Set URI from the given client registration.
   *
   * @param clientRegistration the client registration
   * @return the JWK Set URI
   * @throws IllegalArgumentException if the URI is missing or blank
   */
  protected String getJWKSetUri(final ClientRegistration clientRegistration) {
    final var providerDetails = clientRegistration.getProviderDetails();
    final var jwkSetUri = providerDetails.getJwkSetUri();
    if (jwkSetUri == null || jwkSetUri.isBlank()) {
      throw new IllegalArgumentException(
          ERROR_MISSING_JWK.formatted(
              clientRegistration.getRegistrationId(), providerDetails.getIssuerUri()));
    }
    return jwkSetUri;
  }

  /**
   * Creates a {@link NimbusJwtDecoder} using the given processor and validator.
   *
   * @param jwtProcessor the JWT processor
   * @param tokenValidator the token validator
   * @return a configured {@link NimbusJwtDecoder}
   */
  protected NimbusJwtDecoder createNimbusJwtDecoder(
      final JWTProcessor<SecurityContext> jwtProcessor,
      final OAuth2TokenValidator<Jwt> tokenValidator) {
    final var decoder = new NimbusJwtDecoder(jwtProcessor);
    // Two-layer typ enforcement (defense-in-depth):
    // 1. createJOSEObjectTypeVerifier() — Nimbus-level, runs before JWK lookup; primary gate.
    // 2. JwtTypeValidator below — Spring-level, runs after signature verification; ensures the
    //    same allowlist (JWT, at+jwt, absent) is enforced even if the Nimbus verifier is ever
    //    swapped or subclassed. Both layers accept the same set, so they cannot diverge.
    final JwtTypeValidator jwtTypeValidator =
        new JwtTypeValidator(List.of(JOSEObjectType.JWT.getType(), AT_JWT.getType()));
    jwtTypeValidator.setAllowEmpty(true);
    decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(jwtTypeValidator, tokenValidator));
    return decoder;
  }

  /**
   * Creates a {@link ConfigurableJWTProcessor} that is aware of multiple issuers.
   *
   * @param clientRegistrations the list of client registrations
   * @return a configured JWT processor
   */
  protected ConfigurableJWTProcessor<SecurityContext> createIssuerAwareJwtProcessor(
      final List<ClientRegistration> clientRegistrations) {
    return createIssuerAwareJwtProcessor(clientRegistrations, Collections.emptyMap());
  }

  /**
   * Creates a {@link ConfigurableJWTProcessor} that is aware of multiple issuers and supports
   * additional JWK Set URIs per issuer.
   *
   * @param clientRegistrations the list of client registrations
   * @param additionalJwkSetUrisByIssuer a map of issuer URI to additional JWK Set URIs
   * @return a configured JWT processor
   */
  protected ConfigurableJWTProcessor<SecurityContext> createIssuerAwareJwtProcessor(
      final List<ClientRegistration> clientRegistrations,
      final Map<String, List<String>> additionalJwkSetUrisByIssuer) {
    final var jwsKeySelector =
        new IssuerAwareJWSKeySelector(
            clientRegistrations, jwsKeySelectorFactory, additionalJwkSetUrisByIssuer);
    return createAndCustomizeJwtProcessor(
        processor -> processor.setJWTClaimsSetAwareJWSKeySelector(jwsKeySelector));
  }

  /**
   * Creates a {@link ConfigurableJWTProcessor} for a single issuer using its JWK Set URI.
   *
   * @param clientRegistration the client registration
   * @return a configured JWT processor
   */
  protected ConfigurableJWTProcessor<SecurityContext> createJwtProcessor(
      final ClientRegistration clientRegistration) {
    return createJwtProcessor(clientRegistration, null);
  }

  /**
   * Creates a {@link ConfigurableJWTProcessor} for a single issuer with optional additional JWK Set
   * URIs.
   *
   * @param clientRegistration the client registration
   * @param additionalJwkSetUris additional JWK Set URIs for key resolution
   * @return a configured JWT processor
   */
  protected ConfigurableJWTProcessor<SecurityContext> createJwtProcessor(
      final ClientRegistration clientRegistration, final List<String> additionalJwkSetUris) {
    final var jwkSetUri = getJWKSetUri(clientRegistration);
    final var jwsKeySelector =
        jwsKeySelectorFactory.createJWSKeySelector(jwkSetUri, additionalJwkSetUris);
    return createAndCustomizeJwtProcessor(processor -> processor.setJWSKeySelector(jwsKeySelector));
  }

  /**
   * Creates and customizes a {@link ConfigurableJWTProcessor} with a standard JOSE header type
   * verifier.
   *
   * @param customizer a lambda for applying processor-specific customization
   * @return a configured JWT processor
   */
  protected ConfigurableJWTProcessor<SecurityContext> createAndCustomizeJwtProcessor(
      final Consumer<ConfigurableJWTProcessor<SecurityContext>> customizer) {
    final var jwtProcessor = new DefaultJWTProcessor<>();
    final var jwsTypeVerifier = createJOSEObjectTypeVerifier();
    jwtProcessor.setJWSTypeVerifier(jwsTypeVerifier);
    customizer.accept(jwtProcessor);
    return jwtProcessor;
  }

  /**
   * Creates a {@link Jwt} validator that supports multiple issuers, using the injected singleton
   * {@link TokenValidatorFactory}.
   *
   * @param clientRegistrations the list of client registrations
   * @return a token validator aware of multiple issuers
   */
  protected OAuth2TokenValidator<Jwt> createIssuerAwareJwtValidator(
      final List<ClientRegistration> clientRegistrations) {
    return createIssuerAwareJwtValidator(clientRegistrations, tokenValidatorFactory);
  }

  /**
   * Creates a {@link Jwt} validator that supports multiple issuers, using the supplied {@link
   * TokenValidatorFactory}.
   *
   * @param clientRegistrations the list of client registrations
   * @param validatorFactory the {@link TokenValidatorFactory} to use
   * @return a token validator aware of multiple issuers
   */
  protected OAuth2TokenValidator<Jwt> createIssuerAwareJwtValidator(
      final List<ClientRegistration> clientRegistrations,
      final TokenValidatorFactory validatorFactory) {
    return new IssuerAwareTokenValidator(clientRegistrations, validatorFactory);
  }

  /**
   * Creates a token validator for a single OIDC Identity Provider, using the injected singleton
   * {@link TokenValidatorFactory}.
   *
   * @param clientRegistration the client registration
   * @return a token validator for the issuer
   */
  protected OAuth2TokenValidator<Jwt> createJwtValidator(
      final ClientRegistration clientRegistration) {
    return createJwtValidator(clientRegistration, tokenValidatorFactory);
  }

  /**
   * Creates a token validator for a single OIDC Identity Provider, using the supplied {@link
   * TokenValidatorFactory}.
   *
   * @param clientRegistration the client registration
   * @param validatorFactory the {@link TokenValidatorFactory} to use
   * @return a token validator for the issuer
   */
  protected OAuth2TokenValidator<Jwt> createJwtValidator(
      final ClientRegistration clientRegistration, final TokenValidatorFactory validatorFactory) {
    return validatorFactory.createTokenValidator(clientRegistration);
  }

  /**
   * Creates a {@link JOSEObjectTypeVerifier} that accepts standard JWT types.
   *
   * @return a JOSE object type verifier
   */
  protected JOSEObjectTypeVerifier<SecurityContext> createJOSEObjectTypeVerifier() {
    return new DefaultJOSEObjectTypeVerifier<>(JWT, AT_JWT, null);
  }

  /**
   * Builds a map of issuer URI to additional JWK Set URIs from the given registrations and provider
   * configuration. Only registrations with a non-empty {@code additional-jwk-set-uris} list and a
   * non-blank {@code issuerUri} contribute an entry.
   *
   * @param registrations the list of client registrations
   * @param providers the provider configuration map keyed by registrationId
   * @return a map of issuer URI to additional JWK Set URIs; empty if none configured
   */
  private static Map<String, List<String>> buildAdditionalJwkSetUrisByIssuer(
      final List<ClientRegistration> registrations,
      final Map<String, OidcConfiguration> providers) {
    return registrations.stream()
        .filter(
            reg -> {
              final var config = providers.get(reg.getRegistrationId());
              return config != null
                  && config.getAdditionalJwkSetUris() != null
                  && config.getAdditionalJwkSetUris().stream().anyMatch(StringUtils::hasText)
                  && StringUtils.hasText(reg.getProviderDetails().getIssuerUri());
            })
        .collect(
            Collectors.toMap(
                reg -> reg.getProviderDetails().getIssuerUri(),
                reg -> providers.get(reg.getRegistrationId()).getAdditionalJwkSetUris(),
                (a, b) -> a));
  }
}
