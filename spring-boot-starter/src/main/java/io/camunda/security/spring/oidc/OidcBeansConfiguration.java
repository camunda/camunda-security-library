/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.security.CamundaOidcLogoutSuccessHandler;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.util.StringUtils;

/**
 * Provides default OIDC infrastructure beans ({@link JwtDecoder}, {@link
 * ClientRegistrationRepository}, {@link OAuth2AuthorizedClientRepository}, {@link
 * OAuth2AuthorizedClientManager}) when {@code camunda.security.authentication.method=oidc}. Hosts
 * that need custom wiring can override any bean via {@code @ConditionalOnMissingBean} back-off.
 */
@Configuration
@ConditionalOnProperty(name = "camunda.security.authentication.method", havingValue = "oidc")
public class OidcBeansConfiguration {

  // RSA + EC families. Applied uniformly to every path so enabling
  // additional-jwk-set-uris does not silently widen or narrow the accepted set
  // relative to the single-URI / discovery paths. Matches the monorepo's
  // JWSKeySelectorFactory default; broader than Spring's RS256-only default for
  // NimbusJwtDecoder.withJwkSetUri(...).build(), which we override on every path.
  private static final Set<SignatureAlgorithm> DEFAULT_SIGNATURE_ALGORITHMS =
      Set.of(
          SignatureAlgorithm.RS256,
          SignatureAlgorithm.RS384,
          SignatureAlgorithm.RS512,
          SignatureAlgorithm.ES256,
          SignatureAlgorithm.ES384,
          SignatureAlgorithm.ES512);

  // Same algorithm set in the Nimbus type used by the composite path's
  // JWSVerificationKeySelector. Kept in lockstep with DEFAULT_SIGNATURE_ALGORITHMS above.
  private static final Set<JWSAlgorithm> DEFAULT_JWS_ALGORITHMS =
      Set.of(
          JWSAlgorithm.RS256,
          JWSAlgorithm.RS384,
          JWSAlgorithm.RS512,
          JWSAlgorithm.ES256,
          JWSAlgorithm.ES384,
          JWSAlgorithm.ES512);

  @Bean
  @ConditionalOnMissingBean
  public JwtDecoder jwtDecoder(final CamundaSecurityLibraryProperties properties) {
    // Single-decoder model: pick the flat block when configured, otherwise the sole providers entry
    // with a JWT source. When multiple providers are configured without a flat block, the host must
    // register their own JwtDecoder bean — a single decoder cannot correctly validate tokens from
    // multiple IdPs, so the library refuses to guess.
    final AuthenticationConfiguration authentication = properties.getAuthentication();
    // Specific-error pre-check: if any OidcConfiguration sets additional-jwk-set-uris without
    // a primary jwk-set-uri, fail with an actionable message before falling through to the generic
    // "set issuer-uri or jwk-set-uri" error. Keeps the misconfiguration discoverable even when
    // the only thing the host has configured is the additional list.
    requireExplicitPrimaryWhenAdditionalSet(authentication);
    final OidcConfiguration source = pickJwtDecoderSource(authentication);
    final List<String> additionalJwkSetUris = source.getAdditionalJwkSetUris();
    final NimbusJwtDecoder decoder;
    if (hasNonBlankEntries(additionalJwkSetUris)) {
      decoder = compositeJwtDecoder(source, additionalJwkSetUris);
    } else if (StringUtils.hasText(source.getJwkSetUri())) {
      final var builder = NimbusJwtDecoder.withJwkSetUri(source.getJwkSetUri());
      DEFAULT_SIGNATURE_ALGORITHMS.forEach(builder::jwsAlgorithm);
      decoder = builder.build();
    } else {
      final var builder = NimbusJwtDecoder.withIssuerLocation(source.getIssuerUri());
      DEFAULT_SIGNATURE_ALGORITHMS.forEach(builder::jwsAlgorithm);
      decoder = builder.build();
    }
    // Apply issuer-claim validation uniformly when issuer-uri is set. withIssuerLocation already
    // wires this; calling setJwtValidator again is harmless (it overrides with the same effective
    // validators). The composite path and the explicit jwk-set-uri path would otherwise skip the
    // 'iss' check entirely.
    if (StringUtils.hasText(source.getIssuerUri())) {
      decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(source.getIssuerUri()));
    }
    return decoder;
  }

  private static void requireExplicitPrimaryWhenAdditionalSet(
      final AuthenticationConfiguration authentication) {
    final var flat = authentication.getOidc();
    if (hasNonBlankEntries(flat.getAdditionalJwkSetUris())
        && !StringUtils.hasText(flat.getJwkSetUri())) {
      throw missingPrimaryJwkSetUri();
    }
    authentication
        .getProviders()
        .getOidc()
        .values()
        .forEach(
            provider -> {
              if (hasNonBlankEntries(provider.getAdditionalJwkSetUris())
                  && !StringUtils.hasText(provider.getJwkSetUri())) {
                throw missingPrimaryJwkSetUri();
              }
            });
  }

  private static IllegalStateException missingPrimaryJwkSetUri() {
    return new IllegalStateException(
        "Cannot build JwtDecoder with additional-jwk-set-uris when the primary jwk-set-uri is"
            + " unset: set camunda.security.authentication.oidc.jwk-set-uri (or"
            + " providers.oidc.<id>.jwk-set-uri) explicitly. Discovery via issuer-uri is not"
            + " supported when additional-jwk-set-uris is configured.");
  }

  /**
   * Builds a {@link NimbusJwtDecoder} backed by a {@link CompositeJWKSource} when {@code
   * additional-jwk-set-uris} is non-empty. The primary {@code jwk-set-uri} is queried first, then
   * each additional URI in declared order; the first source that resolves the token's signing key
   * wins. A failing source falls through to the next rather than failing the decode (see {@link
   * CompositeJWKSource}). Discovery via {@code issuer-uri} is not supported here — an explicit
   * primary {@code jwk-set-uri} must be set alongside the additional URIs.
   */
  private static NimbusJwtDecoder compositeJwtDecoder(
      final OidcConfiguration source, final List<String> additionalJwkSetUris) {
    if (!StringUtils.hasText(source.getJwkSetUri())) {
      throw missingPrimaryJwkSetUri();
    }
    final List<JWKSource<SecurityContext>> sources =
        java.util.stream.Stream.concat(
                java.util.stream.Stream.of(source.getJwkSetUri()),
                additionalJwkSetUris.stream().filter(StringUtils::hasText))
            .map(OidcBeansConfiguration::createJwkSource)
            .toList();
    final var composite = new CompositeJWKSource<SecurityContext>(sources);
    final var keySelector = new JWSVerificationKeySelector<>(DEFAULT_JWS_ALGORITHMS, composite);
    final var jwtProcessor = new DefaultJWTProcessor<SecurityContext>();
    jwtProcessor.setJWSKeySelector(keySelector);
    return new NimbusJwtDecoder(jwtProcessor);
  }

  private static JWKSource<SecurityContext> createJwkSource(final String jwkSetUri) {
    return JWKSourceBuilder.create(toUrl(jwkSetUri))
        .refreshAheadCache(false)
        .rateLimited(false)
        .cache(true)
        .build();
  }

  private static URL toUrl(final String jwkSetUri) {
    try {
      return URI.create(jwkSetUri).toURL();
    } catch (final MalformedURLException | IllegalArgumentException ex) {
      throw new IllegalArgumentException(
          "Invalid JWK Set URI '" + jwkSetUri + "': " + ex.getMessage(), ex);
    }
  }

  private static boolean hasNonBlankEntries(final List<String> uris) {
    return uris != null && uris.stream().anyMatch(StringUtils::hasText);
  }

  private static OidcConfiguration pickJwtDecoderSource(
      final AuthenticationConfiguration authentication) {
    final OidcConfiguration flat = authentication.getOidc();
    if (hasJwtSource(flat)) {
      return flat;
    }
    final var providerSources =
        authentication.getProviders().getOidc().values().stream()
            .filter(OidcBeansConfiguration::hasJwtSource)
            .toList();
    if (providerSources.size() == 1) {
      return providerSources.get(0);
    }
    if (providerSources.isEmpty()) {
      throw new IllegalStateException(
          "Cannot build JwtDecoder: set issuer-uri or jwk-set-uri under"
              + " camunda.security.authentication.oidc.* or under at least one"
              + " camunda.security.authentication.providers.oidc.<id>.* entry.");
    }
    throw new IllegalStateException(
        "Cannot build a single JwtDecoder when multiple providers are configured under"
            + " camunda.security.authentication.providers.oidc.* and the flat oidc block has no"
            + " issuer-uri or jwk-set-uri. Either configure the flat block to pin the resource-server"
            + " audience, or register a custom @Bean JwtDecoder in the host application.");
  }

  private static boolean hasJwtSource(final OidcConfiguration oidc) {
    return StringUtils.hasText(oidc.getJwkSetUri()) || StringUtils.hasText(oidc.getIssuerUri());
  }

  @Bean
  @ConditionalOnMissingBean
  public ClientRegistrationRepository clientRegistrationRepository(
      final CamundaSecurityLibraryProperties properties) {
    final var authentication = properties.getAuthentication();
    final OidcConfiguration flat = authentication.getOidc();
    final Map<String, OidcConfiguration> providers = authentication.getProviders().getOidc();

    // Mirrors OC's OidcAuthenticationConfigurationRepository: the flat block contributes a single
    // registration under its own registrationId when clientId is set; the providers map is merged
    // on top so a colliding provider id overwrites the flat entry.
    final Map<String, OidcConfiguration> sources = new LinkedHashMap<>();
    if (StringUtils.hasText(flat.getClientId())) {
      sources.put(flat.getRegistrationId(), flat);
    }
    sources.putAll(providers);

    if (sources.isEmpty()) {
      throw new IllegalStateException(
          "Cannot build ClientRegistrationRepository: set"
              + " camunda.security.authentication.oidc.client-id (with issuer-uri or explicit"
              + " endpoints), or one or more"
              + " camunda.security.authentication.providers.oidc.<id>.* entries.");
    }

    final var registrations =
        sources.entrySet().stream()
            .map(e -> buildClientRegistration(e.getKey(), e.getValue()))
            .toList();
    return new InMemoryClientRegistrationRepository(registrations);
  }

  /**
   * Builds a single {@link ClientRegistration} from {@link OidcConfiguration}. When {@code
   * issuer-uri} is set, OIDC discovery populates the authorization/token/user-info/jwk-set URIs
   * automatically; any explicitly-configured endpoint URI on {@link OidcConfiguration} then
   * overrides the discovered value. When {@code issuer-uri} is unset, all of authorization-uri,
   * token-uri, and jwk-set-uri must be configured explicitly. The {@code registrationId} argument
   * is the map key in the multi-provider shape and {@link OidcConfiguration#getRegistrationId()} in
   * the legacy flat shape.
   */
  private static ClientRegistration buildClientRegistration(
      final String registrationId, final OidcConfiguration oidc) {
    if (!StringUtils.hasText(registrationId)) {
      throw new IllegalStateException(
          "OIDC registrationId must be non-blank: set"
              + " camunda.security.authentication.oidc.registration-id (flat block)"
              + " or use a non-blank key under"
              + " camunda.security.authentication.providers.oidc.<id>.*");
    }
    final ClientRegistration.Builder builder =
        clientRegistrationBuilder(registrationId, oidc)
            .registrationId(registrationId)
            .clientId(oidc.getClientId())
            .clientSecret(oidc.getClientSecret())
            .clientAuthenticationMethod(
                new ClientAuthenticationMethod(oidc.getClientAuthenticationMethod()))
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri(oidc.getRedirectUri())
            .scope(oidc.getScope());
    if (!oidc.isUserInfoEnabled()) {
      builder.userInfoUri(null);
    }
    return builder.build();
  }

  /**
   * Builds the base {@link ClientRegistration.Builder}: discovery via {@code issuer-uri} when set,
   * otherwise an empty builder; in both cases any explicitly-configured endpoint URI on {@link
   * OidcConfiguration} overrides the discovered value. A non-blank value on the configuration
   * always wins; a null/blank value leaves the discovered value untouched.
   *
   * <p>Mirrors OC's previous {@code ClientRegistrationFactory} so that adopters can rely on
   * explicit overrides to plug gaps in incomplete IdP discovery metadata (older Keycloak realms,
   * custom STS endpoints, proxies that rewrite discovery documents). See
   * camunda/camunda-security-library#233.
   */
  private static ClientRegistration.Builder clientRegistrationBuilder(
      final String registrationId, final OidcConfiguration oidc) {
    final boolean hasIssuer = StringUtils.hasText(oidc.getIssuerUri());
    final ClientRegistration.Builder builder =
        hasIssuer
            ? ClientRegistrations.fromIssuerLocation(oidc.getIssuerUri())
                .registrationId(registrationId)
            : ClientRegistration.withRegistrationId(registrationId);

    if (!hasIssuer
        && (!StringUtils.hasText(oidc.getAuthorizationUri())
            || !StringUtils.hasText(oidc.getTokenUri())
            || !StringUtils.hasText(oidc.getJwkSetUri()))) {
      throw new IllegalStateException(
          "Cannot build ClientRegistration '"
              + registrationId
              + "': set issuer-uri, or all of authorization-uri, token-uri, and jwk-set-uri,"
              + " under camunda.security.authentication.oidc.* (flat) or"
              + " camunda.security.authentication.providers.oidc."
              + registrationId
              + ".*");
    }

    if (StringUtils.hasText(oidc.getAuthorizationUri())) {
      builder.authorizationUri(oidc.getAuthorizationUri());
    }
    if (StringUtils.hasText(oidc.getTokenUri())) {
      builder.tokenUri(oidc.getTokenUri());
    }
    if (StringUtils.hasText(oidc.getJwkSetUri())) {
      builder.jwkSetUri(oidc.getJwkSetUri());
    }
    if (StringUtils.hasText(oidc.getUserInfoUri())) {
      builder.userInfoUri(oidc.getUserInfoUri());
    }
    if (StringUtils.hasText(oidc.getEndSessionEndpointUri())) {
      // Spring's ClientRegistration carries end_session_endpoint via providerConfigurationMetadata.
      // Setting the map replaces the discovered metadata wholesale, so seed it with only the
      // explicit override; discovery already populated the builder's other endpoints individually.
      builder.providerConfigurationMetadata(
          Map.of("end_session_endpoint", oidc.getEndSessionEndpointUri()));
    }
    return builder;
  }

  @Bean
  @ConditionalOnMissingBean
  public OAuth2AuthorizedClientRepository authorizedClientRepository() {
    return new HttpSessionOAuth2AuthorizedClientRepository();
  }

  /**
   * Default {@link LogoutSuccessHandler} for the OIDC webapp chain. Preserves OC's RP-initiated
   * logout behaviour: a same-origin {@code Referer} is stored as the post-logout redirect URI on
   * the session under {@link CamundaOidcLogoutSuccessHandler#POST_LOGOUT_REDIRECT_ATTRIBUTE}, and
   * the OIDC {@code login_hint} claim is forwarded as {@code logout_hint} to the IdP's end-session
   * endpoint. Backs off via {@link ConditionalOnMissingBean} when the host registers its own {@link
   * LogoutSuccessHandler}.
   */
  @Bean
  @ConditionalOnMissingBean(LogoutSuccessHandler.class)
  public LogoutSuccessHandler camundaOidcLogoutSuccessHandler(
      final ClientRegistrationRepository clientRegistrationRepository) {
    return new CamundaOidcLogoutSuccessHandler(clientRegistrationRepository);
  }

  @Bean
  @ConditionalOnMissingBean
  public OAuth2AuthorizedClientManager authorizedClientManager(
      final ClientRegistrationRepository clientRegistrationRepository,
      final OAuth2AuthorizedClientRepository authorizedClientRepository) {
    final var provider =
        OAuth2AuthorizedClientProviderBuilder.builder()
            .authorizationCode()
            .refreshToken()
            .clientCredentials()
            .build();
    final var manager =
        new DefaultOAuth2AuthorizedClientManager(
            clientRegistrationRepository, authorizedClientRepository);
    manager.setAuthorizedClientProvider(provider);
    return manager;
  }
}
