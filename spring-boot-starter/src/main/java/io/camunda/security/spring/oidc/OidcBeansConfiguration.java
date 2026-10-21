/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import io.camunda.security.api.context.MembershipResolutionContextPropagator;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.api.model.config.oidc.OidcPrincipalClaims;
import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import io.camunda.security.core.port.in.OidcProviderConfigurationPort;
import io.camunda.security.core.port.out.MembershipPort;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.converter.AdditionalJwkSetUrisByRegistrationId;
import io.camunda.security.spring.converter.TokenClaimsConvertersByIssuer;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.util.StringUtils;

/**
 * Provides default OIDC infrastructure beans not tied to client registration ({@link
 * OidcProviderConfigurationPort}-derived services) when {@code
 * camunda.security.authentication.method=oidc}. The client-registration-dependent beans ({@link
 * org.springframework.security.oauth2.jwt.JwtDecoder}, {@link
 * org.springframework.security.oauth2.client.registration.ClientRegistrationRepository}, and
 * related OAuth2 client beans) live in {@link OidcWebappClientBeansConfiguration}, additionally
 * gated on {@code camunda.security.authentication.webapp-enabled}. Hosts that need custom wiring
 * can override any bean via {@code @ConditionalOnMissingBean} back-off.
 *
 * <p>The per-scope OIDC factories ({@code JWSKeySelectorFactory}, {@code
 * ScopedClientRegistrationFactory}, {@code OidcAccessTokenDecoderFactory}, {@code
 * ScopedJwtDecoderFactory}) are declared in the unconditional {@link
 * ScopedOidcInfrastructureConfiguration} so they are available regardless of the global
 * authentication method. It is {@code @Import}ed so a host that opts in by importing only {@code
 * OidcBeansConfiguration} (the documented quickstart) still gets a working context. Its beans are
 * {@code @ConditionalOnMissingBean}, so importing it here and via the {@code
 * CamundaSecurityAutoConfiguration} umbrella is idempotent.
 */
@Configuration
@ConditionalOnProperty(name = "camunda.security.authentication.method", havingValue = "oidc")
@Import(ScopedOidcInfrastructureConfiguration.class)
public class OidcBeansConfiguration {

  private static final Logger LOG = LoggerFactory.getLogger(OidcBeansConfiguration.class);

  @Bean
  @ConditionalOnMissingBean
  public OidcProviderConfigurationPort oidcProviderConfigurationPort(
      final CamundaSecurityLibraryProperties properties,
      final ScopedClientRegistrationFactory scopedClientRegistrationFactory) {
    return new OidcAuthenticationConfigurationRepository(
        properties, scopedClientRegistrationFactory);
  }

  @Bean
  @ConditionalOnMissingBean
  public TokenValidatorFactory tokenValidatorFactory(
      final OidcProviderConfigurationPort oidcProviderConfigurationPort) {
    return new TokenValidatorFactory(
        oidcProviderConfigurationPort.getOidcAuthenticationConfigurations(),
        OidcConfiguration.DEFAULT_CLOCK_SKEW,
        List.of());
  }

  /**
   * Per-registration {@code additional-jwk-set-uris} lookup for {@code
   * OidcUserAuthenticationConverter}. Keyed by registration ID rather than by issuer URI so a
   * provider configured with explicit endpoints and no {@code issuer-uri} still contributes its
   * supplementary key sets; see <a
   * href="https://github.com/camunda/camunda-security-library/blob/main/docs/adr/0030-additional-jwk-set-uris-by-registration-id.md">ADR-0030</a>.
   *
   * <p>Registrations that declare no usable URI are left out, so the lookup answers {@code null}
   * for them and the decoder takes its single-URI path.
   */
  @Bean
  @ConditionalOnMissingBean
  public AdditionalJwkSetUrisByRegistrationId additionalJwkSetUrisByRegistrationId(
      final OidcProviderConfigurationPort oidcProviderConfigurationPort) {
    final Map<String, List<String>> byRegistrationId = new LinkedHashMap<>();
    // Blank ids are filtered for the same reason the claims-converter bean below filters them: a
    // blank key can never match a ClientRegistration's registrationId, so it would only ever be
    // dead weight in the lookup.
    ScopedClientRegistrationFactory.withoutBlankRegistrationIds(
            oidcProviderConfigurationPort.getOidcAuthenticationConfigurations())
        .forEach(
            (registrationId, config) -> {
              final var additionalUris = config.getAdditionalJwkSetUris();
              if (additionalUris != null
                  && additionalUris.stream().anyMatch(StringUtils::hasText)) {
                byRegistrationId.put(registrationId, additionalUris);
              }
            });
    LOG.debug("Additional JWK Set URIs by registration id: {}", byRegistrationId.keySet());
    return new AdditionalJwkSetUrisByRegistrationId(byRegistrationId);
  }

  @Bean
  @ConditionalOnMissingBean
  public AssertionJwkProvider assertionJwkProvider(
      final OidcProviderConfigurationPort oidcProviderConfigurationPort) {
    return new AssertionJwkProvider(oidcProviderConfigurationPort);
  }

  /**
   * Per-issuer {@link LazyTokenClaimsConverter} lookup for {@code
   * OidcTokenAuthenticationConverter}. Providers without an {@code issuer-uri} fall back to the
   * default converter.
   *
   * <p>The flat block's entry is identified by reference equality against {@code
   * properties.getAuthentication().getOidc()}, not by registration-ID key, since a custom {@code
   * registration-id} or a colliding {@code providers.oidc.*} key can each make the key unreliable.
   *
   * <p>Gated on {@link LazyTokenClaimsConverter} because the documented {@code @Import} quickstart
   * doesn't pull in {@code CamundaAuthenticationBeansConfiguration}, where that bean and {@link
   * MembershipResolutionContextPropagator} live; backing off avoids a fatal wiring failure when
   * they're absent.
   *
   * <p>Two registrations that share an issuer resolve by the order of {@code
   * getOidcAuthenticationConfigurations()}, which is the order of the configuration with the flat
   * block first. The decoder of the same deployment reads that order as well, so the converter of a
   * token comes from the provider that verified it.
   *
   * <p>With an enumerable {@link ClientRegistrationRepository} of the host, the converters follow
   * the issuers its registrations carry instead, as its decoder does; see {@link
   * RegisteredIssuerClaimsConverters}.
   */
  @Bean
  @ConditionalOnBean({MembershipPort.class, LazyTokenClaimsConverter.class})
  @ConditionalOnMissingBean
  public TokenClaimsConvertersByIssuer tokenClaimsConvertersByIssuer(
      final CamundaSecurityLibraryProperties properties,
      final OidcProviderConfigurationPort oidcProviderConfigurationPort,
      final LazyTokenClaimsConverter lazyTokenClaimsConverter,
      final MembershipPort membershipPort,
      final ObjectProvider<MembershipResolutionContextPropagator> contextPropagatorProvider,
      final ObjectProvider<ClientRegistrationRepository> clientRegistrationRepositoryProvider) {
    final var contextPropagator =
        contextPropagatorProvider.getIfAvailable(MembershipResolutionContextPropagator::identity);
    final var flatOidcConfiguration = properties.getAuthentication().getOidc();
    final var configurations = oidcProviderConfigurationPort.getOidcAuthenticationConfigurations();
    // IssuerOwnership decides the winner per issuer and logs the duplicate-issuer warning — the
    // one place that warning is built, redacted and sanitized, rather than a second copy of it
    // here. Filtered first: a blank/null registrationId must not win ownership over a valid
    // provider sharing its issuer, or the claims converter is built from the wrong configuration
    // while the decoder verifies the token with the valid one.
    final var providers =
        ScopedClientRegistrationFactory.withoutBlankRegistrationIds(configurations);
    final var repository = clientRegistrationRepositoryProvider.getIfAvailable();
    final var routesByConfiguration = routesByConfiguration(repository);
    if (!routesByConfiguration) {
      requireNoTrailingSlashTwins(providers);
    }
    final Map<String, LazyTokenClaimsConverter> byRegistrationId = new LinkedHashMap<>();
    providers.forEach(
        (registrationId, config) ->
            byRegistrationId.put(
                registrationId,
                config == flatOidcConfiguration
                    ? lazyTokenClaimsConverter
                    : namedProviderConverter(
                        config, flatOidcConfiguration, membershipPort, contextPropagator)));
    final var winningRegistrationIdByIssuer =
        IssuerOwnership.registrationIdByIssuer(
            providers, LOG, "the claim configuration", routesByConfiguration);
    final Map<String, LazyTokenClaimsConverter> byIssuer = new LinkedHashMap<>();
    winningRegistrationIdByIssuer.forEach(
        (issuerUri, registrationId) ->
            byIssuer.put(issuerUri, byRegistrationId.get(registrationId)));
    return new TokenClaimsConvertersByIssuer(
        byIssuer,
        routesByConfiguration,
        byRegisteredIssuer(routesByConfiguration, repository, byRegistrationId));
  }

  /** A named provider uses the global claims for each claim that it does not set. */
  private static LazyTokenClaimsConverter namedProviderConverter(
      final OidcConfiguration config,
      final OidcConfiguration flatOidcConfiguration,
      final MembershipPort membershipPort,
      final MembershipResolutionContextPropagator contextPropagator) {
    final var claims = OidcPrincipalClaims.resolve(config, flatOidcConfiguration);
    return new LazyTokenClaimsConverter(
        claims.usernameClaim(),
        claims.clientIdClaim(),
        claims.preferUsernameClaim(),
        membershipPort,
        contextPropagator);
  }

  /**
   * For a host's own repository, the converters are routed by the issuers its registrations carry,
   * as its decoder routes the tokens, rather than by the configured issuer-uris: discovery can
   * resolve a registration to the issuer the provider declares, such as {@code https://idp/realm}
   * for a configured {@code https://idp/realm/}, and its tokens would otherwise miss the claim
   * settings of their provider. A repository that cannot be enumerated keeps the lookup by the
   * configured issuer-uris.
   */
  @SuppressWarnings("unchecked")
  private static RegisteredIssuerClaimsConverters byRegisteredIssuer(
      final boolean routesByConfiguration,
      final ClientRegistrationRepository repository,
      final Map<String, LazyTokenClaimsConverter> byRegistrationId) {
    if (routesByConfiguration || !(repository instanceof Iterable)) {
      return null;
    }
    return new RegisteredIssuerClaimsConverters(
        (Iterable<ClientRegistration>) repository, byRegistrationId);
  }

  /**
   * With a host's own repository, the decoder routes the host's resolved registrations exactly,
   * while this map is keyed by the configured issuer-uris. Two providers whose issuer-uris differ
   * only by a trailing slash can both resolve to the provider's issuer (see {@code
   * ScopedClientRegistrationFactory}), and then the decoder and this map could pick different
   * providers for the same token, so a token would be mapped with another provider's claim
   * settings. Such a configuration is ambiguous, and before discovery tolerated the slash it failed
   * anyway, so it is rejected at the start rather than guessed.
   */
  private static void requireNoTrailingSlashTwins(final Map<String, OidcConfiguration> providers) {
    final Map<String, String> registrationIdByIssuer = new LinkedHashMap<>();
    providers.forEach(
        (registrationId, configuration) -> {
          final var issuerUri = configuration.getIssuerUri();
          if (issuerUri == null || issuerUri.isBlank()) {
            return;
          }
          final var twin = IssuerUris.withToggledTrailingSlash(issuerUri);
          final var twinRegistrationId = twin != null ? registrationIdByIssuer.get(twin) : null;
          if (twinRegistrationId != null) {
            throw new IllegalStateException(
                ("OIDC providers '%s' and '%s' declare issuer-uris that differ only by a trailing"
                        + " slash ('%s' and '%s'). With the ClientRegistrationRepository of the host"
                        + " application, their tokens cannot be told apart, so one provider's claim"
                        + " settings could be applied to the other's tokens. Remove one of them, or"
                        + " give both the issuer the identity provider declares.")
                    .formatted(
                        UrlRedaction.escapeControlCharacters(twinRegistrationId),
                        UrlRedaction.escapeControlCharacters(registrationId),
                        UrlRedaction.redact(twin),
                        UrlRedaction.redact(issuerUri)));
          }
          registrationIdByIssuer.putIfAbsent(issuerUri, registrationId);
        });
  }

  /**
   * Whether the access-token decoder routes tokens by the provider configuration, as {@code
   * OidcWebappClientBeansConfiguration#jwtDecoder} does for CSL's own {@link
   * LazyClientRegistrationRepository}, and the scoped decoders always do. Issuers that differ only
   * by a trailing slash are then one issuer. A host's own repository is routed exactly, by its
   * resolved registrations, so the claim converters must keep those issuers apart too, or a token
   * verified for one provider would be mapped with the other's claim settings.
   */
  private static boolean routesByConfiguration(final ClientRegistrationRepository repository) {
    return repository == null || repository instanceof LazyClientRegistrationRepository;
  }
}
