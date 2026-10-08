/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import io.camunda.security.api.context.CamundaSecurityScopeProvider;
import io.camunda.security.api.context.MembershipResolutionContextPropagator;
import io.camunda.security.api.model.config.ScopedSecurityDescriptor;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import io.camunda.security.core.port.in.OidcProviderConfigurationPort;
import io.camunda.security.core.port.out.MembershipPort;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.converter.AdditionalJwkSetUrisByRegistrationId;
import io.camunda.security.spring.converter.TokenClaimsConvertersByIssuer;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
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
   * <p>Providers declared only through a per-scope {@link CamundaSecurityScopeProvider} descriptor
   * (ADR-0013) — for example a physical tenant's own identity provider — are included too, so a
   * bearer token issued by a scope-only provider resolves with that provider's own claim
   * configuration instead of the cluster default. The root-level providers are processed first and
   * own any issuer they share with a scope, so a deployment with no scope providers is unchanged
   * (ADR-0024 / issue #668, fixing camunda/camunda#64685).
   *
   * <p><b>Shared-issuer limitation.</b> The map is keyed by issuer alone, so when two sources (root
   * and a scope, or two scopes) declare the <em>same</em> issuer the first-processed source owns it
   * and the other's claim configuration is dropped. When the dropped settings <em>differ</em> from
   * the winner's this can misresolve a principal (e.g. one Microsoft Entra issuer serving two app
   * registrations with different {@code username-claim}s), so it is logged at {@code WARN} naming
   * both sources; an identical overlap (the default tenant appearing both at root and as its own
   * scope) stays quiet at {@code DEBUG}. Resolving the converter per scope is tracked as <a
   * href="https://github.com/camunda/camunda-security-library/issues/714">#714</a>.
   *
   * <p><b>Scope ordering.</b> Scope providers are read through an {@link ObjectProvider}, whose
   * iteration order is not guaranteed to match {@code ScopedSecurityChainRegistrar}'s bean-name
   * order. That only matters when two scopes share an issuer — the case #714 addresses — so until
   * then "first scope wins" is best-effort for that overlap and exact for every distinct issuer.
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
      final ScopedClientRegistrationFactory scopedClientRegistrationFactory,
      final ObjectProvider<CamundaSecurityScopeProvider> scopeProviders) {
    final var contextPropagator =
        contextPropagatorProvider.getIfAvailable(MembershipResolutionContextPropagator::identity);
    final var flatOidcConfiguration = properties.getAuthentication().getOidc();
    final Map<String, LazyTokenClaimsConverter> byIssuer = new LinkedHashMap<>();
    // Tracks which source owns each issuer, so a later cross-source collision can name the winner
    // and compare its claim settings — see IssuerOwner and logSharedIssuer below.
    final Map<String, IssuerOwner> ownerByIssuer = new LinkedHashMap<>();

    // Root-level providers (flat oidc.* block + providers.oidc.*) first, so they own any issuer a
    // scope provider shares with them and a deployment without scope providers is unchanged.
    addConvertersByIssuer(
        byIssuer,
        ownerByIssuer,
        oidcProviderConfigurationPort.getOidcAuthenticationConfigurations(),
        flatOidcConfiguration,
        lazyTokenClaimsConverter,
        membershipPort,
        contextPropagator,
        "the root providers",
        "the claim configuration");

    // Then providers declared only through per-scope descriptors (ADR-0013). flatten() merges each
    // scope's own flat + providers.oidc.* block the same way the root config port does.
    for (final var descriptor : collectScopeDescriptors(scopeProviders)) {
      final var scopeLabel = "scope '" + descriptor.basePath() + "'";
      addConvertersByIssuer(
          byIssuer,
          ownerByIssuer,
          scopedClientRegistrationFactory.flatten(descriptor.authentication()),
          flatOidcConfiguration,
          lazyTokenClaimsConverter,
          membershipPort,
          contextPropagator,
          scopeLabel,
          "the claim configuration of " + scopeLabel);
    }

    return new TokenClaimsConvertersByIssuer(byIssuer);
  }

  /**
   * Collects the descriptors of every {@link CamundaSecurityScopeProvider} bean, guarding against a
   * {@code null} list or {@code null} element exactly as {@code
   * ScopedSecurityChainRegistrar#collectDescriptors} does — so a provider contract violation fails
   * with a clear message here too, rather than an anonymous {@link NullPointerException} at bean
   * creation.
   */
  private static List<ScopedSecurityDescriptor> collectScopeDescriptors(
      final ObjectProvider<CamundaSecurityScopeProvider> scopeProviders) {
    final List<ScopedSecurityDescriptor> descriptors = new ArrayList<>();
    scopeProviders.forEach(
        provider -> {
          final var returned = provider.get();
          if (returned == null) {
            throw new IllegalStateException(
                "CamundaSecurityScopeProvider "
                    + provider.getClass().getName()
                    + " returned null; it must return a (possibly empty) list of descriptors");
          }
          for (final var descriptor : returned) {
            if (descriptor == null) {
              throw new IllegalStateException(
                  "CamundaSecurityScopeProvider "
                      + provider.getClass().getName()
                      + " returned a list containing a null element");
            }
            descriptors.add(descriptor);
          }
        });
    return descriptors;
  }

  /**
   * Adds one issuer-keyed {@link LazyTokenClaimsConverter} per provider in {@code configurations}
   * that declares an {@code issuer-uri}, skipping any issuer already owned by an earlier source
   * (the root config, or an earlier scope) and recording the owner of every new issuer in {@code
   * ownerByIssuer}.
   *
   * <p>{@link IssuerOwnership} decides the winner per issuer <em>within</em> this source and logs
   * the duplicate-issuer warning — the one place that warning is built, redacted and sanitized.
   * Blank/null registrationIds are filtered first: a blank id must not win ownership over a valid
   * provider sharing its issuer, or the claims converter is built from the wrong configuration
   * while the decoder verifies the token with the valid one.
   *
   * @param sourceLabel names this source (e.g. {@code "the root providers"} or {@code "scope
   *     '/x'"}) for the cross-source collision diagnostic
   * @param ownershipLabel the within-source phrase {@link IssuerOwnership} uses for its own
   *     duplicate-issuer warning
   */
  private static void addConvertersByIssuer(
      final Map<String, LazyTokenClaimsConverter> byIssuer,
      final Map<String, IssuerOwner> ownerByIssuer,
      final Map<String, OidcConfiguration> configurations,
      final OidcConfiguration flatOidcConfiguration,
      final LazyTokenClaimsConverter defaultConverter,
      final MembershipPort membershipPort,
      final MembershipResolutionContextPropagator contextPropagator,
      final String sourceLabel,
      final String ownershipLabel) {
    final var winningRegistrationIdByIssuer =
        IssuerOwnership.registrationIdByIssuer(
            ScopedClientRegistrationFactory.withoutBlankRegistrationIds(configurations),
            LOG,
            ownershipLabel);
    winningRegistrationIdByIssuer.forEach(
        (issuerUri, registrationId) -> {
          final var config = configurations.get(registrationId);
          final var existingOwner = ownerByIssuer.get(issuerUri);
          if (existingOwner != null) {
            logSharedIssuer(issuerUri, existingOwner, sourceLabel, config);
            return;
          }
          final var converter =
              config == flatOidcConfiguration
                  ? defaultConverter
                  : new LazyTokenClaimsConverter(
                      config.getUsernameClaim(),
                      config.getClientIdClaim(),
                      config.isPreferUsernameClaim(),
                      membershipPort,
                      contextPropagator);
          byIssuer.put(issuerUri, converter);
          ownerByIssuer.put(issuerUri, new IssuerOwner(sourceLabel, config));
        });
  }

  /**
   * Diagnoses a cross-source issuer collision: the issuer is already owned, so the current source's
   * claim configuration is dropped. Logged at {@code WARN} when the dropped settings
   * <em>differ</em> from the winner's (a principal can be misresolved — see #714), at {@code DEBUG}
   * when they are identical (the benign default-tenant-at-root-and-as-scope overlap). The issuer is
   * redacted like the {@link IssuerOwnership} warning, since the warn-only issuer-uri check lets a
   * credential-bearing value reach here too.
   */
  private static void logSharedIssuer(
      final String issuerUri,
      final IssuerOwner owner,
      final String ignoredSourceLabel,
      final OidcConfiguration ignoredConfig) {
    final var redactedIssuer = UrlRedaction.redact(issuerUri);
    if (claimSettingsDiffer(owner.config(), ignoredConfig)) {
      LOG.warn(
          "Issuer '{}' is configured by both {} and {} with different claim settings. {} owns it,"
              + " so bearer tokens from this issuer are converted with that source's claim"
              + " configuration and a token actually issued for {} may resolve the wrong principal."
              + " The claim converter is keyed by issuer alone and cannot tell the two apart; see"
              + " https://github.com/camunda/camunda-security-library/issues/714.",
          redactedIssuer,
          owner.sourceLabel(),
          ignoredSourceLabel,
          owner.sourceLabel(),
          ignoredSourceLabel);
    } else {
      LOG.debug(
          "Issuer '{}' is already owned by {} with identical claim settings; ignoring the"
              + " duplicate from {}.",
          redactedIssuer,
          owner.sourceLabel(),
          ignoredSourceLabel);
    }
  }

  private static boolean claimSettingsDiffer(
      final OidcConfiguration winner, final OidcConfiguration ignored) {
    return !Objects.equals(winner.getUsernameClaim(), ignored.getUsernameClaim())
        || !Objects.equals(winner.getClientIdClaim(), ignored.getClientIdClaim())
        || winner.isPreferUsernameClaim() != ignored.isPreferUsernameClaim();
  }

  /** The source that owns an issuer's converter, plus the config its claim settings came from. */
  private record IssuerOwner(String sourceLabel, OidcConfiguration config) {}
}
