/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.camunda.security.api.context.OidcClaimsProvider;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.micrometer.core.instrument.MeterRegistry;
import java.net.http.HttpClient;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

/**
 * Registers the {@link OidcClaimsProvider} bean: an augmenting provider when {@code
 * camunda.security.authentication.oidc.user-info-augmentation.enabled=true}, or a {@link
 * NoopOidcClaimsProvider} otherwise. A host-supplied {@link OidcClaimsProvider} bean suppresses
 * both via {@link ConditionalOnMissingBean}.
 *
 * <p>The augmenting provider is a {@link CachingOidcClaimsProvider} that resolves the UserInfo
 * endpoint of one issuer at the first claims lookup that carries it, or a {@link
 * DeferredOidcClaimsProvider} over the whole repository of the host application, which cannot be
 * read per issuer.
 *
 * <p>The two beans carry mutually exclusive {@code @ConditionalOnProperty} conditions ({@code
 * enabled=true} vs {@code enabled=false, matchIfMissing=true}), so registration is deterministic
 * regardless of bean declaration order.
 */
@Configuration
@ConditionalOnProperty(name = "camunda.security.authentication.method", havingValue = "oidc")
public class OidcClaimsProviderConfiguration {

  private static final Logger LOG = LoggerFactory.getLogger(OidcClaimsProviderConfiguration.class);

  /**
   * JDK HTTP client used by {@link CachingOidcClaimsProvider} to call the IdP's UserInfo endpoint.
   * Hosts can override by registering a bean named {@code oidcUserInfoHttpClient} — for example to
   * supply a custom SSL context via {@code spring.ssl.bundle.*}.
   */
  // Must be declared before cachingOidcClaimsProvider:
  // @ConditionalOnMissingBean(OidcClaimsProvider.class)
  // is evaluated in declaration order within a @Configuration class, so placing this after the
  // caching provider would suppress it — leaving cachingOidcClaimsProvider unable to inject it.
  @Bean(name = "oidcUserInfoHttpClient")
  @ConditionalOnProperty(
      name = "camunda.security.authentication.oidc.user-info-augmentation.enabled",
      havingValue = "true")
  @ConditionalOnMissingBean(value = OidcClaimsProvider.class, name = "oidcUserInfoHttpClient")
  HttpClient oidcUserInfoHttpClient() {
    return OidcUserInfoHttpClient.defaultHttpClient();
  }

  /**
   * The per-issuer UserInfo URIs come from a {@link ClientRegistrationRepository}, which only the
   * webapp chain registers (see {@link OidcWebappClientBeansConfiguration}). A bearer-only host
   * that enables augmentation must therefore supply its own {@link ClientRegistrationRepository} or
   * {@link OidcClaimsProvider}.
   *
   * <p>To read the UserInfo URI of a provider is to make OIDC discovery. The provider resolves the
   * URI at the first claims lookup that needs it, and not while the application starts.
   *
   * <p>A {@link LazyClientRegistrationRepository} declares the issuer of each registration, so the
   * provider resolves one issuer at a time, and an identity provider that does not answer fails the
   * tokens of its own issuer only. Any other repository of the host application can hold
   * registrations that no configuration of the library describes, so the provider reads it as a
   * whole, and one identity provider that does not answer fails the augmentation of every token.
   * See {@link DeferredOidcClaimsProvider}.
   *
   * @throws IllegalStateException if the mapping cannot read the repository. The shape of a
   *     repository needs no network access, so such a configuration error stops the start.
   */
  @Bean
  @ConditionalOnProperty(
      name = "camunda.security.authentication.oidc.user-info-augmentation.enabled",
      havingValue = "true")
  @ConditionalOnMissingBean(OidcClaimsProvider.class)
  @ConditionalOnBean(ClientRegistrationRepository.class)
  OidcClaimsProvider cachingOidcClaimsProvider(
      final ClientRegistrationRepository clientRegistrationRepository,
      final CamundaSecurityLibraryProperties properties,
      final ObjectMapper objectMapper,
      @Qualifier("oidcUserInfoHttpClient") final HttpClient httpClient,
      @Autowired(required = false) final MeterRegistry meterRegistry) {
    requireIterable(clientRegistrationRepository);
    final var augmentation = properties.getAuthentication().getOidc().getUserInfoAugmentation();
    final var fetcher = new OidcUserInfoHttpClient(httpClient, objectMapper);
    if (clientRegistrationRepository instanceof final LazyClientRegistrationRepository lazy) {
      // lazy.providers() is already free of a blank/null registrationId — its constructor filters
      // it after warning about it, so no filtering is needed here.
      final var providers = lazy.providers();
      return new CachingOidcClaimsProvider(
          fetcher,
          CachingOidcClaimsProvider.userInfoUriByIssuer(
              IssuerRegistrations.ofConfiguration(
                  providers, lazy::findByRegistrationId, "the UserInfo endpoint"),
              providers),
          augmentation,
          meterRegistry);
    }
    return new DeferredOidcClaimsProvider(
        userInfoMappingSubject(),
        () ->
            CachingOidcClaimsProvider.forConfiguredMappings(
                fetcher,
                buildUserInfoUriByIssuer(clientRegistrationRepository),
                augmentation,
                meterRegistry));
  }

  @Bean
  @ConditionalOnProperty(
      name = "camunda.security.authentication.oidc.user-info-augmentation.enabled",
      havingValue = "false",
      matchIfMissing = true)
  @ConditionalOnMissingBean(OidcClaimsProvider.class)
  OidcClaimsProvider noopOidcClaimsProvider() {
    return new NoopOidcClaimsProvider();
  }

  /** Names the mapping, and the repository of the host application it reads, for a failure log. */
  private static String userInfoMappingSubject() {
    return "the per-issuer UserInfo endpoint mapping of the ClientRegistrationRepository of the"
        + " host application";
  }

  /**
   * Rejects a repository the mapping cannot read. The shape of a repository needs no network
   * access, so a host that wires a repository of the wrong shape learns this at the start.
   */
  private static void requireIterable(final ClientRegistrationRepository repo) {
    if (!(repo instanceof Iterable)) {
      throw new IllegalStateException(
          "UserInfo augmentation is enabled but the ClientRegistrationRepository is not iterable, so"
              + " the per-issuer UserInfo mapping cannot be derived. Register a custom"
              + " OidcClaimsProvider bean to supply the mapping explicitly, or disable userinfo"
              + " augmentation"
              + " (camunda.security.authentication.oidc.user-info-augmentation.enabled=false).");
    }
  }

  /**
   * Maps each issuer to the UserInfo endpoint of the registration that {@link IssuerOwnership}
   * gives that issuer, which is the registration the decoder also reads. To read a {@link
   * ClientRegistration} is to resolve it, so the deferred provider alone calls this method.
   */
  static Map<String, String> buildUserInfoUriByIssuer(final ClientRegistrationRepository repo) {
    final List<ClientRegistration> registrations = new ArrayList<>();
    for (final Object item : (Iterable<?>) repo) {
      if (item instanceof final ClientRegistration reg) {
        registrations.add(reg);
      }
    }
    final Map<String, String> map = new LinkedHashMap<>();
    IssuerOwnership.byIssuer(registrations, LOG, "the UserInfo endpoint")
        .forEach(
            (issuerUri, owner) -> {
              final var userInfoUri = owner.getProviderDetails().getUserInfoEndpoint().getUri();
              if (userInfoUri != null && !userInfoUri.isBlank()) {
                map.put(issuerUri, userInfoUri);
              }
            });
    return map;
  }
}
