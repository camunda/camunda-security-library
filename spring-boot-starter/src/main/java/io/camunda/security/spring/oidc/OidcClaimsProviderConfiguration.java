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
 * Registers the {@link OidcClaimsProvider} bean: either a {@link CachingOidcClaimsProvider} that
 * resolves the UserInfo endpoint of an issuer at the first claims lookup that needs it when {@code
 * camunda.security.authentication.oidc.user-info-augmentation.enabled=true}, or a {@link
 * NoopOidcClaimsProvider} otherwise. A host-supplied {@link OidcClaimsProvider} bean suppresses
 * both via {@link ConditionalOnMissingBean}.
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
   * Requires session-scoped OAuth2 client-registration infrastructure ({@link
   * ClientRegistrationRepository}) to resolve the per-issuer UserInfo URIs, so this bean only
   * activates when the webapp chain is enabled ({@code
   * camunda.security.authentication.webapp-enabled} is not {@code false}); that repository bean is
   * only registered in that case (see {@link OidcWebappClientBeansConfiguration}). A bearer-only
   * OIDC host that disables the webapp chain and enables UserInfo augmentation without supplying
   * its own {@link ClientRegistrationRepository} or {@link OidcClaimsProvider} therefore gets no
   * UserInfo-augmenting default from CSL.
   *
   * <p>To read the UserInfo URI of a provider is to make OIDC discovery, so the provider resolves
   * it at the first claims lookup that needs it.
   *
   * <p>A {@link LazyClientRegistrationRepository} gives the provider the UserInfo endpoint of one
   * issuer at a time. An identity provider that does not answer then fails the augmentation of the
   * tokens of its own issuer, and the tokens of the providers that answer keep theirs. The issuers
   * come from the configuration of that repository, so an endpoint belongs to the provider that
   * declares the issuer of the token, whoever built the repository.
   *
   * <p>Any other repository of the host application can hold registrations that no configuration of
   * the library describes, so the mapping reads the whole repository in that case, and one provider
   * that does not answer fails the augmentation of every token. See {@link
   * DeferredOidcClaimsProvider}.
   *
   * <p>The mapping needs a repository it can read, and the shape of a repository needs no network
   * access, so the method checks it here, and a configuration error still stops the start.
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

  /**
   * Names the mapping and the repository it reads. Only a repository the library cannot read per
   * issuer reaches this step, and such a repository belongs to the host application, which is what
   * the subject says.
   */
  private static String userInfoMappingSubject() {
    return "the per-issuer UserInfo endpoint mapping of the ClientRegistrationRepository of the"
        + " host application";
  }

  /**
   * Rejects a repository the mapping cannot read. The shape of a repository needs no network
   * access, so the method runs while the application builds the bean, and a host that wires a
   * repository of the wrong shape learns it at the start.
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
   * Builds the per-issuer UserInfo URI map from the resolved {@link ClientRegistration}s. Reading a
   * registration resolves it, so this method runs inside the deferred provider only. Where two
   * registrations declare the same issuer, the map holds the endpoint of the registration that
   * {@link IssuerOwnership} names the owner of that issuer, which is the registration the decoder
   * reads.
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
