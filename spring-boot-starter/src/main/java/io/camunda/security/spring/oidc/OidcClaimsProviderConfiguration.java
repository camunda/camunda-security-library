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
import io.camunda.security.api.model.config.oidc.OidcUserInfoAugmentationConfiguration;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.micrometer.core.instrument.MeterRegistry;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

/**
 * Registers the {@link OidcClaimsProvider} bean: either a {@link CachingOidcClaimsProvider} when
 * {@code camunda.security.authentication.oidc.user-info-augmentation.enabled=true}, or a {@link
 * NoopOidcClaimsProvider} otherwise. A host-supplied {@link OidcClaimsProvider} bean suppresses
 * both via {@link ConditionalOnMissingBean}.
 *
 * <p>Declaration order matters: the caching bean is evaluated first. When the property condition
 * passes it registers, and the noop sees an existing bean and backs off. When the property
 * condition fails the noop registers.
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
  @Bean(name = "oidcUserInfoHttpClient")
  @ConditionalOnMissingBean(name = "oidcUserInfoHttpClient")
  HttpClient oidcUserInfoHttpClient() {
    return HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(2))
        .followRedirects(HttpClient.Redirect.NEVER)
        .build();
  }

  @Bean
  @ConditionalOnProperty(
      name = "camunda.security.authentication.oidc.user-info-augmentation.enabled",
      havingValue = "true")
  @ConditionalOnMissingBean(OidcClaimsProvider.class)
  OidcClaimsProvider cachingOidcClaimsProvider(
      final ClientRegistrationRepository clientRegistrationRepository,
      final CamundaSecurityLibraryProperties properties,
      final ObjectMapper objectMapper,
      @Qualifier("oidcUserInfoHttpClient") final HttpClient httpClient,
      @Autowired(required = false) final MeterRegistry meterRegistry) {
    final OidcUserInfoAugmentationConfiguration config =
        properties.getAuthentication().getOidc().getUserInfoAugmentation();
    final Map<String, String> uriByIssuer = buildUserInfoUriByIssuer(clientRegistrationRepository);
    return new CachingOidcClaimsProvider(
        new OidcUserInfoHttpClient(httpClient, objectMapper), uriByIssuer, config, meterRegistry);
  }

  @Bean
  @ConditionalOnMissingBean(OidcClaimsProvider.class)
  OidcClaimsProvider noopOidcClaimsProvider() {
    return new NoopOidcClaimsProvider();
  }

  /**
   * Builds the per-issuer UserInfo URI map from the resolved {@link ClientRegistration}s. Requires
   * the repository to be iterable (the default {@link
   * org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository}
   * is). Returns an empty map if the repository is not iterable.
   */
  @SuppressWarnings("unchecked")
  private static Map<String, String> buildUserInfoUriByIssuer(
      final ClientRegistrationRepository repo) {
    if (!(repo instanceof Iterable)) {
      LOG.warn(
          "ClientRegistrationRepository is not Iterable; per-issuer UserInfo routing"
              + " will be unavailable. Register a custom OidcClaimsProvider bean to"
              + " supply the issuer→userInfoUri mapping explicitly.");
      return Map.of();
    }
    final Map<String, String> map = new HashMap<>();
    for (final ClientRegistration reg : (Iterable<ClientRegistration>) repo) {
      final String issuerUri = reg.getProviderDetails().getIssuerUri();
      final String userInfoUri = reg.getProviderDetails().getUserInfoEndpoint().getUri();
      if (issuerUri != null
          && !issuerUri.isBlank()
          && userInfoUri != null
          && !userInfoUri.isBlank()) {
        map.put(issuerUri, userInfoUri);
      }
    }
    return map;
  }
}
