/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.client;

import io.camunda.security.api.model.config.client.OutboundBasicConfiguration;
import io.camunda.security.api.model.config.client.OutboundClientConfiguration;
import io.camunda.security.api.model.config.client.OutboundOidcConfiguration;
import io.camunda.security.client.BasicAuthConfiguration;
import io.camunda.security.client.OidcClientCredentialsConfiguration;
import io.camunda.security.client.OutboundCredentialsProvider;
import io.camunda.security.client.OutboundCredentialsProviders;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Builds the {@link OutboundCredentialsProviders} registry from the named clients under {@code
 * camunda.security.client.<name>}. Each client sets exactly one of {@code oidc} and {@code basic}.
 * The bean always exists, also when no client is configured. Spring closes the registry when the
 * context closes. A host can replace the bean with its own.
 *
 * <p>Error messages name the property path and never contain a configured value.
 */
@Configuration
public class OutboundCredentialsConfiguration {

  private static final Logger LOG = LoggerFactory.getLogger(OutboundCredentialsConfiguration.class);
  private static final String PREFIX = "camunda.security.client.";

  @Bean
  @ConditionalOnMissingBean
  public OutboundCredentialsProviders outboundCredentialsProviders(
      final CamundaSecurityLibraryProperties properties) {
    final Map<String, OutboundCredentialsProvider> providers = new LinkedHashMap<>();
    properties
        .getClient()
        .forEach((name, client) -> providers.put(name, createProvider(name, client)));
    if (!providers.isEmpty()) {
      LOG.info("Outbound clients configured: {}", providers.keySet());
    }
    return new OutboundCredentialsProviders(providers);
  }

  private static OutboundCredentialsProvider createProvider(
      final String name, final OutboundClientConfiguration client) {
    final var oidc = client == null ? null : client.getOidc();
    final var basic = client == null ? null : client.getBasic();
    if ((oidc == null) == (basic == null)) {
      throw new IllegalStateException(PREFIX + name + " must set exactly one of oidc or basic");
    }
    if (oidc != null) {
      return OutboundCredentialsProviders.oidc(toOidc(name, oidc));
    }
    return OutboundCredentialsProviders.basic(toBasic(name, basic));
  }

  private static OidcClientCredentialsConfiguration toOidc(
      final String name, final OutboundOidcConfiguration oidc) {
    final String path = PREFIX + name + ".oidc";
    final URI tokenUri = parseTokenUri(path, oidc.getTokenUri());
    try {
      return new OidcClientCredentialsConfiguration(
          tokenUri,
          oidc.getClientId(),
          oidc.getClientSecret(),
          oidc.getAudience(),
          oidc.getScopes(),
          oidc.getResource(),
          oidc.getConnectTimeout(),
          oidc.getReadTimeout());
    } catch (final IllegalArgumentException e) {
      throw new IllegalStateException("Invalid " + path + ": " + e.getMessage(), e);
    }
  }

  private static URI parseTokenUri(final String path, final String tokenUri) {
    if (tokenUri == null || tokenUri.isBlank()) {
      throw new IllegalStateException(path + ".token-uri must be set");
    }
    try {
      return URI.create(tokenUri);
    } catch (final IllegalArgumentException e) {
      // The exception message holds the raw value, which can contain user-info. Report the path
      // only.
      throw new IllegalStateException(path + ".token-uri is not a valid URI");
    }
  }

  private static BasicAuthConfiguration toBasic(
      final String name, final OutboundBasicConfiguration basic) {
    final String path = PREFIX + name + ".basic";
    if (basic.getPassword() == null) {
      throw new IllegalStateException(path + ".password must be set");
    }
    try {
      return new BasicAuthConfiguration(basic.getUsername(), basic.getPassword());
    } catch (final IllegalArgumentException e) {
      throw new IllegalStateException("Invalid " + path + ": " + e.getMessage(), e);
    }
  }
}
