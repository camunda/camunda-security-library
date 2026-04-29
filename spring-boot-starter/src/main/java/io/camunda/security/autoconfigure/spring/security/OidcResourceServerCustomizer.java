/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.autoconfigure.spring.security;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;

/**
 * Extension point applied inside the {@code oauth2ResourceServer(...)} DSL of {@link
 * OidcApiSecurityAutoConfiguration} and {@link OidcWebappSecurityAutoConfiguration}.
 * Implementations are discovered via {@link org.springframework.beans.factory.ObjectProvider} and
 * applied in {@code @Order}.
 *
 * <p>Typical use cases include wiring RFC 9728 {@code protectedResourceMetadata} customisers,
 * adjusting JWT validators, or swapping the bearer-token entry point.
 *
 * <pre>{@code
 * @Bean
 * public OidcResourceServerCustomizer protectedResourceMetadata(...) {
 *     return oauth2 -> oauth2.protectedResourceMetadata(...);
 * }
 * }</pre>
 */
@FunctionalInterface
public interface OidcResourceServerCustomizer {
  void customize(OAuth2ResourceServerConfigurer<HttpSecurity> oauth2);
}
