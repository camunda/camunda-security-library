/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.autoconfigure.spring.oidc;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;

/**
 * Extension point for hosts to customize the OAuth2 login token endpoint — e.g., to wire {@code
 * private_key_jwt} client authentication. The OIDC webapp chain consumes this via {@code
 * ObjectProvider} and applies it if a host bean is registered; otherwise the default Spring
 * Security token response client is used.
 */
@FunctionalInterface
public interface OidcTokenEndpointCustomizer
    extends Customizer<OAuth2LoginConfigurer<HttpSecurity>.TokenEndpointConfig> {}
