/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.spi;

import org.springframework.security.web.AuthenticationEntryPoint;

/**
 * Handles redirect-to-IdP for unauthenticated browser navigations on the stateful OIDC webapp chain
 * built by {@link io.camunda.security.spring.security.ScopedWebappSecurityChainBuilder}. The
 * library-supplied default delegates to Spring's standard OAuth2 login redirect; hosts override
 * this bean to redirect to a custom Identity authorize URL instead.
 */
public interface OidcAuthenticationEntryPoint extends AuthenticationEntryPoint {}
