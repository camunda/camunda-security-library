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
 * Handles authentication failures (missing or invalid bearer token) on the OIDC API chain. The
 * library-supplied default delegates to Spring's {@link
 * org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint},
 * preserving the RFC 6750 {@code WWW-Authenticate: Bearer} challenge; hosts override this bean to
 * apply different behavior for some or all requests on the chain (e.g. redirecting browser
 * navigations to a login page while still returning a bearer challenge for genuine API calls).
 *
 * <p>Deliberately a distinct type from {@link OidcAuthenticationEntryPoint} (the webapp-chain
 * equivalent): the two chains authenticate via different mechanisms (header-based bearer JWT here,
 * cookie-session OIDC login there), so a single bean must not be usable to satisfy both hooks
 * ambiguously.
 */
public interface OidcApiAuthenticationEntryPoint extends AuthenticationEntryPoint {}
