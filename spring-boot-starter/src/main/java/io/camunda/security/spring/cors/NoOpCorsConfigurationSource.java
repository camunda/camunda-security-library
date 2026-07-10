/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.cors;

import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Marker type used as the CSL no-op CORS default. {@link
 * io.camunda.security.spring.security.SecurityFilterChainSupport#applyCorsConfiguration} disables
 * CORS when it sees this type, and enables it for any other {@link
 * org.springframework.web.cors.CorsConfigurationSource} — including host-provided {@link
 * UrlBasedCorsConfigurationSource} instances that start empty and are populated later.
 *
 * <p><strong>Do not register CORS mappings on this instance.</strong> {@code
 * applyCorsConfiguration} keys off the marker type, not the registered mappings. Any mappings added
 * via {@link #registerCorsConfiguration} are silently ignored — CORS remains disabled. To enable
 * CORS, register your own {@link org.springframework.web.cors.CorsConfigurationSource} bean instead
 * of mutating this default.
 */
public final class NoOpCorsConfigurationSource extends UrlBasedCorsConfigurationSource {}
