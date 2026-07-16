/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * SPI for contributing additional response headers, or route-varying header behavior, to CSL
 * security filter chains.
 *
 * <p>CSL's own {@code camunda.security.http-headers.*} configuration applies a fixed, static set of
 * headers uniformly across the whole chain. Register a bean of this type to add headers CSL doesn't
 * know about, or to vary header application by route:
 *
 * <pre>{@code
 * @Bean
 * public SecurityHeadersCustomizer extraHeaders() {
 *   return http -> http.headers(headers -> headers.addHeaderWriter(
 *       (request, response) -> response.setHeader("X-My-Header", "value")));
 * }
 * }</pre>
 *
 * <p>CSL applies every registered customizer, in {@code @Order} order, to every content-serving
 * filter chain. No bean present means no additional headers beyond CSL's static configuration. See
 * ADR-0037 for the design rationale.
 */
@FunctionalInterface
public interface SecurityHeadersCustomizer {
  void customize(HttpSecurity http) throws Exception;
}
