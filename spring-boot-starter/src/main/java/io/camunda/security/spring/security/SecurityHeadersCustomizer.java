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
 * SPI for contributing dynamic response-header behavior to CSL security filter chains — including
 * Content-Security-Policy, or any other header CSL's static configuration doesn't know about.
 *
 * <p>CSL's own {@code camunda.security.http-headers.*} configuration (including {@code
 * content-security-policy.*}) applies a fixed, static set of headers uniformly across the whole
 * chain — it cannot generate a fresh CSP nonce per request, vary a header by route, or add a header
 * CSL has no opinion on. Register a bean of this type to add that behavior, typically via a custom
 * {@code HeaderWriter}:
 *
 * <pre>{@code
 * @Bean
 * public SecurityHeadersCustomizer nonceBasedCsp() {
 *   return http -> http.headers(headers -> headers.addHeaderWriter(new MyNonceCspHeaderWriter()));
 * }
 * }</pre>
 *
 * <p>CSL applies every registered customizer, in {@code @Order} order, to every content-serving
 * filter chain. No bean present means no additional header behavior beyond CSL's static
 * configuration. See ADR-0037 for the design rationale.
 */
@FunctionalInterface
public interface SecurityHeadersCustomizer {
  void customize(HttpSecurity http) throws Exception;
}
