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
 * SPI for contributing dynamic Content-Security-Policy behavior to CSL security filter chains.
 *
 * <p>CSL's own {@code camunda.security.http-headers.content-security-policy.*} configuration
 * applies a single static, property-resolved directive string, uniformly across the whole chain —
 * it cannot generate a fresh nonce per request or vary the policy by route. Register a bean of this
 * type to add that behavior; a common implementation registers a custom {@code HeaderWriter} that
 * generates a nonce per request and writes its own {@code Content-Security-Policy} header,
 * coexisting with (or superseding, depending on write order) CSL's static header:
 *
 * <pre>{@code
 * @Bean
 * public CspCustomizer nonceBasedCsp() {
 *   return http -> http.headers(headers -> headers.addHeaderWriter(new MyNonceCspHeaderWriter()));
 * }
 * }</pre>
 *
 * <p>CSL applies every registered customizer, in {@code @Order} order, to every content-serving
 * filter chain. No bean present means no additional CSP behavior beyond CSL's static configuration.
 * See ADR-0037 for the design rationale.
 */
@FunctionalInterface
public interface CspCustomizer {
  void customize(HttpSecurity http) throws Exception;
}
