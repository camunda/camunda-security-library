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
 * SPI for inserting an HTTPS redirect filter into CSL security filter chains.
 *
 * <p>Register a bean of this type to redirect HTTP requests to HTTPS. CSL applies the customizer to
 * every filter chain: the unprotected-path chain, the catch-all deny chain, the dev-mode
 * unprotected API chain, scoped API chains, and scoped webapp chains. No bean present means no
 * redirect — CSL's default is to leave HTTP→HTTPS policy to the host's infrastructure layer.
 *
 * <p>The customizer receives full access to {@link HttpSecurity}, so the redirect strategy,
 * excluded paths, and response code are entirely host-controlled. A typical implementation:
 *
 * <pre>{@code
 * @Bean
 * public HttpsRedirectCustomizer httpsRedirectCustomizer() {
 *   return http -> http.addFilterBefore(
 *       new MyHttpsRedirectFilter(),
 *       org.springframework.security.web.context.SecurityContextHolderFilter.class);
 * }
 * }</pre>
 */
@FunctionalInterface
public interface HttpsRedirectCustomizer {
  void customize(HttpSecurity http) throws Exception;
}
