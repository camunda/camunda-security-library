/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.cors.CorsBeansConfiguration;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import jakarta.servlet.Filter;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

/**
 * Verifies {@link SecurityFilterChainSupport#applyCorsConfiguration} behaviour:
 *
 * <ul>
 *   <li>No {@link CorsFilter} is added to the chain when the default empty {@link
 *       UrlBasedCorsConfigurationSource} is in use (preserves the previous always-disabled
 *       default).
 *   <li>A {@link CorsFilter} IS added when the host registers path mappings.
 * </ul>
 */
class ApplyCorsConfigurationTest {

  private static final String UNPROTECTED_CHAIN = "unprotectedPathsSecurityFilterChain";
  private static final String DENY_ALL_CHAIN = "protectedUnhandledPathsSecurityFilterChain";

  private final WebApplicationContextRunner runner =
      new WebApplicationContextRunner()
          .withUserConfiguration(ObjectMapperConfig.class, StubPaths.class)
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class,
                  CorsBeansConfiguration.class,
                  BaseSecurityConfiguration.class))
          .withPropertyValues("camunda.security.authentication.method=basic");

  @Test
  void noCorsFilterOnUnprotectedChainWhenNoHostSourceRegistered() {
    runner.run(
        ctx -> {
          assertThat(filtersOf(ctx.getBean(UNPROTECTED_CHAIN, SecurityFilterChain.class)))
              .as("default empty source must not add CorsFilter to unprotected-path chain")
              .noneSatisfy(f -> assertThat(f).isInstanceOf(CorsFilter.class));
        });
  }

  @Test
  void noCorsFilterOnDenyAllChainWhenNoHostSourceRegistered() {
    runner.run(
        ctx -> {
          assertThat(filtersOf(ctx.getBean(DENY_ALL_CHAIN, SecurityFilterChain.class)))
              .as("default empty source must not add CorsFilter to deny-all chain")
              .noneSatisfy(f -> assertThat(f).isInstanceOf(CorsFilter.class));
        });
  }

  @Test
  void corsFilterPresentOnUnprotectedChainWhenHostProvidesRegistrations() {
    runner
        .withBean(CorsConfigurationSource.class, ApplyCorsConfigurationTest::hostCorsSource)
        .run(
            ctx -> {
              assertThat(filtersOf(ctx.getBean(UNPROTECTED_CHAIN, SecurityFilterChain.class)))
                  .as("host-provided source with registrations must add CorsFilter")
                  .anySatisfy(f -> assertThat(f).isInstanceOf(CorsFilter.class));
            });
  }

  @Test
  void corsFilterPresentOnDenyAllChainWhenHostProvidesRegistrations() {
    runner
        .withBean(CorsConfigurationSource.class, ApplyCorsConfigurationTest::hostCorsSource)
        .run(
            ctx -> {
              assertThat(filtersOf(ctx.getBean(DENY_ALL_CHAIN, SecurityFilterChain.class)))
                  .as(
                      "host-provided source with registrations must add CorsFilter to deny-all chain")
                  .anySatisfy(f -> assertThat(f).isInstanceOf(CorsFilter.class));
            });
  }

  private static CorsConfigurationSource hostCorsSource() {
    final var config = new CorsConfiguration();
    config.addAllowedOrigin("https://example.com");
    final var source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);
    return source;
  }

  private static List<Filter> filtersOf(final SecurityFilterChain chain) {
    return ((DefaultSecurityFilterChain) chain).getFilters();
  }

  @Configuration
  static class StubPaths {

    @Bean
    SecurityPathPort securityPathPort() {
      return StubSecurityPaths.builder().unprotectedPaths("/actuator/**").build();
    }
  }

  @Configuration
  static class ObjectMapperConfig {

    @Bean
    ObjectMapper objectMapper() {
      return new ObjectMapper();
    }
  }
}
