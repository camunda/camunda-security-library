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
import io.camunda.security.core.port.out.BasicAuthUserDetailsPort;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import io.camunda.security.spring.user.UserConfiguration;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Verifies the {@link SecurityHeadersCustomizer} SPI contract on {@link
 * UnprotectedApiSecurityConfiguration#unprotectedApiSecurityFilterChain}: when a host registers a
 * customizer bean it is invoked during chain construction and any filter it adds is present in the
 * built chain.
 */
class UnprotectedApiCustomizerIntegrationTest {

  private static final String UNPROTECTED_API_CHAIN_BEAN = "unprotectedApiSecurityFilterChain";

  private final WebApplicationContextRunner runner =
      new WebApplicationContextRunner()
          .withUserConfiguration(
              ObjectMapperConfig.class, StubPaths.class, StubUserDetailsPort.class)
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class,
                  BaseSecurityConfiguration.class,
                  AuthFailureHandlerConfiguration.class,
                  UnprotectedApiSecurityConfiguration.class,
                  UserConfiguration.class))
          .withPropertyValues(
              "camunda.security.authentication.method=basic",
              "camunda.security.authentication.unprotected-api=true");

  @Test
  void securityHeadersMarkerFilterIsPresentWhenSecurityHeadersCustomizerBeanIsRegistered() {
    runner
        .withUserConfiguration(StubSecurityHeadersCustomizerConfig.class)
        .run(
            ctx -> {
              final var chain = ctx.getBean(UNPROTECTED_API_CHAIN_BEAN, SecurityFilterChain.class);
              assertThat(filtersOf(chain))
                  .as("MarkerFilter added by SecurityHeadersCustomizer must be in the filter chain")
                  .anySatisfy(f -> assertThat(f).isInstanceOf(MarkerFilter.class));
            });
  }

  @Test
  void markerFilterIsAbsentWhenNoCustomizerBeanIsRegistered() {
    runner.run(
        ctx -> {
          final var chain = ctx.getBean(UNPROTECTED_API_CHAIN_BEAN, SecurityFilterChain.class);
          assertThat(filtersOf(chain))
              .as("no customizer registered — MarkerFilter must not be in the chain")
              .noneSatisfy(f -> assertThat(f).isInstanceOf(MarkerFilter.class));
        });
  }

  private static List<Filter> filtersOf(final SecurityFilterChain chain) {
    return ((DefaultSecurityFilterChain) chain).getFilters();
  }

  static final class MarkerFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(
        final HttpServletRequest request,
        final HttpServletResponse response,
        final FilterChain filterChain)
        throws ServletException, IOException {
      filterChain.doFilter(request, response);
    }
  }

  @Configuration
  static class StubSecurityHeadersCustomizerConfig {

    @Bean
    SecurityHeadersCustomizer securityHeadersCustomizer() {
      return http ->
          http.addFilterBefore(
              new MarkerFilter(),
              org.springframework.security.web.context.SecurityContextHolderFilter.class);
    }
  }

  @Configuration
  static class ObjectMapperConfig {

    @Bean
    ObjectMapper objectMapper() {
      return new ObjectMapper();
    }
  }

  @Configuration
  static class StubPaths {

    @Bean
    SecurityPathPort securityPathPort() {
      return StubSecurityPaths.builder().build();
    }
  }

  @Configuration
  static class StubUserDetailsPort {

    @Bean
    BasicAuthUserDetailsPort userDetailsPort() {
      return username -> null;
    }
  }
}
