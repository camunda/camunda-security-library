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
import io.camunda.security.core.port.out.BasicAuthUserDetailsPort.CamundaUserDetails;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.user.UserConfiguration;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * End-to-end coverage for the wiring this feature relies on: CSL ships a {@link
 * io.camunda.security.spring.user.CamundaUserDetailsService} and a default {@link PasswordEncoder}
 * but leaves the basic-auth chain config untouched, trusting Spring Boot to assemble the chain's
 * {@code AuthenticationManager} from those two beans. This drives a real {@code Authorization:
 * Basic} request through the actual {@code basicAuthApiSecurityFilterChain} (not a hand-built
 * {@code DaoAuthenticationProvider}) so a regression in that assumption fails the build.
 */
class BasicAuthApiChainAuthenticationTest {

  private static final String API_CHAIN_BEAN = "basicAuthApiSecurityFilterChain";

  private final WebApplicationContextRunner runner =
      new WebApplicationContextRunner()
          .withUserConfiguration(
              ObjectMapperConfig.class, StubPaths.class, StubUserDetailsPort.class)
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class,
                  BaseSecurityConfiguration.class,
                  // No manual ScopedApiSecurityChainBuilderConfiguration import: it is @Imported by
                  // BasicAuthApiSecurityConfiguration, so the individual-import path is
                  // self-contained.
                  BasicAuthApiSecurityConfiguration.class,
                  AuthFailureHandlerConfiguration.class,
                  UserConfiguration.class))
          .withPropertyValues("camunda.security.authentication.method=basic");

  @Test
  void validBasicCredentialsAuthenticateThroughTheChain() {
    runner.run(
        ctx -> {
          stubResolvableUser(ctx, "alice", "s3cret");
          final var response = new MockHttpServletResponse();
          final var next = sendApiRequest(ctx, "alice", "s3cret", response);

          // Authenticated: the chain handed the request downstream rather than issuing a 401.
          assertThat(next.getRequest()).isNotNull();
          assertThat(response.getStatus()).isEqualTo(200);
        });
  }

  @Test
  void wrongPasswordIsRejectedByTheChain() {
    runner.run(
        ctx -> {
          stubResolvableUser(ctx, "alice", "s3cret");
          final var response = new MockHttpServletResponse();
          final var next = sendApiRequest(ctx, "alice", "wrong", response);

          assertThat(next.getRequest()).isNull();
          assertThat(response.getStatus()).isEqualTo(401);
        });
  }

  @Test
  void unknownUserIsRejectedByTheChain() {
    runner.run(
        ctx -> {
          stubResolvableUser(ctx, "alice", "s3cret");
          final var response = new MockHttpServletResponse();
          final var next = sendApiRequest(ctx, "ghost", "s3cret", response);

          assertThat(next.getRequest()).isNull();
          assertThat(response.getStatus()).isEqualTo(401);
        });
  }

  private static void stubResolvableUser(
      final org.springframework.context.ApplicationContext ctx,
      final String username,
      final String rawPassword) {
    // Encode with the context's own PasswordEncoder so the provider validates against the same
    // encoding scheme that CSL wires into the chain.
    final var encoder = ctx.getBean(PasswordEncoder.class);
    final var port = ctx.getBean(BasicAuthUserDetailsPort.class);
    Mockito.when(port.loadUser(username))
        .thenReturn(new CamundaUserDetails(username, encoder.encode(rawPassword)));
  }

  private static MockFilterChain sendApiRequest(
      final org.springframework.context.ApplicationContext ctx,
      final String username,
      final String password,
      final MockHttpServletResponse response)
      throws Exception {
    final var chain = ctx.getBean(API_CHAIN_BEAN, SecurityFilterChain.class);
    final var proxy = new FilterChainProxy(List.of(chain));
    final var request = new MockHttpServletRequest("GET", "/api/resource");
    request.addHeader("Authorization", basicHeader(username, password));

    // Defensive precondition: if "/api/**" ever drops out of apiPaths(), FilterChainProxy would
    // silently fall through to nextChain and mask what this test asserts.
    assertThat(chain.matches(request)).isTrue();

    final var next = new MockFilterChain();
    proxy.doFilter(request, response, next);
    return next;
  }

  private static String basicHeader(final String username, final String password) {
    final var token = (username + ":" + password).getBytes(StandardCharsets.UTF_8);
    return "Basic " + Base64.getEncoder().encodeToString(token);
  }

  @Configuration
  static class StubUserDetailsPort {

    @Bean
    BasicAuthUserDetailsPort userDetailsPort() {
      // A mock so each test stubs the resolvable user with a hash from the context encoder.
      return Mockito.mock(BasicAuthUserDetailsPort.class);
    }
  }

  @Configuration
  static class StubPaths {

    @Bean
    SecurityPathPort securityPathPort() {
      return new SecurityPathPort() {
        @Override
        public Set<String> apiPaths() {
          return Set.of("/api/**");
        }

        @Override
        public Set<String> unprotectedApiPaths() {
          return Set.of();
        }

        @Override
        public Set<String> unprotectedPaths() {
          return Set.of("/error");
        }

        @Override
        public Set<String> webappPaths() {
          return Set.of();
        }

        @Override
        public Set<String> webComponentNames() {
          return Set.of();
        }
      };
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
