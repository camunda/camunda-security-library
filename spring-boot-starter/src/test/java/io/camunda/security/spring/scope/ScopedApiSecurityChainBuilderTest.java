/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.AuthenticationMethod;
import io.camunda.security.core.port.out.BasicAuthUserDetailsPort;
import io.camunda.security.core.port.out.BasicAuthUserDetailsPort.CamundaUserDetails;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.handler.AuthFailureHandler;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.security.BaseSecurityConfiguration;
import io.camunda.security.spring.security.OidcResourceServerCustomizer;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import io.camunda.security.spring.user.UserConfiguration;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Verifies that {@link ScopedApiSecurityChainBuilder} produces correctly-scoped filter chains for
 * both BASIC and OIDC authentication methods, including matcher scoping and access control.
 */
class ScopedApiSecurityChainBuilderTest {

  private static final String BASE_PATH = "/example-scope/s1";
  // StubPaths.apiPaths() returns {"/api/**"}, so the scoped matcher is BASE_PATH + "/api/**"
  private static final String SCOPED_PATH = BASE_PATH + "/api/foo";
  // StubPaths.unprotectedApiPaths() returns {"/api/public"}, so this is permit-all under scope
  private static final String SCOPED_UNPROTECTED_PATH = BASE_PATH + "/api/public";
  // A /v2 path under the scope — must NOT match because the host declared /api/**, not /v2/**
  private static final String SCOPED_V2_PATH = BASE_PATH + "/v2/foo";
  private static final String OUT_OF_SCOPE_PATH = "/api/foo";
  private static final String UNRELATED_PATH = BASE_PATH + "/other";

  private final WebApplicationContextRunner basicRunner =
      new WebApplicationContextRunner()
          .withUserConfiguration(
              ObjectMapperConfig.class, StubPaths.class, StubUserDetailsPort.class)
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class,
                  BaseSecurityConfiguration.class,
                  ScopedApiSecurityChainBuilderConfiguration.class,
                  AuthFailureHandlerConfiguration.class,
                  UserConfiguration.class))
          .withUserConfiguration(BasicScopedChainConfig.class)
          .withPropertyValues("camunda.security.authentication.method=basic");

  private final WebApplicationContextRunner oidcRunner =
      new WebApplicationContextRunner()
          .withUserConfiguration(ObjectMapperConfig.class, StubPaths.class)
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class,
                  BaseSecurityConfiguration.class,
                  ScopedApiSecurityChainBuilderConfiguration.class,
                  AuthFailureHandlerConfiguration.class))
          .withUserConfiguration(OidcScopedChainConfig.class)
          .withPropertyValues("camunda.security.authentication.method=oidc");

  // -------------------------------------------------------------------------
  // Basic auth scenarios
  // -------------------------------------------------------------------------

  @Test
  void basicScopedChainRejects401WhenNoCredentials() {
    basicRunner.run(
        ctx -> {
          final var chain = ctx.getBean("scopedBasicChain", SecurityFilterChain.class);
          final var proxy = new FilterChainProxy(List.of(chain));
          final var request = new MockHttpServletRequest("GET", SCOPED_PATH);
          final var response = new MockHttpServletResponse();

          assertThat(chain.matches(request)).as("chain must match scoped path").isTrue();

          proxy.doFilter(request, response, new MockFilterChain());

          assertThat(response.getStatus()).isEqualTo(401);
        });
  }

  @Test
  void basicScopedChainAcceptsValidCredentials() {
    basicRunner.run(
        ctx -> {
          stubResolvableUser(ctx, "alice", "s3cret");

          final var chain = ctx.getBean("scopedBasicChain", SecurityFilterChain.class);
          final var proxy = new FilterChainProxy(List.of(chain));
          final var request = new MockHttpServletRequest("GET", SCOPED_PATH);
          request.addHeader("Authorization", basicHeader("alice", "s3cret"));
          final var response = new MockHttpServletResponse();
          final var next = new MockFilterChain();

          proxy.doFilter(request, response, next);

          // authenticated: chain passed the request downstream
          assertThat(next.getRequest())
              .as("authenticated request must pass through the chain")
              .isNotNull();
          assertThat(response.getStatus()).isEqualTo(200);
        });
  }

  @Test
  void basicScopedChainDoesNotMatchOutOfScopePaths() {
    basicRunner.run(
        ctx -> {
          final var chain = ctx.getBean("scopedBasicChain", SecurityFilterChain.class);

          final var outOfScopeRequest = new MockHttpServletRequest("GET", OUT_OF_SCOPE_PATH);
          assertThat(chain.matches(outOfScopeRequest))
              .as("chain must NOT match path outside scope (/api/foo not under basePath)")
              .isFalse();

          final var unrelatedRequest = new MockHttpServletRequest("GET", UNRELATED_PATH);
          assertThat(chain.matches(unrelatedRequest))
              .as("chain must NOT match unrelated path under basePath")
              .isFalse();

          // Prove that /v2 is NOT hardcoded: even under the scope's basePath, /v2/** is not matched
          // because the host declared apiPaths()={"/api/**"}, not {"/v2/**"}
          final var scopedV2Request = new MockHttpServletRequest("GET", SCOPED_V2_PATH);
          assertThat(chain.matches(scopedV2Request))
              .as("chain must NOT match basePath + /v2/** — API surface is host-defined, not /v2")
              .isFalse();
        });
  }

  @Test
  void basicScopedChainMatchesScopedPath() {
    basicRunner.run(
        ctx -> {
          final var chain = ctx.getBean("scopedBasicChain", SecurityFilterChain.class);

          final var apiRequest = new MockHttpServletRequest("GET", SCOPED_PATH);
          assertThat(chain.matches(apiRequest))
              .as("chain must match basePath + host-declared apiPath (/api/**)")
              .isTrue();
        });
  }

  @Test
  void basicScopedChainPermitsUnprotectedPathWithoutCredentials() {
    // StubPaths.unprotectedApiPaths() = {"/api/public"}, so basePath + "/api/public" is permit-all
    basicRunner.run(
        ctx -> {
          final var chain = ctx.getBean("scopedBasicChain", SecurityFilterChain.class);
          final var proxy = new FilterChainProxy(List.of(chain));
          final var request = new MockHttpServletRequest("GET", SCOPED_UNPROTECTED_PATH);
          final var response = new MockHttpServletResponse();
          final var next = new MockFilterChain();

          proxy.doFilter(request, response, next);

          // No credentials supplied, but the unprotected path is permit-all
          assertThat(next.getRequest())
              .as("unprotected scoped path must pass through without credentials")
              .isNotNull();
          assertThat(response.getStatus()).isEqualTo(200);
        });
  }

  // -------------------------------------------------------------------------
  // OIDC scenarios
  // -------------------------------------------------------------------------

  @Test
  void oidcScopedChainRejects401WhenNoToken() {
    oidcRunner.run(
        ctx -> {
          final var chain = ctx.getBean("scopedOidcChain", SecurityFilterChain.class);
          final var proxy = new FilterChainProxy(List.of(chain));
          final var request = new MockHttpServletRequest("GET", SCOPED_PATH);
          final var response = new MockHttpServletResponse();

          assertThat(chain.matches(request)).as("chain must match scoped path").isTrue();

          proxy.doFilter(request, response, new MockFilterChain());

          assertThat(response.getStatus()).isEqualTo(401);
        });
  }

  @Test
  void oidcScopedChainDoesNotMatchOutOfScopePaths() {
    oidcRunner.run(
        ctx -> {
          final var chain = ctx.getBean("scopedOidcChain", SecurityFilterChain.class);

          final var outOfScopeRequest = new MockHttpServletRequest("GET", OUT_OF_SCOPE_PATH);
          assertThat(chain.matches(outOfScopeRequest))
              .as("OIDC chain must NOT match path outside scope")
              .isFalse();

          final var unrelatedRequest = new MockHttpServletRequest("GET", UNRELATED_PATH);
          assertThat(chain.matches(unrelatedRequest))
              .as("OIDC chain must NOT match unrelated path under basePath")
              .isFalse();

          // Prove that /v2 is NOT hardcoded: even under the scope's basePath, /v2/** is not matched
          // because the host declared apiPaths()={"/api/**"}, not {"/v2/**"}
          final var scopedV2Request = new MockHttpServletRequest("GET", SCOPED_V2_PATH);
          assertThat(chain.matches(scopedV2Request))
              .as(
                  "OIDC chain must NOT match basePath + /v2/** — API surface is host-defined, not /v2")
              .isFalse();
        });
  }

  @Test
  void oidcScopedChainUsesTheDecoderSuppliedByTheSupplier() {
    // Arrange: a stub decoder that accepts a specific bearer token value.
    final var stubJwt =
        Jwt.withTokenValue("stub-token")
            .header("alg", "none")
            .claim("sub", "user1")
            .issuedAt(java.time.Instant.now())
            .expiresAt(java.time.Instant.now().plusSeconds(300))
            .build();
    final JwtDecoder stubDecoder = mock(JwtDecoder.class);
    when(stubDecoder.decode(any())).thenReturn(stubJwt);

    oidcRunner
        .withBean("capturedStubDecoder", JwtDecoder.class, () -> stubDecoder)
        .run(
            ctx -> {
              final var chain = ctx.getBean("scopedOidcChain", SecurityFilterChain.class);
              assertThat(chain).as("OIDC scoped chain must be produced").isNotNull();

              // The supplier is invoked: confirm a request with the token succeeds
              final var proxy = new FilterChainProxy(List.of(chain));
              final var request = new MockHttpServletRequest("GET", SCOPED_PATH);
              request.addHeader("Authorization", "Bearer stub-token");
              final var response = new MockHttpServletResponse();
              final var next = new MockFilterChain();

              proxy.doFilter(request, response, next);

              // Decoder accepted the token → request passed downstream
              assertThat(next.getRequest())
                  .as("authenticated OIDC request must pass through the chain")
                  .isNotNull();
            });
  }

  // -------------------------------------------------------------------------
  // Null-guard tests for buildScopedApiChain
  // -------------------------------------------------------------------------

  @Test
  void buildScopedApiChainRejectsNullAuthentication() {
    // The requireNonNull on authentication fires before http is used, so http can be null.
    basicRunner.run(
        ctx -> {
          final var properties = ctx.getBean(CamundaSecurityLibraryProperties.class);
          final var authFailureHandler = ctx.getBean(AuthFailureHandler.class);
          final var pathPort = ctx.getBean(SecurityPathPort.class);
          final var builder =
              new ScopedApiSecurityChainBuilder(
                  properties,
                  authFailureHandler,
                  pathPort,
                  ctx.getBeanProvider(OidcResourceServerCustomizer.class));
          assertThatNullPointerException()
              .isThrownBy(() -> builder.buildScopedApiChain(null, BASE_PATH, null, () -> null))
              .withMessageContaining("authentication");
        });
  }

  @Test
  void buildScopedApiChainRejectsNullMethod() {
    // The requireNonNull on authentication.method fires before http is used, so http can be null.
    basicRunner.run(
        ctx -> {
          final var properties = ctx.getBean(CamundaSecurityLibraryProperties.class);
          final var authFailureHandler = ctx.getBean(AuthFailureHandler.class);
          final var pathPort = ctx.getBean(SecurityPathPort.class);
          final var builder =
              new ScopedApiSecurityChainBuilder(
                  properties,
                  authFailureHandler,
                  pathPort,
                  ctx.getBeanProvider(OidcResourceServerCustomizer.class));
          final var authWithNullMethod = new AuthenticationConfiguration();
          authWithNullMethod.setMethod(null);
          assertThatNullPointerException()
              .isThrownBy(
                  () ->
                      builder.buildScopedApiChain(null, BASE_PATH, authWithNullMethod, () -> null))
              .withMessageContaining("method");
        });
  }

  @Test
  void buildScopedApiChainRejectsNullBasePath() {
    // The requireNonNull on basePath fires before http is used, so http can be null.
    basicRunner.run(
        ctx -> {
          final var properties = ctx.getBean(CamundaSecurityLibraryProperties.class);
          final var authFailureHandler = ctx.getBean(AuthFailureHandler.class);
          final var pathPort = ctx.getBean(SecurityPathPort.class);
          final var builder =
              new ScopedApiSecurityChainBuilder(
                  properties,
                  authFailureHandler,
                  pathPort,
                  ctx.getBeanProvider(OidcResourceServerCustomizer.class));
          final var auth = new AuthenticationConfiguration();
          auth.setMethod(AuthenticationMethod.BASIC);
          assertThatNullPointerException()
              .isThrownBy(() -> builder.buildScopedApiChain(null, null, auth, () -> null))
              .withMessageContaining("basePath");
        });
  }

  @Test
  void buildScopedApiChainRejectsNullOidcDecoderSupplier() {
    // The requireNonNull on oidcDecoderSupplier fires before http is used.
    basicRunner.run(
        ctx -> {
          final var properties = ctx.getBean(CamundaSecurityLibraryProperties.class);
          final var authFailureHandler = ctx.getBean(AuthFailureHandler.class);
          final var pathPort = ctx.getBean(SecurityPathPort.class);
          final var builder =
              new ScopedApiSecurityChainBuilder(
                  properties,
                  authFailureHandler,
                  pathPort,
                  ctx.getBeanProvider(OidcResourceServerCustomizer.class));
          final var auth = new AuthenticationConfiguration();
          auth.setMethod(AuthenticationMethod.OIDC);
          assertThatNullPointerException()
              .isThrownBy(() -> builder.buildScopedApiChain(null, BASE_PATH, auth, null))
              .withMessageContaining("oidcDecoderSupplier");
        });
  }

  @Test
  void buildScopedApiChainRejectsNullHttp() {
    // All earlier guards (basePath, authentication, method, oidcDecoderSupplier) are satisfied;
    // the http guard fires last among the requireNonNulls.
    oidcRunner.run(
        ctx -> {
          final var properties = ctx.getBean(CamundaSecurityLibraryProperties.class);
          final var authFailureHandler = ctx.getBean(AuthFailureHandler.class);
          final var pathPort = ctx.getBean(SecurityPathPort.class);
          final var builder =
              new ScopedApiSecurityChainBuilder(
                  properties,
                  authFailureHandler,
                  pathPort,
                  ctx.getBeanProvider(OidcResourceServerCustomizer.class));
          final var auth = new AuthenticationConfiguration();
          auth.setMethod(AuthenticationMethod.OIDC);
          assertThatNullPointerException()
              .isThrownBy(
                  () ->
                      builder.buildScopedApiChain(
                          null, BASE_PATH, auth, () -> Mockito.mock(JwtDecoder.class)))
              .withMessageContaining("http");
        });
  }

  @Test
  void buildScopedApiChainRejectsSupplierReturningNullDecoder() {
    // The requireNonNull on the supplier result fires when the OIDC arm is reached.
    oidcRunner.run(
        ctx -> {
          final var http = ctx.getBean(HttpSecurity.class);
          final var properties = ctx.getBean(CamundaSecurityLibraryProperties.class);
          final var authFailureHandler = ctx.getBean(AuthFailureHandler.class);
          final var pathPort = ctx.getBean(SecurityPathPort.class);
          final var builder =
              new ScopedApiSecurityChainBuilder(
                  properties,
                  authFailureHandler,
                  pathPort,
                  ctx.getBeanProvider(OidcResourceServerCustomizer.class));
          final var auth = new AuthenticationConfiguration();
          auth.setMethod(AuthenticationMethod.OIDC);
          assertThatNullPointerException()
              .isThrownBy(() -> builder.buildScopedApiChain(http, BASE_PATH, auth, () -> null))
              .withMessageContaining("null JwtDecoder");
        });
  }

  // -------------------------------------------------------------------------
  // normalizeBasePath unit tests
  // -------------------------------------------------------------------------

  @Test
  void normalizeBasePathStripsTrailingSlash() {
    assertThat(ScopedApiSecurityChainBuilder.normalizeBasePath("/x/")).isEqualTo("/x");
  }

  @Test
  void normalizeBasePathLeavesRootSlashUnchanged() {
    assertThat(ScopedApiSecurityChainBuilder.normalizeBasePath("/")).isEqualTo("/");
  }

  @Test
  void buildOidcApiChainRejectsNullJwtDecoder() {
    oidcRunner.run(
        ctx -> {
          final var http = ctx.getBean(HttpSecurity.class);
          final var properties = ctx.getBean(CamundaSecurityLibraryProperties.class);
          final var authFailureHandler = ctx.getBean(AuthFailureHandler.class);
          final var pathPort = ctx.getBean(SecurityPathPort.class);
          final var builder =
              new ScopedApiSecurityChainBuilder(
                  properties,
                  authFailureHandler,
                  pathPort,
                  ctx.getBeanProvider(OidcResourceServerCustomizer.class));
          assertThatNullPointerException()
              .isThrownBy(
                  () -> builder.buildOidcApiChain(http, List.of("/api/**"), List.of(), null))
              .withMessageContaining("jwtDecoder");
        });
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  private static void stubResolvableUser(
      final org.springframework.context.ApplicationContext ctx,
      final String username,
      final String rawPassword) {
    final var encoder = ctx.getBean(PasswordEncoder.class);
    final var port = ctx.getBean(BasicAuthUserDetailsPort.class);
    Mockito.when(port.loadUser(username))
        .thenReturn(new CamundaUserDetails(username, encoder.encode(rawPassword)));
  }

  private static String basicHeader(final String username, final String password) {
    final var token = (username + ":" + password).getBytes(StandardCharsets.UTF_8);
    return "Basic " + Base64.getEncoder().encodeToString(token);
  }

  // -------------------------------------------------------------------------
  // Inner configuration classes
  // -------------------------------------------------------------------------

  /**
   * Registers a {@link ScopedApiSecurityChainBuilder}-produced Basic chain as a bean so the test
   * context can retrieve it by name.
   */
  @Configuration
  static class BasicScopedChainConfig {

    @Bean
    @Order(1)
    SecurityFilterChain scopedBasicChain(
        final HttpSecurity http,
        final CamundaSecurityLibraryProperties properties,
        final AuthFailureHandler authFailureHandler,
        final SecurityPathPort pathPort,
        final ObjectProvider<OidcResourceServerCustomizer> resourceServerCustomizers)
        throws Exception {
      final var builder =
          new ScopedApiSecurityChainBuilder(
              properties, authFailureHandler, pathPort, resourceServerCustomizers);
      final var authentication = new AuthenticationConfiguration();
      authentication.setMethod(AuthenticationMethod.BASIC);
      return builder.buildScopedApiChain(http, BASE_PATH, authentication, () -> null);
    }
  }

  /**
   * Registers a {@link ScopedApiSecurityChainBuilder}-produced OIDC chain as a bean so the test
   * context can retrieve it by name. The supplier resolves the {@code capturedStubDecoder} bean if
   * present, falling back to a no-op decoder; tests that need a real stub register it via {@code
   * withBean("capturedStubDecoder", ...)}.
   */
  @Configuration
  static class OidcScopedChainConfig {

    @Bean
    @Order(1)
    SecurityFilterChain scopedOidcChain(
        final HttpSecurity http,
        final CamundaSecurityLibraryProperties properties,
        final AuthFailureHandler authFailureHandler,
        final SecurityPathPort pathPort,
        final ObjectProvider<OidcResourceServerCustomizer> resourceServerCustomizers,
        final ObjectProvider<JwtDecoder> decoderProvider)
        throws Exception {
      final var builder =
          new ScopedApiSecurityChainBuilder(
              properties, authFailureHandler, pathPort, resourceServerCustomizers);
      final var authentication = new AuthenticationConfiguration();
      authentication.setMethod(AuthenticationMethod.OIDC);
      // Supplier resolves the stub decoder from context; falls back to a reject-all decoder.
      return builder.buildScopedApiChain(
          http,
          BASE_PATH,
          authentication,
          () -> {
            final var stub = decoderProvider.getIfAvailable();
            if (stub != null) {
              return stub;
            }
            // Reject-all fallback: no token is considered valid.
            return token -> {
              throw new org.springframework.security.oauth2.jwt.JwtException(
                  "no decoder configured");
            };
          });
    }
  }

  @Configuration
  static class StubPaths {

    @Bean
    SecurityPathPort securityPathPort() {
      return StubSecurityPaths.builder()
          .unprotectedApiPaths("/api/public")
          .webappPaths()
          .webComponentNames()
          .build();
    }
  }

  @Configuration
  static class StubUserDetailsPort {

    @Bean
    BasicAuthUserDetailsPort userDetailsPort() {
      return Mockito.mock(BasicAuthUserDetailsPort.class);
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
