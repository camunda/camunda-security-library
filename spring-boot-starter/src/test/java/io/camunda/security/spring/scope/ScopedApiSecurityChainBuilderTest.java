/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
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
import io.camunda.security.spring.cors.CorsBeansConfiguration;
import io.camunda.security.spring.handler.AuthFailureHandler;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.security.BaseSecurityConfiguration;
import io.camunda.security.spring.security.HttpsRedirectCustomizer;
import io.camunda.security.spring.security.OidcResourceServerCustomizer;
import io.camunda.security.spring.security.SecurityHeadersCustomizer;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import io.camunda.security.spring.user.UserConfiguration;
import jakarta.servlet.FilterChain;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.web.http.SessionRepositoryFilter;
import org.springframework.web.cors.CorsConfigurationSource;

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
                  CorsBeansConfiguration.class,
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
                  CorsBeansConfiguration.class,
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
  // CSP / security-headers customizer hooks (camunda-security-library#538, #539)
  // -------------------------------------------------------------------------

  @Test
  void buildOidcApiChainAppliesRegisteredSecurityHeadersCustomizer() {
    final var stubJwt =
        Jwt.withTokenValue("stub-token")
            .header("alg", "none")
            .claim("sub", "user1")
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(300))
            .build();
    final JwtDecoder stubDecoder = mock(JwtDecoder.class);
    when(stubDecoder.decode(any())).thenReturn(stubJwt);

    oidcRunner.run(
        ctx -> {
          final var http = ctx.getBean(HttpSecurity.class);
          final var properties = ctx.getBean(CamundaSecurityLibraryProperties.class);
          final var authFailureHandler = ctx.getBean(AuthFailureHandler.class);
          final var pathPort = ctx.getBean(SecurityPathPort.class);

          final SecurityHeadersCustomizer headersCustomizer = mock(SecurityHeadersCustomizer.class);
          final var builder =
              new ScopedApiSecurityChainBuilder(
                  properties,
                  authFailureHandler,
                  pathPort,
                  ctx.getBeanProvider(OidcResourceServerCustomizer.class),
                  ctx.getBean(CorsConfigurationSource.class),
                  ctx.getBeanProvider(HttpsRedirectCustomizer.class),
                  singleBeanProvider(SecurityHeadersCustomizer.class, headersCustomizer));

          final SecurityFilterChain chain;
          try {
            chain = builder.buildOidcApiChain(http, List.of("/api/**"), List.of(), stubDecoder);
          } catch (final Exception e) {
            throw new AssertionError("buildOidcApiChain threw unexpectedly", e);
          }
          assertThat(chain).isNotNull();

          try {
            Mockito.verify(headersCustomizer, Mockito.times(1)).customize(http);
          } catch (final Exception e) {
            throw new AssertionError("customizer verification failed", e);
          }
        });
  }

  private static <T> ObjectProvider<T> singleBeanProvider(final Class<T> type, final T bean) {
    final var factory = new StaticListableBeanFactory();
    factory.addBean("bean", bean);
    return factory.getBeanProvider(type);
  }

  // -------------------------------------------------------------------------
  // Per-chain JwtAuthenticationConverter (camunda-security-library#537)
  // -------------------------------------------------------------------------

  @Test
  void buildOidcApiChainAppliesSuppliedJwtAuthenticationConverter() {
    final var stubJwt =
        Jwt.withTokenValue("stub-token")
            .header("alg", "none")
            .claim("sub", "user1")
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(300))
            .build();
    final JwtDecoder stubDecoder = mock(JwtDecoder.class);
    when(stubDecoder.decode(any())).thenReturn(stubJwt);

    final GrantedAuthority customAuthority =
        new SimpleGrantedAuthority("ROLE_CUSTOM_FROM_CONVERTER");
    final Converter<Jwt, Authentication> customConverter =
        jwt -> new JwtAuthenticationToken(jwt, List.of(customAuthority));

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
                  ctx.getBeanProvider(OidcResourceServerCustomizer.class),
                  ctx.getBean(CorsConfigurationSource.class),
                  ctx.getBeanProvider(HttpsRedirectCustomizer.class),
                  ctx.getBeanProvider(SecurityHeadersCustomizer.class));

          final SecurityFilterChain chain =
              builder.buildOidcApiChain(
                  http, List.of("/api/**"), List.of(), stubDecoder, customConverter, null);
          final var proxy = new FilterChainProxy(List.of(chain));

          final var request = new MockHttpServletRequest("GET", "/api/foo");
          request.addHeader("Authorization", "Bearer stub-token");
          final var response = new MockHttpServletResponse();
          final var captured = new AtomicReference<Authentication>();
          final FilterChain next =
              (req, res) -> captured.set(SecurityContextHolder.getContext().getAuthentication());

          proxy.doFilter(request, response, next);

          assertThat(captured.get())
              .as("terminal authentication must reach the app after the custom converter runs")
              .isNotNull();
          final List<GrantedAuthority> authorities =
              new ArrayList<>(captured.get().getAuthorities());
          assertThat(authorities)
              .as("authorities must reflect the supplied converter, not Spring's default mapping")
              .containsExactly(customAuthority);
        });
  }

  @Test
  void buildOidcApiChainWithoutConverterKeepsDefaultJwtAuthenticationConverterBehavior() {
    final var stubJwt =
        Jwt.withTokenValue("stub-token")
            .header("alg", "none")
            .claim("sub", "user1")
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(300))
            .build();
    final JwtDecoder stubDecoder = mock(JwtDecoder.class);
    when(stubDecoder.decode(any())).thenReturn(stubJwt);

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
                  ctx.getBeanProvider(OidcResourceServerCustomizer.class),
                  ctx.getBean(CorsConfigurationSource.class),
                  ctx.getBeanProvider(HttpsRedirectCustomizer.class),
                  ctx.getBeanProvider(SecurityHeadersCustomizer.class));

          // Existing 4-arg overload — must behave exactly as it did before this change.
          final SecurityFilterChain chain =
              builder.buildOidcApiChain(http, List.of("/api/**"), List.of(), stubDecoder);
          final var proxy = new FilterChainProxy(List.of(chain));

          final var request = new MockHttpServletRequest("GET", "/api/foo");
          request.addHeader("Authorization", "Bearer stub-token");
          final var response = new MockHttpServletResponse();
          final var captured = new AtomicReference<Authentication>();
          final FilterChain next =
              (req, res) -> captured.set(SecurityContextHolder.getContext().getAuthentication());

          proxy.doFilter(request, response, next);

          assertThat(captured.get())
              .as("default Spring Security JWT authentication must still be produced")
              .isInstanceOf(JwtAuthenticationToken.class);
          // The default converter maps the 'scope'/'scp' claim to SCOPE_* authorities; stubJwt has
          // none, so no SCOPE_* authority is present, proving the custom converter from the other
          // tests in this class was not silently applied here — this test only asserts the absence
          // of SCOPE_*/custom authorities.
          final List<String> authorityNames =
              captured.get().getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
          assertThat(authorityNames)
              .as("no SCOPE_* authority must be present since stubJwt has no scope/scp claim")
              .noneMatch(name -> name.startsWith("SCOPE_"));
          assertThat(authorityNames)
              .as(
                  "the custom converter's authority must NOT be present — proves it was not"
                      + " silently applied by the decoder-only overload")
              .doesNotContain("ROLE_CUSTOM_FROM_CONVERTER");
        });
  }

  @Test
  void buildOidcApiChainRejectsConverterReturningNonAbstractAuthenticationToken() {
    // The converter parameter's public type is Converter<Jwt, Authentication>, but Spring
    // Security's jwtAuthenticationConverter(...) requires an AbstractAuthenticationToken. A
    // converter that returns some other Authentication implementation must fail the request with
    // 401 (via InvalidBearerTokenException), not throw an uncaught ClassCastException.
    final var stubJwt =
        Jwt.withTokenValue("stub-token")
            .header("alg", "none")
            .claim("sub", "user1")
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(300))
            .build();
    final JwtDecoder stubDecoder = mock(JwtDecoder.class);
    when(stubDecoder.decode(any())).thenReturn(stubJwt);

    // A Mockito mock of Authentication is NOT an AbstractAuthenticationToken (unlike
    // TestingAuthenticationToken, JwtAuthenticationToken, etc., which all extend it) — this is
    // the only reliable way to produce a non-conforming Authentication for this test.
    final Converter<Jwt, Authentication> nonConformingConverter = jwt -> mock(Authentication.class);

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
                  ctx.getBeanProvider(OidcResourceServerCustomizer.class),
                  ctx.getBean(CorsConfigurationSource.class),
                  ctx.getBeanProvider(HttpsRedirectCustomizer.class),
                  ctx.getBeanProvider(SecurityHeadersCustomizer.class));

          final SecurityFilterChain chain =
              builder.buildOidcApiChain(
                  http, List.of("/api/**"), List.of(), stubDecoder, nonConformingConverter, null);
          final var proxy = new FilterChainProxy(List.of(chain));

          final var request = new MockHttpServletRequest("GET", "/api/foo");
          request.addHeader("Authorization", "Bearer stub-token");
          final var response = new MockHttpServletResponse();

          proxy.doFilter(request, response, new MockFilterChain());

          assertThat(response.getStatus())
              .as(
                  "a converter returning a non-AbstractAuthenticationToken must fail as 401, not"
                      + " throw uncaught")
              .isEqualTo(401);
        });
  }

  @Test
  void buildOidcApiChainRejectsConverterReturningNull() {
    // A converter that returns null (a reachable host bug, e.g. an incomplete claim mapping) must
    // hit the "null" branch of the adapter's DEBUG log (the client-facing message is the same for
    // both branches) and still fail as 401, not NPE.
    final var stubJwt =
        Jwt.withTokenValue("stub-token")
            .header("alg", "none")
            .claim("sub", "user1")
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(300))
            .build();
    final JwtDecoder stubDecoder = mock(JwtDecoder.class);
    when(stubDecoder.decode(any())).thenReturn(stubJwt);

    final Converter<Jwt, Authentication> nullReturningConverter = jwt -> null;

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
                  ctx.getBeanProvider(OidcResourceServerCustomizer.class),
                  ctx.getBean(CorsConfigurationSource.class),
                  ctx.getBeanProvider(HttpsRedirectCustomizer.class),
                  ctx.getBeanProvider(SecurityHeadersCustomizer.class));

          final SecurityFilterChain chain =
              builder.buildOidcApiChain(
                  http, List.of("/api/**"), List.of(), stubDecoder, nullReturningConverter, null);
          final var proxy = new FilterChainProxy(List.of(chain));

          final var request = new MockHttpServletRequest("GET", "/api/foo");
          request.addHeader("Authorization", "Bearer stub-token");
          final var response = new MockHttpServletResponse();

          proxy.doFilter(request, response, new MockFilterChain());

          assertThat(response.getStatus())
              .as("a converter returning null must fail as 401, not throw uncaught")
              .isEqualTo(401);
        });
  }

  @Test
  void buildScopedApiChainAppliesSuppliedJwtAuthenticationConverterSupplier() {
    final var stubJwt =
        Jwt.withTokenValue("stub-token")
            .header("alg", "none")
            .claim("sub", "user1")
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(300))
            .build();
    final JwtDecoder stubDecoder = mock(JwtDecoder.class);
    when(stubDecoder.decode(any())).thenReturn(stubJwt);

    final GrantedAuthority customAuthority = new SimpleGrantedAuthority("ROLE_SCOPED_CUSTOM");
    final Converter<Jwt, Authentication> customConverter =
        jwt -> new JwtAuthenticationToken(jwt, List.of(customAuthority));

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
                  ctx.getBeanProvider(OidcResourceServerCustomizer.class),
                  ctx.getBean(CorsConfigurationSource.class),
                  ctx.getBeanProvider(HttpsRedirectCustomizer.class),
                  ctx.getBeanProvider(SecurityHeadersCustomizer.class));
          final var auth = new AuthenticationConfiguration();
          auth.setMethod(AuthenticationMethod.OIDC);

          final SecurityFilterChain chain =
              builder.buildScopedApiChain(
                  http, BASE_PATH, auth, () -> stubDecoder, () -> customConverter, null);
          final var proxy = new FilterChainProxy(List.of(chain));

          final var request = new MockHttpServletRequest("GET", SCOPED_PATH);
          request.addHeader("Authorization", "Bearer stub-token");
          final var response = new MockHttpServletResponse();
          final var captured = new AtomicReference<Authentication>();
          final FilterChain next =
              (req, res) -> captured.set(SecurityContextHolder.getContext().getAuthentication());

          proxy.doFilter(request, response, next);

          assertThat(captured.get())
              .as("scoped chain must reach the app with the custom converter's authentication")
              .isNotNull();
          final List<GrantedAuthority> authorities =
              new ArrayList<>(captured.get().getAuthorities());
          assertThat(authorities)
              .as("authorities must reflect the per-scope supplied converter")
              .containsExactly(customAuthority);
        });
  }

  @Test
  void buildScopedApiChainRejectsNullOidcAuthenticationConverterSupplier() {
    // The requireNonNull on the supplier reference fires before http/matchers are used — mirrors
    // the existing oidcDecoderSupplier null-guard, since both are mandatory references even though
    // the converter supplier is allowed to *return* null (meaning "no override").
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
                  ctx.getBeanProvider(OidcResourceServerCustomizer.class),
                  ctx.getBean(CorsConfigurationSource.class),
                  ctx.getBeanProvider(HttpsRedirectCustomizer.class),
                  ctx.getBeanProvider(SecurityHeadersCustomizer.class));
          final var auth = new AuthenticationConfiguration();
          auth.setMethod(AuthenticationMethod.OIDC);
          assertThatNullPointerException()
              .isThrownBy(
                  () ->
                      builder.buildScopedApiChain(
                          null, BASE_PATH, auth, () -> mock(JwtDecoder.class), null, null))
              .withMessageContaining("oidcAuthenticationConverterSupplier");
        });
  }

  @Test
  void buildScopedApiChainAllowsConverterSupplierToReturnNull() {
    // A converter supplier returning null means "no override" — must NOT throw, unlike the decoder
    // supplier, which requires a non-null JwtDecoder result.
    final var stubJwt =
        Jwt.withTokenValue("stub-token")
            .header("alg", "none")
            .claim("sub", "user1")
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(300))
            .build();
    final JwtDecoder stubDecoder = mock(JwtDecoder.class);
    when(stubDecoder.decode(any())).thenReturn(stubJwt);

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
                  ctx.getBeanProvider(OidcResourceServerCustomizer.class),
                  ctx.getBean(CorsConfigurationSource.class),
                  ctx.getBeanProvider(HttpsRedirectCustomizer.class),
                  ctx.getBeanProvider(SecurityHeadersCustomizer.class));
          final var auth = new AuthenticationConfiguration();
          auth.setMethod(AuthenticationMethod.OIDC);

          final SecurityFilterChain chain;
          try {
            chain =
                builder.buildScopedApiChain(
                    http, BASE_PATH, auth, () -> stubDecoder, () -> null, null);
          } catch (final Exception e) {
            throw new AssertionError(
                "buildScopedApiChain must not throw when the converter supplier returns null", e);
          }
          assertThat(chain).isNotNull();
        });
  }

  // -------------------------------------------------------------------------
  // Per-scope CSRF cookie name
  // -------------------------------------------------------------------------

  @Test
  void buildScopedBasicApiChainUsesPerScopeCsrfCookieName() {
    basicRunner.run(
        ctx -> {
          final var chain = ctx.getBean("scopedBasicChain", SecurityFilterChain.class);
          assertCsrfCookieName(chain, ScopedSecurityChainRegistrar.csrfCookieName(BASE_PATH));
        });
  }

  @Test
  void buildScopedOidcApiChainUsesPerScopeCsrfCookieName() {
    oidcRunner.run(
        ctx -> {
          final var chain = ctx.getBean("scopedOidcChain", SecurityFilterChain.class);
          assertCsrfCookieName(chain, ScopedSecurityChainRegistrar.csrfCookieName(BASE_PATH));
        });
  }

  @Test
  void buildUnprotectedScopedApiChainUsesPerScopeCsrfCookieName() {
    basicRunner.run(
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
                  ctx.getBeanProvider(OidcResourceServerCustomizer.class),
                  ctx.getBean(CorsConfigurationSource.class),
                  ctx.getBeanProvider(HttpsRedirectCustomizer.class),
                  ctx.getBeanProvider(SecurityHeadersCustomizer.class));

          final SecurityFilterChain chain;
          try {
            chain = builder.buildUnprotectedScopedApiChain(http, BASE_PATH);
          } catch (final Exception e) {
            throw new AssertionError("buildUnprotectedScopedApiChain threw unexpectedly", e);
          }
          assertCsrfCookieName(chain, ScopedSecurityChainRegistrar.csrfCookieName(BASE_PATH));
        });
  }

  @Test
  void buildUnprotectedScopedApiChainInstallsSessionRepositoryFilter() {
    basicRunner.run(
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
                  ctx.getBeanProvider(OidcResourceServerCustomizer.class),
                  ctx.getBean(CorsConfigurationSource.class),
                  ctx.getBeanProvider(HttpsRedirectCustomizer.class),
                  ctx.getBeanProvider(SecurityHeadersCustomizer.class));
          final var sessionFilter =
              new SessionRepositoryFilter<>(new MapSessionRepository(new ConcurrentHashMap<>()));

          final SecurityFilterChain chain;
          try {
            chain = builder.buildUnprotectedScopedApiChain(http, BASE_PATH, sessionFilter);
          } catch (final Exception e) {
            throw new AssertionError("buildUnprotectedScopedApiChain threw unexpectedly", e);
          }

          final var filters = chain.getFilters();
          assertThat(filters)
              .as(
                  "the unprotected scoped API chain must install the per-scope session filter, so a"
                      + " scoped session is resolved and CSRF protection engages")
              .contains(sessionFilter);

          final int sessionFilterIndex = filters.indexOf(sessionFilter);
          int contextHolderFilterIndex = -1;
          for (int i = 0; i < filters.size(); i++) {
            if (filters.get(i) instanceof SecurityContextHolderFilter) {
              contextHolderFilterIndex = i;
              break;
            }
          }
          assertThat(contextHolderFilterIndex)
              .as("SecurityContextHolderFilter must be present on the chain")
              .isNotNegative();
          assertThat(sessionFilterIndex)
              .as(
                  "the SessionRepositoryFilter must run before SecurityContextHolderFilter so the"
                      + " session-backed HttpSession is available when the security context is read")
              .isLessThan(contextHolderFilterIndex);
        });
  }

  @Test
  void buildScopedApiChainUsesScopedCookiePath() {
    basicRunner.run(
        ctx -> {
          final var chain = ctx.getBean("scopedBasicChain", SecurityFilterChain.class);
          final var csrfFilter =
              chain.getFilters().stream()
                  .filter(f -> f instanceof CsrfFilter)
                  .map(f -> (CsrfFilter) f)
                  .findFirst()
                  .orElseThrow(() -> new AssertionError("CsrfFilter not found in filter chain"));
          try {
            final var repoField = CsrfFilter.class.getDeclaredField("tokenRepository");
            repoField.setAccessible(true);
            final var repo = (CsrfTokenRepository) repoField.get(csrfFilter);
            assertThat(repo).isNotInstanceOf(CookieCsrfTokenRepository.class);
            final var delegateField = repo.getClass().getDeclaredField("delegate");
            delegateField.setAccessible(true);
            final var delegate = (CookieCsrfTokenRepository) delegateField.get(repo);
            assertThat(delegate.getCookiePath()).isEqualTo(BASE_PATH);
          } catch (final ReflectiveOperationException e) {
            throw new AssertionError("Failed to inspect CSRF token repository path", e);
          }
        });
  }

  private static void assertCsrfCookieName(
      final SecurityFilterChain chain, final String expectedName) {
    final var csrfFilter =
        chain.getFilters().stream()
            .filter(f -> f instanceof CsrfFilter)
            .map(f -> (CsrfFilter) f)
            .findFirst()
            .orElseThrow(() -> new AssertionError("CsrfFilter not found in filter chain"));
    try {
      final var repoField = CsrfFilter.class.getDeclaredField("tokenRepository");
      repoField.setAccessible(true);
      final var repo = (CsrfTokenRepository) repoField.get(csrfFilter);
      // CookieCsrfTokenRepository has no getCookieName(); reflection is the only option.
      // Scoped chains wrap the repo in ContextPathScopedCsrfTokenRepository, so unwrap if needed.
      final CookieCsrfTokenRepository cookieRepo;
      if (repo instanceof CookieCsrfTokenRepository direct) {
        cookieRepo = direct;
      } else {
        final var delegateField = repo.getClass().getDeclaredField("delegate");
        delegateField.setAccessible(true);
        cookieRepo = (CookieCsrfTokenRepository) delegateField.get(repo);
      }
      final var nameField = CookieCsrfTokenRepository.class.getDeclaredField("cookieName");
      nameField.setAccessible(true);
      assertThat(nameField.get(cookieRepo))
          .as("scoped API chain must use per-scope CSRF cookie name")
          .isEqualTo(expectedName);
    } catch (final ReflectiveOperationException e) {
      throw new AssertionError("Failed to inspect CSRF token repository", e);
    }
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
                  ctx.getBeanProvider(OidcResourceServerCustomizer.class),
                  ctx.getBean(CorsConfigurationSource.class),
                  ctx.getBeanProvider(HttpsRedirectCustomizer.class),
                  ctx.getBeanProvider(SecurityHeadersCustomizer.class));
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
                  ctx.getBeanProvider(OidcResourceServerCustomizer.class),
                  ctx.getBean(CorsConfigurationSource.class),
                  ctx.getBeanProvider(HttpsRedirectCustomizer.class),
                  ctx.getBeanProvider(SecurityHeadersCustomizer.class));
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
                  ctx.getBeanProvider(OidcResourceServerCustomizer.class),
                  ctx.getBean(CorsConfigurationSource.class),
                  ctx.getBeanProvider(HttpsRedirectCustomizer.class),
                  ctx.getBeanProvider(SecurityHeadersCustomizer.class));
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
                  ctx.getBeanProvider(OidcResourceServerCustomizer.class),
                  ctx.getBean(CorsConfigurationSource.class),
                  ctx.getBeanProvider(HttpsRedirectCustomizer.class),
                  ctx.getBeanProvider(SecurityHeadersCustomizer.class));
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
                  ctx.getBeanProvider(OidcResourceServerCustomizer.class),
                  ctx.getBean(CorsConfigurationSource.class),
                  ctx.getBeanProvider(HttpsRedirectCustomizer.class),
                  ctx.getBeanProvider(SecurityHeadersCustomizer.class));
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
  void buildScopedApiChainRejectsRootBasePath() {
    // A root "/" basePath normalizes to the empty prefix, which would build an unscoped chain
    // (matchers collapse to the host's raw apiPaths) — a scope must be non-root. All requireNonNull
    // guards are satisfied so the post-normalize root-reject is the one that fires.
    basicRunner.run(
        ctx -> {
          final var http = Mockito.mock(HttpSecurity.class);
          final var properties = ctx.getBean(CamundaSecurityLibraryProperties.class);
          final var authFailureHandler = ctx.getBean(AuthFailureHandler.class);
          final var pathPort = ctx.getBean(SecurityPathPort.class);
          final var builder =
              new ScopedApiSecurityChainBuilder(
                  properties,
                  authFailureHandler,
                  pathPort,
                  ctx.getBeanProvider(OidcResourceServerCustomizer.class),
                  ctx.getBean(CorsConfigurationSource.class),
                  ctx.getBeanProvider(HttpsRedirectCustomizer.class),
                  ctx.getBeanProvider(SecurityHeadersCustomizer.class));
          final var auth = new AuthenticationConfiguration();
          auth.setMethod(AuthenticationMethod.BASIC);
          assertThatIllegalArgumentException()
              .isThrownBy(() -> builder.buildScopedApiChain(http, "/", auth, () -> null))
              .withMessageContaining("must not be the root path");
        });
  }

  @Test
  void buildUnprotectedScopedApiChainRejectsRootBasePath() {
    // Same non-root requirement for the unprotected (permit-all) scoped chain overload.
    basicRunner.run(
        ctx -> {
          final var http = Mockito.mock(HttpSecurity.class);
          final var properties = ctx.getBean(CamundaSecurityLibraryProperties.class);
          final var authFailureHandler = ctx.getBean(AuthFailureHandler.class);
          final var pathPort = ctx.getBean(SecurityPathPort.class);
          final var builder =
              new ScopedApiSecurityChainBuilder(
                  properties,
                  authFailureHandler,
                  pathPort,
                  ctx.getBeanProvider(OidcResourceServerCustomizer.class),
                  ctx.getBean(CorsConfigurationSource.class),
                  ctx.getBeanProvider(HttpsRedirectCustomizer.class),
                  ctx.getBeanProvider(SecurityHeadersCustomizer.class));
          assertThatIllegalArgumentException()
              .isThrownBy(() -> builder.buildUnprotectedScopedApiChain(http, "/"))
              .withMessageContaining("must not be the root path");
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
                  ctx.getBeanProvider(OidcResourceServerCustomizer.class),
                  ctx.getBean(CorsConfigurationSource.class),
                  ctx.getBeanProvider(HttpsRedirectCustomizer.class),
                  ctx.getBeanProvider(SecurityHeadersCustomizer.class));
          final var auth = new AuthenticationConfiguration();
          auth.setMethod(AuthenticationMethod.OIDC);
          assertThatNullPointerException()
              .isThrownBy(() -> builder.buildScopedApiChain(http, BASE_PATH, auth, () -> null))
              .withMessageContaining("null JwtDecoder");
        });
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
                  ctx.getBeanProvider(OidcResourceServerCustomizer.class),
                  ctx.getBean(CorsConfigurationSource.class),
                  ctx.getBeanProvider(HttpsRedirectCustomizer.class),
                  ctx.getBeanProvider(SecurityHeadersCustomizer.class));
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
        final ObjectProvider<OidcResourceServerCustomizer> resourceServerCustomizers,
        final CorsConfigurationSource corsSource,
        final ObjectProvider<HttpsRedirectCustomizer> httpsRedirectCustomizers,
        final ObjectProvider<SecurityHeadersCustomizer> securityHeadersCustomizers)
        throws Exception {
      final var builder =
          new ScopedApiSecurityChainBuilder(
              properties,
              authFailureHandler,
              pathPort,
              resourceServerCustomizers,
              corsSource,
              httpsRedirectCustomizers,
              securityHeadersCustomizers);
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
        final ObjectProvider<JwtDecoder> decoderProvider,
        final CorsConfigurationSource corsSource,
        final ObjectProvider<HttpsRedirectCustomizer> httpsRedirectCustomizers,
        final ObjectProvider<SecurityHeadersCustomizer> securityHeadersCustomizers)
        throws Exception {
      final var builder =
          new ScopedApiSecurityChainBuilder(
              properties,
              authFailureHandler,
              pathPort,
              resourceServerCustomizers,
              corsSource,
              httpsRedirectCustomizers,
              securityHeadersCustomizers);
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
