/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.AuthenticationMethod;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.api.model.config.oidc.OidcProvidersConfiguration;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.oidc.OidcBeansConfiguration;
import io.camunda.security.spring.oidc.OidcTestServer;
import io.camunda.security.spring.oidc.OidcWebappClientBeansConfiguration;
import io.camunda.security.spring.oidc.ScopedJwtDecoderFactory;
import io.camunda.security.spring.oidc.ScopedOidcInfrastructureConfiguration;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderInitializationException;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.web.http.SessionRepositoryFilter;

/**
 * Regression coverage for camunda/camunda#61967: an OIDC deployment whose identity provider is
 * unreachable must still start. Discovery used to run while the application context came up, so an
 * identity provider that was down — or merely slower to start than Camunda — aborted the context
 * and left the deployment restart-looping until the provider came back.
 *
 * <p>The requests that need the provider still fail while it is down. What changed is the blast
 * radius: the process stays up, everything not needing that provider keeps working, and recovery
 * needs no restart.
 */
class OidcUnreachableIssuerStartupTest {

  private static final String OIDC_CHAIN_BEAN = "oidcWebappSecurityFilterChain";

  private static final String SCOPE_BASE_PATH = "/physical-tenants/t1";
  private static final String SCOPE_CHAIN_BEAN = "scopedOidcChain";

  /** Nothing listens on port 1, so discovery fails immediately rather than waiting on a timeout. */
  private static final String UNREACHABLE_ISSUER_URI = "http://127.0.0.1:1/realms/camunda";

  private OidcTestServer server;

  @AfterEach
  void stopServer() {
    if (server != null) {
      server.stop();
    }
  }

  @Test
  void shouldStartWhenTheConfiguredIssuerIsUnreachable() {
    runnerFor(UNREACHABLE_ISSUER_URI)
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(ctx).hasSingleBean(JwtDecoder.class);
              assertThat(ctx.getBean(OIDC_CHAIN_BEAN, SecurityFilterChain.class)).isNotNull();
            });
  }

  @Test
  void shouldRejectTokensWhileTheIssuerIsUnreachable() {
    runnerFor(UNREACHABLE_ISSUER_URI)
        .run(
            ctx ->
                // Same outcome as an identity provider that goes down after startup: the token
                // cannot be verified, so the request is rejected.
                assertThatThrownBy(() -> ctx.getBean(JwtDecoder.class).decode("any-token"))
                    .isInstanceOf(JwtDecoderInitializationException.class));
  }

  @Test
  void shouldStillServeTheLoginRedirectWhileTheIssuerIsUnreachable() {
    runnerFor(UNREACHABLE_ISSUER_URI)
        .run(
            ctx -> {
              final var proxy =
                  new FilterChainProxy(
                      List.of(ctx.getBean(OIDC_CHAIN_BEAN, SecurityFilterChain.class)));
              final var response = new MockHttpServletResponse();

              proxy.doFilter(
                  new MockHttpServletRequest("GET", "/login"), response, new MockFilterChain());

              // The login path is derived from configuration, so it does not depend on the
              // provider being reachable — the redirect to the provider is served either way.
              assertThat(response.getStatus()).isEqualTo(302);
              assertThat(response.getRedirectedUrl()).endsWith("/oauth2/authorization/oidc");
            });
  }

  @Test
  void shouldRecoverWithoutARestartOnceTheIssuerAnswers() throws Exception {
    server = OidcTestServer.startRsa("key");
    server.failNextDiscoveryRequests(1);

    runnerFor(server.issuerUri())
        .run(
            ctx -> {
              final var decoder = ctx.getBean(JwtDecoder.class);

              assertThatThrownBy(() -> decoder.decode("any-token"))
                  .isInstanceOf(JwtDecoderInitializationException.class);

              // The failed resolution is not cached: the next request resolves the provider and
              // gets as far as rejecting the token itself, without the process being restarted.
              assertThatThrownBy(() -> decoder.decode("any-token"))
                  .isInstanceOf(BadJwtException.class);
            });
  }

  @Test
  void shouldStartWhenAScopedChainsIssuerIsUnreachable() {
    // A scoped chain builds its own client registrations, decoder and claims provider while the
    // context comes up, so it has to survive an unreachable issuer on its own.
    scopedRunner()
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(ctx.getBean(SCOPE_CHAIN_BEAN, SecurityFilterChain.class)).isNotNull();
            });
  }

  @Test
  void shouldStillServeTheScopedLoginRedirectWhileTheIssuerIsUnreachable() {
    scopedRunner()
        .run(
            ctx -> {
              final var proxy =
                  new FilterChainProxy(
                      List.of(ctx.getBean(SCOPE_CHAIN_BEAN, SecurityFilterChain.class)));
              final var response = new MockHttpServletResponse();

              proxy.doFilter(
                  new MockHttpServletRequest("GET", SCOPE_BASE_PATH + "/operate/dashboard"),
                  response,
                  new MockFilterChain());

              // The scoped authorization path comes from configuration, so the scope still sends
              // its users to the provider instead of failing the request outright.
              assertThat(response.getStatus()).isEqualTo(302);
              assertThat(response.getRedirectedUrl())
                  .endsWith(SCOPE_BASE_PATH + "/oauth2/authorization/unreachable");
            });
  }

  @Test
  void shouldRejectTokensForTheUnreachableScopeOnlyWhileItsIssuerIsUnreachable() throws Exception {
    server = OidcTestServer.startRsa("key");

    scopedRunner()
        .run(
            ctx -> {
              final var decoders = ctx.getBean(ScopedJwtDecoderFactory.class);
              final var unreachable =
                  decoders.buildIssuerAwareDecoder(
                      scopedAuthentication("unreachable", UNREACHABLE_ISSUER_URI),
                      "basePath=" + SCOPE_BASE_PATH);
              final var healthy =
                  decoders.buildIssuerAwareDecoder(
                      scopedAuthentication("healthy", server.issuerUri()),
                      "basePath=/physical-tenants/t2");

              // One scope's unreachable provider is that scope's problem: the other scope gets as
              // far as rejecting the token itself.
              assertThatThrownBy(() -> unreachable.decode("any-token"))
                  .isInstanceOf(JwtDecoderInitializationException.class);
              assertThatThrownBy(() -> healthy.decode("any-token"))
                  .isInstanceOf(BadJwtException.class);
            });
  }

  @Test
  void shouldRecoverAScopedChainWithoutARestartOnceTheIssuerAnswers() throws Exception {
    server = OidcTestServer.startRsa("key");
    server.failNextDiscoveryRequests(1);

    scopedRunner()
        .run(
            ctx -> {
              final var decoder =
                  ctx.getBean(ScopedJwtDecoderFactory.class)
                      .buildIssuerAwareDecoder(
                          scopedAuthentication("healthy", server.issuerUri()),
                          "basePath=" + SCOPE_BASE_PATH);

              assertThatThrownBy(() -> decoder.decode("any-token"))
                  .isInstanceOf(JwtDecoderInitializationException.class);

              // As for the cluster chain, the failed resolution is not cached.
              assertThatThrownBy(() -> decoder.decode("any-token"))
                  .isInstanceOf(BadJwtException.class);
            });
  }

  private static WebApplicationContextRunner scopedRunner() {
    return new WebApplicationContextRunner()
        .withUserConfiguration(ObjectMapperConfig.class, StubPaths.class, ScopedChainConfig.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                BaseSecurityConfiguration.class,
                AuthFailureHandlerConfiguration.class,
                ScopedOidcInfrastructureConfiguration.class,
                ScopedWebappSecurityChainBuilderConfiguration.class))
        .withPropertyValues("camunda.security.authentication.method=oidc");
  }

  private static AuthenticationConfiguration scopedAuthentication(
      final String registrationId, final String issuerUri) {
    final var authentication = new AuthenticationConfiguration();
    authentication.setMethod(AuthenticationMethod.OIDC);
    final var providers = new OidcProvidersConfiguration();
    final var byId = new LinkedHashMap<String, OidcConfiguration>();
    byId.put(
        registrationId,
        OidcConfiguration.builder()
            .clientId("client-" + registrationId)
            .clientSecret("secret")
            .redirectUri("{baseUrl}" + SCOPE_BASE_PATH + "/sso-callback")
            .issuerUri(issuerUri)
            .build());
    providers.setOidc(byId);
    authentication.setProviders(providers);
    return authentication;
  }

  private static WebApplicationContextRunner runnerFor(final String issuerUri) {
    return new WebApplicationContextRunner()
        .withUserConfiguration(ObjectMapperConfig.class, StubPaths.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                BaseSecurityConfiguration.class,
                OidcWebappSecurityConfiguration.class,
                ScopedWebappSecurityChainBuilderConfiguration.class,
                AuthFailureHandlerConfiguration.class,
                OidcBeansConfiguration.class,
                OidcWebappClientBeansConfiguration.class,
                ScopedOidcInfrastructureConfiguration.class))
        .withPropertyValues(
            "camunda.security.authentication.method=oidc",
            "camunda.security.authentication.oidc.client-id=test-client",
            "camunda.security.authentication.oidc.client-secret=secret",
            "camunda.security.authentication.oidc.redirect-uri=http://localhost/sso-callback",
            "camunda.security.authentication.oidc.issuer-uri=" + issuerUri);
  }

  @Configuration
  static class ObjectMapperConfig {

    @Bean
    ObjectMapper objectMapper() {
      return new ObjectMapper();
    }
  }

  @Configuration
  static class ScopedChainConfig {

    @Bean
    JwtDecoder jwtDecoder() {
      return token -> {
        throw new UnsupportedOperationException("stub — the scoped decoders are built per test");
      };
    }

    @Bean(SCOPE_CHAIN_BEAN)
    SecurityFilterChain scopedOidcChain(
        final HttpSecurity http, final ScopedWebappSecurityChainBuilder builder) throws Exception {
      return builder.buildScopedWebappChain(
          http,
          SCOPE_BASE_PATH,
          scopedAuthentication("unreachable", UNREACHABLE_ISSUER_URI),
          new SessionRepositoryFilter<>(new MapSessionRepository(new ConcurrentHashMap<>())),
          "camunda-session-physical-tenants-t1",
          "X-CSRF-TOKEN-physical-tenants-t1");
    }
  }

  @Configuration
  static class StubPaths {

    @Bean
    SecurityPathPort securityPathPort() {
      return StubSecurityPaths.builder().build();
    }
  }
}
