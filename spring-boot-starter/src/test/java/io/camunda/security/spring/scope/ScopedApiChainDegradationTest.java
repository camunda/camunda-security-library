/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.camunda.security.api.context.CamundaSecurityScopeProvider;
import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.AuthenticationMethod;
import io.camunda.security.api.model.config.ScopedSecurityDescriptor;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.oidc.OidcTestServer;
import io.camunda.security.spring.security.BaseSecurityConfiguration;
import io.camunda.security.spring.security.BasicAuthApiSecurityConfiguration;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import io.camunda.security.spring.user.UserConfiguration;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;

/** One scope's unreachable identity provider must not affect any other scope. */
class ScopedApiChainDegradationTest {

  private static final String BASE_A = "/physical-tenants/a";
  private static final String BASE_B = "/physical-tenants/b";
  private static final String API_PATH_A = BASE_A + "/api/authentication/me";
  private static final String API_PATH_B = BASE_B + "/api/authentication/me";
  // StubSecurityPaths defaults webappPaths to /operate/**, /login, /logout
  private static final String WEBAPP_PATH_B = BASE_B + "/operate/dashboard";

  private static OidcTestServer serverA;
  private static OidcTestServer serverB;

  @BeforeAll
  static void startOidcServers() throws Exception {
    serverA = OidcTestServer.startRsa("key-degraded-a");
    serverB = OidcTestServer.startRsa("key-degraded-b");
  }

  @AfterAll
  static void stopOidcServers() {
    if (serverA != null) {
      serverA.stop();
    }
    if (serverB != null) {
      serverB.stop();
    }
  }

  /**
   * Well past the retry budget, so scope B degrades no matter how many attempts discovery makes.
   */
  @BeforeEach
  void makeScopeBsIdpUnreachable() {
    serverB.failNextDiscoveryRequests(50);
  }

  @Test
  void anUnreachableIdpDegradesOnlyItsOwnScope() throws Exception {
    runner()
        .run(
            ctx -> {
              assertThat(ctx)
                  .as("one scope's unreachable IdP must not abort startup")
                  .hasNotFailed();

              // the healthy scope authenticates as usual
              final var accepted = send(apiChain(ctx, "a"), API_PATH_A, bearerFrom(serverA));
              assertThat(accepted.downstreamRequest)
                  .as("scope A must still serve a valid token")
                  .isNotNull();
              assertThat(accepted.status).isEqualTo(200);

              // the degraded scope keeps its own paths and refuses everything on them
              final var chainB = apiChain(ctx, "b");
              assertThat(chainB.matches(new MockHttpServletRequest("GET", API_PATH_B)))
                  .as("a degraded scope must keep claiming its paths")
                  .isTrue();
              final var refused = send(chainB, API_PATH_B, bearerFrom(serverB));
              assertThat(refused.downstreamRequest).isNull();
              assertThat(refused.status).isEqualTo(503);

              assertThat(serverB.discoveryRequestCount())
                  .as("the retry budget must have been spent before degrading")
                  .isGreaterThanOrEqualTo(2);
            });
  }

  @Test
  void aDegradedScopeRefusesAValidTokenFromAnotherScope() throws Exception {
    runner()
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();

              // a genuinely valid token — for scope A's issuer, presented to degraded scope B
              final var refused = send(apiChain(ctx, "b"), API_PATH_B, bearerFrom(serverA));

              assertThat(refused.downstreamRequest)
                  .as("a degraded scope has no decoder at all, so no token can pass")
                  .isNull();
              assertThat(refused.status).isEqualTo(503);
            });
  }

  @Test
  void anUnreachableIdpAlsoDegradesTheScopesWebappChain() throws Exception {
    runner()
        .run(
            ctx -> {
              // without this the webapp chain still throws and the context dies anyway
              final var webappB = webappChain(ctx, "b");
              assertThat(webappB.matches(new MockHttpServletRequest("GET", WEBAPP_PATH_B)))
                  .as("a degraded scope must keep claiming its webapp paths")
                  .isTrue();

              final var refused = send(webappB, WEBAPP_PATH_B, null);

              assertThat(refused.downstreamRequest).isNull();
              assertThat(refused.status).isEqualTo(503);
            });
  }

  @Test
  void noEarlierChainClaimsADegradedScopesPaths() throws Exception {
    runner()
        .run(
            ctx -> {
              // through every chain in registration order, not just the degraded one: an
              // unprotected-path pattern sorts ahead of the scoped chains and would permit the
              // request instead
              final var allChains =
                  ctx.getBeanProvider(SecurityFilterChain.class).orderedStream().toList();

              final var refused = sendThrough(allChains, API_PATH_B, null);

              assertThat(refused.downstreamRequest)
                  .as("no earlier chain may serve a degraded scope's paths")
                  .isNull();
              assertThat(refused.status).isEqualTo(503);
            });
  }

  @Test
  void degradingLogsTheScopeAndItsIssuer() throws Exception {
    final var logged = attachRegistrarAppender();

    runner()
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();

              final var errors =
                  logged.list.stream()
                      .filter(e -> e.getLevel() == Level.ERROR)
                      .map(ILoggingEvent::getFormattedMessage)
                      .toList();

              // an operator has to be able to tell which scope went dark, and against which issuer
              assertThat(errors)
                  .as("degrading must be reported at ERROR, naming the scope and its issuer")
                  .anyMatch(m -> m.contains(BASE_B) && m.contains(serverB.issuerUri()));
              assertThat(errors)
                  .as("the healthy scope must not be reported as degraded")
                  .noneMatch(m -> m.contains(BASE_A));
            });
  }

  private static ListAppender<ILoggingEvent> attachRegistrarAppender() {
    final var logger = (Logger) LoggerFactory.getLogger(ScopedSecurityChainRegistrar.class);
    final var appender = new ListAppender<ILoggingEvent>();
    appender.start();
    logger.addAppender(appender);
    return appender;
  }

  private WebApplicationContextRunner runner() {
    return new WebApplicationContextRunner()
        .withUserConfiguration(
            ObjectMapperConfig.class,
            StubPaths.class,
            StubUserDetailsPort.class,
            TwoScopeProvider.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                BaseSecurityConfiguration.class,
                BasicAuthApiSecurityConfiguration.class,
                AuthFailureHandlerConfiguration.class,
                UserConfiguration.class,
                ScopedSecurityChainConfiguration.class))
        .withPropertyValues("camunda.security.authentication.method=basic");
  }

  private static String bearerFrom(final OidcTestServer server) throws Exception {
    return "Bearer " + server.sign(server.issuerUri());
  }

  private static Outcome send(
      final SecurityFilterChain chain, final String path, final String authorization)
      throws Exception {
    return sendThrough(List.of(chain), path, authorization);
  }

  private static Outcome sendThrough(
      final List<SecurityFilterChain> chains, final String path, final String authorization)
      throws Exception {
    final var request = new MockHttpServletRequest("GET", path);
    if (authorization != null) {
      request.addHeader("Authorization", authorization);
    }
    final var response = new MockHttpServletResponse();
    final var next = new MockFilterChain();
    new FilterChainProxy(chains).doFilter(request, response, next);
    return new Outcome(next.getRequest(), response.getStatus());
  }

  private static OrderedSecurityFilterChainWrapper apiChain(
      final org.springframework.context.ApplicationContext ctx, final String scopeSuffix) {
    return scopedChain(ctx, "scopedApiSecurityFilterChain-", scopeSuffix);
  }

  private static OrderedSecurityFilterChainWrapper webappChain(
      final org.springframework.context.ApplicationContext ctx, final String scopeSuffix) {
    return scopedChain(ctx, "scopedWebappSecurityFilterChain-", scopeSuffix);
  }

  private static OrderedSecurityFilterChainWrapper scopedChain(
      final org.springframework.context.ApplicationContext ctx,
      final String beanNamePrefix,
      final String scopeSuffix) {
    final var names = ctx.getBeanNamesForType(SecurityFilterChain.class);
    final var name =
        Arrays.stream(names)
            .filter(n -> n.startsWith(beanNamePrefix) && n.endsWith(scopeSuffix))
            .findFirst()
            .orElseThrow(
                () ->
                    new AssertionError(
                        "No "
                            + beanNamePrefix
                            + "*-"
                            + scopeSuffix
                            + " bean found; available chains: "
                            + Arrays.toString(names)));
    return (OrderedSecurityFilterChainWrapper) ctx.getBean(name, SecurityFilterChain.class);
  }

  private record Outcome(Object downstreamRequest, int status) {}

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
      return StubSecurityPaths.builder().apiPaths("/api/**").build();
    }
  }

  @Configuration
  static class StubUserDetailsPort {

    @Bean
    io.camunda.security.core.port.out.BasicAuthUserDetailsPort userDetailsPort() {
      return username -> null;
    }
  }

  @Configuration
  static class TwoScopeProvider {

    @Bean
    CamundaSecurityScopeProvider twoScopedDescriptors() {
      return () ->
          List.of(descriptor(BASE_A, serverA, "client-a"), descriptor(BASE_B, serverB, "client-b"));
    }

    private static ScopedSecurityDescriptor descriptor(
        final String basePath, final OidcTestServer server, final String clientId) {
      final var auth = new AuthenticationConfiguration();
      auth.setMethod(AuthenticationMethod.OIDC);
      auth.setOidc(server.oidcConfiguration(clientId));
      return new ScopedSecurityDescriptor(basePath, auth);
    }
  }
}
