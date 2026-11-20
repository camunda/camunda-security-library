/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.handler.LoggingAuthenticationFailureHandler;
import io.camunda.security.spring.oidc.DeferredOidcResolution;
import io.camunda.security.spring.oidc.OidcBeansConfiguration;
import io.camunda.security.spring.oidc.OidcTestServer;
import io.camunda.security.spring.oidc.OidcWebappClientBeansConfiguration;
import io.camunda.security.spring.oidc.ScopedOidcInfrastructureConfiguration;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * A bearer token that arrives while the identity provider is unreachable gets a 503 from the API
 * chain, not an unhandled exception. The next request retries the provider.
 */
class OidcApiUnreachableIssuerTest {

  private static final String API_CHAIN_BEAN = "oidcApiSecurityFilterChain";

  private OidcTestServer server;
  private OidcTestServer otherServer;
  private Logger handlerLogger;
  private Logger resolutionLogger;
  private ListAppender<ILoggingEvent> logs;

  @BeforeEach
  void attachAppender() {
    handlerLogger = (Logger) LoggerFactory.getLogger(LoggingAuthenticationFailureHandler.class);
    resolutionLogger = (Logger) LoggerFactory.getLogger(DeferredOidcResolution.class);
    logs = new ListAppender<>();
    logs.start();
    handlerLogger.addAppender(logs);
    resolutionLogger.addAppender(logs);
  }

  @AfterEach
  void cleanUp() {
    handlerLogger.detachAppender(logs);
    resolutionLogger.detachAppender(logs);
    if (server != null) {
      server.stop();
    }
    if (otherServer != null) {
      otherServer.stop();
    }
  }

  @Test
  void shouldAnswer503WithoutLeakingAnExceptionWhileTheIssuerIsUnreachable() throws Exception {
    // given an issuer that does not answer discovery
    server = OidcTestServer.startRsa("key");
    server.failNextDiscoveryRequests(1);

    runner(server.issuerUri())
        .run(
            ctx -> {
              final var proxy = proxyOf(ctx.getBean(API_CHAIN_BEAN, SecurityFilterChain.class));
              final var response = new MockHttpServletResponse();

              // when a request carries a bearer token
              proxy.doFilter(
                  bearerRequest(server.sign(server.issuerUri())), response, new MockFilterChain());

              // then the chain answers 503 and no exception escapes it
              assertThat(response.getStatus()).isEqualTo(503);
              assertThat(response.getErrorMessage()).isEqualTo("Identity provider is unavailable");
              assertThat(response.getHeader(HttpHeaders.WWW_AUTHENTICATE)).isNull();
            });
  }

  @Test
  void shouldReportTheOutageOnceAtWarnWhileTheIssuerIsUnreachable() throws Exception {
    // given an issuer that does not answer discovery
    server = OidcTestServer.startRsa("key");
    server.failNextDiscoveryRequests(1);

    runner(server.issuerUri())
        .run(
            ctx -> {
              final var proxy = proxyOf(ctx.getBean(API_CHAIN_BEAN, SecurityFilterChain.class));

              // when a request carries a bearer token
              proxy.doFilter(
                  bearerRequest(server.sign(server.issuerUri())),
                  new MockHttpServletResponse(),
                  new MockFilterChain());

              // then the rate-limited resolution log is the one WARN, and the handler adds none
              final var warnings =
                  logs.list.stream().filter(event -> event.getLevel() == Level.WARN).toList();
              assertThat(warnings).hasSize(1);
              assertThat(warnings.get(0).getLoggerName())
                  .isEqualTo(DeferredOidcResolution.class.getName());
            });
  }

  @Test
  void shouldAnswer503WithoutLeakingAnExceptionWhenOneOfSeveralIssuersIsUnreachable()
      throws Exception {
    // given two providers, one of which does not answer discovery
    server = OidcTestServer.startRsa("key");
    otherServer = OidcTestServer.startRsa("other-key");
    server.failNextDiscoveryRequests(1);

    multiProviderRunner(server.issuerUri(), otherServer.issuerUri())
        .run(
            ctx -> {
              final var proxy = proxyOf(ctx.getBean(API_CHAIN_BEAN, SecurityFilterChain.class));
              final var unavailable = new MockHttpServletResponse();

              // when a token of the unreachable provider arrives
              proxy.doFilter(
                  bearerRequest(server.sign(server.issuerUri())),
                  unavailable,
                  new MockFilterChain());

              // then the chain answers 503 and no exception escapes it
              assertThat(unavailable.getStatus()).isEqualTo(503);
              assertThat(unavailable.getErrorMessage())
                  .isEqualTo("Identity provider is unavailable");

              // when the provider answers and the same request arrives again
              final var retried = new MockHttpServletResponse();
              proxy.doFilter(
                  bearerRequest(server.sign(server.issuerUri())), retried, new MockFilterChain());

              // then discovery ran again and the request no longer fails as unavailable
              assertThat(retried.getStatus()).isEqualTo(200);
            });
  }

  @Test
  void shouldRetryDiscoveryOnTheNextRequestOnceTheIssuerAnswers() throws Exception {
    // given a first request that failed because the issuer did not answer
    server = OidcTestServer.startRsa("key");
    server.failNextDiscoveryRequests(1);

    runner(server.issuerUri())
        .run(
            ctx -> {
              final var proxy = proxyOf(ctx.getBean(API_CHAIN_BEAN, SecurityFilterChain.class));
              final var failed = new MockHttpServletResponse();
              proxy.doFilter(
                  bearerRequest(server.sign(server.issuerUri())), failed, new MockFilterChain());
              assertThat(failed.getStatus()).isEqualTo(503);

              // when the issuer answers and the same request arrives again
              final var retried = new MockHttpServletResponse();
              proxy.doFilter(
                  bearerRequest(server.sign(server.issuerUri())), retried, new MockFilterChain());

              // then discovery ran again and the request no longer fails as unavailable
              assertThat(server.discoveryRequestCount()).isGreaterThan(1);
              assertThat(retried.getStatus()).isEqualTo(200);
            });
  }

  private static MockHttpServletRequest bearerRequest(final String token) {
    final var request = new MockHttpServletRequest("GET", "/api/anything");
    request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token);
    return request;
  }

  private static FilterChainProxy proxyOf(final SecurityFilterChain chain) {
    return new FilterChainProxy(List.of(chain));
  }

  private static WebApplicationContextRunner runner(final String issuerUri) {
    return baseRunner()
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=test-client",
            "camunda.security.authentication.oidc.client-secret=secret",
            "camunda.security.authentication.oidc.redirect-uri=http://localhost/sso-callback",
            "camunda.security.authentication.oidc.issuer-uri=" + issuerUri);
  }

  private static WebApplicationContextRunner multiProviderRunner(
      final String firstIssuerUri, final String secondIssuerUri) {
    return baseRunner()
        .withPropertyValues(
            "camunda.security.authentication.providers.oidc.first.client-id=first-client",
            "camunda.security.authentication.providers.oidc.first.client-secret=secret",
            "camunda.security.authentication.providers.oidc.first.redirect-uri=http://localhost/sso-callback",
            "camunda.security.authentication.providers.oidc.first.issuer-uri=" + firstIssuerUri,
            "camunda.security.authentication.providers.oidc.second.client-id=second-client",
            "camunda.security.authentication.providers.oidc.second.client-secret=secret",
            "camunda.security.authentication.providers.oidc.second.redirect-uri=http://localhost/sso-callback",
            "camunda.security.authentication.providers.oidc.second.issuer-uri=" + secondIssuerUri);
  }

  private static WebApplicationContextRunner baseRunner() {
    return new WebApplicationContextRunner()
        .withUserConfiguration(ObjectMapperConfig.class, StubPaths.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                BaseSecurityConfiguration.class,
                OidcApiSecurityConfiguration.class,
                AuthFailureHandlerConfiguration.class,
                OidcBeansConfiguration.class,
                OidcWebappClientBeansConfiguration.class,
                ScopedOidcInfrastructureConfiguration.class))
        .withPropertyValues("camunda.security.authentication.method=oidc");
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
      return StubSecurityPaths.builder().apiPaths("/api/**").build();
    }
  }
}
