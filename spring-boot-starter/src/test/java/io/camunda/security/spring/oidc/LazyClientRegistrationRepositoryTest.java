/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.entry;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

/**
 * Behaviour tests for {@link LazyClientRegistrationRepository} against a local OIDC discovery
 * server, so the discovery calls are real and can be counted and made to fail.
 */
final class LazyClientRegistrationRepositoryTest {

  private OidcTestServer server;

  @AfterEach
  void stopServer() {
    if (server != null) {
      server.stop();
    }
  }

  @Test
  void shouldNotResolveAnyRegistrationWhenConstructed() throws Exception {
    // given
    server = OidcTestServer.startRsa("key");

    // when
    newRepository(Map.of("oidc", server.oidcConfiguration("client")));

    // then
    assertThat(server.discoveryRequestCount()).isZero();
  }

  @Test
  void shouldResolveOnFirstLookupAndReuseTheResult() throws Exception {
    // given
    server = OidcTestServer.startRsa("key");
    final var repository = newRepository(Map.of("oidc", server.oidcConfiguration("client")));

    // when
    final var first = repository.findByRegistrationId("oidc");
    final var second = repository.findByRegistrationId("oidc");

    // then
    assertThat(first).isSameAs(second);
    assertThat(first.getClientId()).isEqualTo("client");
    assertThat(server.discoveryRequestCount()).isOne();
  }

  @Test
  void shouldRetryAfterAFailedResolutionAndRecoverWithoutARestart() throws Exception {
    // given
    server = OidcTestServer.startRsa("key");
    final var repository = newRepository(Map.of("oidc", server.oidcConfiguration("client")));
    server.failNextDiscoveryRequests(1);

    // when
    assertThatThrownBy(() -> repository.findByRegistrationId("oidc"))
        .isInstanceOf(RuntimeException.class);

    // then the failure is not cached, so the next lookup succeeds once the issuer answers again
    assertThat(repository.findByRegistrationId("oidc")).isNotNull();
  }

  @Test
  void shouldKeepOneUnreachableIssuerFromAffectingAnother() throws Exception {
    // given a provider on a healthy issuer and one on an issuer that is not listening at all
    server = OidcTestServer.startRsa("key");
    final var providers = new LinkedHashMap<String, OidcConfiguration>();
    providers.put("healthy", server.oidcConfiguration("healthy-client"));
    providers.put(
        "unreachable",
        OidcConfiguration.builder()
            .clientId("unreachable-client")
            .redirectUri("{baseUrl}/sso-callback")
            .issuerUri("http://127.0.0.1:1/realms/unreachable")
            .build());
    final var repository = newRepository(providers);

    // when / then the healthy provider is unaffected by the unreachable one
    assertThat(repository.findByRegistrationId("healthy")).isNotNull();
    assertThatThrownBy(() -> repository.findByRegistrationId("unreachable"))
        .isInstanceOf(RuntimeException.class);
    assertThat(repository.findByRegistrationId("healthy")).isNotNull();
  }

  @Test
  void shouldReturnNullForAnUnconfiguredRegistrationId() throws Exception {
    // given
    server = OidcTestServer.startRsa("key");
    final var repository = newRepository(Map.of("oidc", server.oidcConfiguration("client")));

    // when / then
    assertThat(repository.findByRegistrationId("other")).isNull();
    assertThat(server.discoveryRequestCount()).isZero();
  }

  @Test
  void shouldAnswerIdsAndDisplayNamesFromConfigurationAlone() throws Exception {
    // given
    server = OidcTestServer.startRsa("key");
    final var named = server.oidcConfiguration("named-client");
    named.setClientName("Corporate IdP");
    final var providers = new LinkedHashMap<String, OidcConfiguration>();
    providers.put("named", named);
    providers.put("unnamed", server.oidcConfiguration("unnamed-client"));
    final var repository = newRepository(providers);

    // when / then the login picker and the entry point can be built without any discovery call
    assertThat(repository.registrationIds()).containsExactly("named", "unnamed");
    assertThat(repository.clientNamesByRegistrationId())
        .containsExactly(entry("named", "Corporate IdP"), entry("unnamed", server.issuerUri()));
    assertThat(server.discoveryRequestCount()).isZero();
  }

  @Test
  void shouldUseTheDisplayNameAResolvedRegistrationWouldCarry() throws Exception {
    // given a discovery-backed provider and an explicit-endpoint one, neither with a client-name
    server = OidcTestServer.startRsa("key");
    final var providers = new LinkedHashMap<String, OidcConfiguration>();
    providers.put("discovered", server.oidcConfiguration("discovered-client"));
    providers.put(
        "explicit",
        OidcConfiguration.builder()
            .clientId("explicit-client")
            .redirectUri("{baseUrl}/sso-callback")
            .authorizationUri(server.issuerUri() + "/auth")
            .tokenUri(server.issuerUri() + "/token")
            .jwkSetUri(server.jwksUri())
            .build());
    final var repository = newRepository(providers);

    // when / then
    final var namesFromConfiguration = repository.clientNamesByRegistrationId();
    assertThat(namesFromConfiguration)
        .containsExactly(entry("discovered", server.issuerUri()), entry("explicit", "explicit"));
    assertThat(namesFromConfiguration)
        .allSatisfy(
            (id, name) ->
                assertThat(name).isEqualTo(repository.findByRegistrationId(id).getClientName()));
  }

  @Test
  void shouldRejectAnIncompleteProviderWhenConstructed() {
    // given a provider with neither an issuer-uri nor a complete set of explicit endpoints
    final var incomplete =
        Map.of(
            "oidc",
            OidcConfiguration.builder()
                .clientId("client")
                .redirectUri("{baseUrl}/sso-callback")
                .authorizationUri("https://idp.example.com/auth")
                .build());

    // when / then a configuration error needs no network access, so it still fails here
    assertThatThrownBy(() -> newRepository(incomplete))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("issuer-uri");
  }

  @Test
  void shouldRejectAProviderWithoutAClientIdWhenConstructed() {
    // given a provider whose client-id is missing — ClientRegistration.Builder#build rejects it
    final var withoutClientId =
        Map.of(
            "oidc",
            OidcConfiguration.builder()
                .redirectUri("{baseUrl}/sso-callback")
                .issuerUri("https://idp.example.com/realms/camunda")
                .build());

    // when / then no network access is needed to see it, so it still fails here
    assertThatThrownBy(() -> newRepository(withoutClientId))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("client-id");
  }

  @Test
  void shouldResolveEveryRegistrationWhenIterated() throws Exception {
    // given
    server = OidcTestServer.startRsa("key");
    final var providers = new LinkedHashMap<String, OidcConfiguration>();
    providers.put("first", server.oidcConfiguration("first-client"));
    providers.put("second", server.oidcConfiguration("second-client"));
    final var repository = newRepository(providers);

    // when
    final var registrationIds = new LinkedHashMap<String, String>();
    repository.forEach(
        registration ->
            registrationIds.put(registration.getRegistrationId(), registration.getClientId()));

    // then
    assertThat(registrationIds)
        .containsExactly(entry("first", "first-client"), entry("second", "second-client"));
  }

  @Test
  void shouldNameTheScopeAndTheIssuerWhenAScopedRegistrationCannotBeResolved() {
    // given a scoped repository whose provider sits on an issuer that is not listening at all
    final var basePath = "/physical-tenants/" + UUID.randomUUID();
    final var issuerUri = "http://127.0.0.1:1/realms/unreachable";
    final var repository =
        new LazyClientRegistrationRepository(
            new ScopedClientRegistrationFactory(),
            Map.of(
                "oidc",
                OidcConfiguration.builder()
                    .clientId("client")
                    .redirectUri("{baseUrl}/sso-callback")
                    .issuerUri(issuerUri)
                    .build()),
            basePath + "/sso-callback",
            "basePath=" + basePath);
    final var appender = captureResolutionLogs();

    // when
    try {
      assertThatThrownBy(() -> repository.findByRegistrationId("oidc"))
          .isInstanceOf(RuntimeException.class);
    } finally {
      releaseResolutionLogs(appender);
    }

    // then the WARN tells the operator which identity provider is down and which scope it serves,
    // so two scopes configuring the same provider stay distinguishable
    assertThat(appender.list)
        .filteredOn(event -> event.getLevel() == Level.WARN)
        .singleElement()
        .satisfies(
            event ->
                assertThat(event.getFormattedMessage())
                    .contains("'oidc'")
                    .contains(issuerUri)
                    .contains("basePath=" + basePath));
  }

  private static ListAppender<ILoggingEvent> captureResolutionLogs() {
    final var appender = new ListAppender<ILoggingEvent>();
    appender.start();
    ((Logger) LoggerFactory.getLogger(DeferredOidcResolution.class)).addAppender(appender);
    return appender;
  }

  private static void releaseResolutionLogs(final ListAppender<ILoggingEvent> appender) {
    ((Logger) LoggerFactory.getLogger(DeferredOidcResolution.class)).detachAppender(appender);
    appender.stop();
  }

  private static LazyClientRegistrationRepository newRepository(
      final Map<String, OidcConfiguration> providers) {
    return new LazyClientRegistrationRepository(new ScopedClientRegistrationFactory(), providers);
  }
}
