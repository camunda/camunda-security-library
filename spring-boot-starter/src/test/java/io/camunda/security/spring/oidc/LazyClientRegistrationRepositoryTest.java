/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
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
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

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
  void shouldWarnRatherThanFailOnAnIncompleteProviderWhenConstructed() {
    // given a provider with neither an issuer-uri nor a complete set of explicit endpoints
    final var incomplete =
        Map.of(
            "oidc",
            OidcConfiguration.builder()
                .clientId("client")
                .redirectUri("{baseUrl}/sso-callback")
                .authorizationUri("https://idp.example.com/auth")
                .build());

    // when / then the problem is logged, but does not stop the repository from being built
    assertThatNoException().isThrownBy(() -> newRepository(incomplete));
  }

  @Test
  void shouldWarnRatherThanFailOnAProviderWithoutAClientIdWhenConstructed() {
    // given a provider whose client-id is missing
    final var withoutClientId =
        Map.of(
            "oidc",
            OidcConfiguration.builder()
                .redirectUri("{baseUrl}/sso-callback")
                .issuerUri("https://idp.example.com/realms/camunda")
                .build());

    // when / then the problem is logged, but does not stop the repository from being built
    assertThatNoException().isThrownBy(() -> newRepository(withoutClientId));
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
  void shouldFilterANullRegistrationIdAtConstructionAndSkipItWhenIterated() throws Exception {
    // given a null registrationId key alongside a valid provider — not reachable from
    // configuration (Spring binds an unset/empty registration-id to "", never null), but a host
    // handing CSL a hand-built map can still produce one. The constructor filters it out, so
    // iterating must not let it reach the resolved cache's ConcurrentHashMap#get(null), which
    // throws NullPointerException
    server = OidcTestServer.startRsa("key");
    final var providers = new LinkedHashMap<String, OidcConfiguration>();
    providers.put(null, server.oidcConfiguration("blank-client"));
    providers.put("second", server.oidcConfiguration("second-client"));
    final var repository = newRepository(providers);

    final var registrationIds = new LinkedHashMap<String, String>();
    assertThatNoException()
        .isThrownBy(
            () ->
                repository.forEach(
                    registration ->
                        registrationIds.put(
                            registration.getRegistrationId(), registration.getClientId())));

    assertThat(registrationIds).containsExactly(entry("second", "second-client"));
    assertThat(repository.providers()).containsOnlyKeys("second");
  }

  @Test
  void shouldDescribeEachConfiguredProviderWithoutResolvingIt() {
    // given two providers on issuers that are not listening at all, so any resolution would fail
    final var providers = new LinkedHashMap<String, OidcConfiguration>();
    providers.put("first", unreachableProvider("http://127.0.0.1:1/realms/first"));
    providers.put("second", unreachableProvider("http://127.0.0.1:1/realms/second"));

    // when
    final var descriptions = newRepository(providers).providerDescriptions();

    // then the text a failure log carries is available from the configuration alone
    assertThat(descriptions)
        .isEqualTo(
            "'first' (issuer http://127.0.0.1:1/realms/first), 'second' (issuer"
                + " http://127.0.0.1:1/realms/second)");
  }

  private static OidcConfiguration unreachableProvider(final String issuerUri) {
    return OidcConfiguration.builder()
        .clientId("client")
        .redirectUri("{baseUrl}/sso-callback")
        .issuerUri(issuerUri)
        .build();
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

  @Test
  void shouldAcceptALoginOnlyMisconfigurationWhenBuiltWithoutLoginRoutes() {
    // given a flag that only ever affects the browser login chain, turned on with the call it
    // would make turned off
    final var loginOnlyMisconfiguration = userInfoRequiredWithoutUserInfo();

    // when / then a caller that derives no login route is not concerned by it (ADR-0039)
    assertThatNoException()
        .isThrownBy(
            () ->
                LazyClientRegistrationRepository.withoutLoginRoutes(
                    new ScopedClientRegistrationFactory(),
                    loginOnlyMisconfiguration,
                    "basePath=/physical-tenants/a"));
  }

  @Test
  void shouldRejectALoginOnlyMisconfigurationWhenBuiltWithLoginRoutes() {
    // given the same configuration
    final var loginOnlyMisconfiguration = userInfoRequiredWithoutUserInfo();

    // when / then a caller that does mount a login route still gets the failure
    assertThatThrownBy(() -> newRepository(loginOnlyMisconfiguration))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("user-info-required=true");
  }

  /**
   * ADR-0042: a dropped registration must not stop the start. The validation pass runs before the
   * filter, so a later check that throws would otherwise kill a deployment for a provider CSL has
   * already decided not to use.
   */
  @Test
  void shouldNotStopTheStartForALoginOnlyMisconfigurationOnARejectedRegistration()
      throws Exception {
    // given a rejected registration that also carries a login-only misconfiguration which throws
    server = OidcTestServer.startRsa("key");
    final var rejected = server.oidcConfiguration("public-client");
    rejected.setType("public");
    rejected.setClientSecret("s3cret");
    rejected.setUserInfoRequired(true);
    rejected.setUserInfoEnabled(false);
    final var providers = new LinkedHashMap<String, OidcConfiguration>();
    providers.put("rejected", rejected);
    providers.put("valid", server.oidcConfiguration("confidential-client"));

    // when / then the repository builds, and the valid provider beside it still resolves
    final var repository = newRepository(providers);

    assertThat(repository.providers()).containsOnlyKeys("valid");
    assertThat(repository.findByRegistrationId("valid").getClientId())
        .isEqualTo("confidential-client");
  }

  /** The same misconfiguration on a registration CSL does use still stops the start. */
  @Test
  void shouldStillStopTheStartForALoginOnlyMisconfigurationOnAUsedRegistration() {
    assertThatThrownBy(() -> newRepository(userInfoRequiredWithoutUserInfo()))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("user-info-required=true");
  }

  private static Map<String, OidcConfiguration> userInfoRequiredWithoutUserInfo() {
    final var oidc =
        OidcConfiguration.builder()
            .clientId("client")
            .redirectUri("{baseUrl}/sso-callback")
            .issuerUri("https://idp.example.com/realms/camunda")
            .build();
    oidc.setUserInfoRequired(true);
    oidc.setUserInfoEnabled(false);
    return Map.of("oidc", oidc);
  }

  /**
   * ADR-0042: a provider block whose client type contradicts its other properties is dropped from
   * every reader of the repository, so CSL behaves as if it was never configured — while the
   * application still starts and the valid provider beside it still resolves (ADR-0029).
   */
  @Test
  void shouldDropAContradictoryClientTypeAndKeepAValidProviderBesideIt() throws Exception {
    // given a public registration that also carries a client secret, beside a confidential one
    server = OidcTestServer.startRsa("key");
    final var contradictory = server.oidcConfiguration("public-client");
    contradictory.setType("public");
    contradictory.setClientSecret("s3cret");
    final var providers = new LinkedHashMap<String, OidcConfiguration>();
    providers.put("rejected", contradictory);
    providers.put("valid", server.oidcConfiguration("confidential-client"));

    // when the repository is built — which must not throw
    final LazyClientRegistrationRepository repository = newRepository(providers);

    // then the rejected registration is absent from every reader
    assertThat(repository.registrationIds()).containsExactly("valid");
    assertThat(repository.providers()).containsOnlyKeys("valid");
    assertThat(repository.clientNamesByRegistrationId()).containsOnlyKeys("valid");
    assertThat(repository.findByRegistrationId("rejected")).isNull();

    // and the valid one still resolves
    assertThat(repository.findByRegistrationId("valid").getClientId())
        .isEqualTo("confidential-client");

    // and iterating yields only the valid one
    final var iterated = new LinkedHashMap<String, String>();
    repository.forEach(
        registration -> iterated.put(registration.getRegistrationId(), registration.getClientId()));
    assertThat(iterated).containsExactly(entry("valid", "confidential-client"));
  }

  /**
   * The bearer-only API chain builds its repository through {@code withoutLoginRoutes}, which runs
   * the SKIPPED validation mode. A contradictory client type is dropped there too, so a token of a
   * rejected registration reaches no decoder on that chain either (ADR-0042).
   */
  @Test
  void shouldDropAContradictoryClientTypeOnTheApiChainRepositoryToo() throws Exception {
    // given
    server = OidcTestServer.startRsa("key");
    final var contradictory = server.oidcConfiguration("public-client");
    contradictory.setType("public");
    contradictory.setClientSecret("s3cret");
    final var providers = new LinkedHashMap<String, OidcConfiguration>();
    providers.put("rejected", contradictory);
    providers.put("valid", server.oidcConfiguration("confidential-client"));

    // when
    final var repository =
        LazyClientRegistrationRepository.withoutLoginRoutes(
            new ScopedClientRegistrationFactory(), providers, "basePath=/physical-tenants/a");

    // then
    assertThat(repository.providers()).containsOnlyKeys("valid");
    assertThat(repository.registrationIds()).containsExactly("valid");
    assertThat(repository.findByRegistrationId("rejected")).isNull();
    assertThat(repository.findByRegistrationId("valid").getClientId())
        .isEqualTo("confidential-client");
  }

  /** The WARN belongs to the validation pass, so a lookup never repeats it (ADR-0042). */
  @Test
  void shouldWarnAboutAContradictoryClientTypeOnceAndNotOnEveryLookup() throws Exception {
    // given a repository built over one rejected and one valid provider — the construction warns
    server = OidcTestServer.startRsa("key");
    final var contradictory = server.oidcConfiguration("public-client");
    contradictory.setType("public");
    contradictory.setClientSecret("s3cret");
    final var providers = new LinkedHashMap<String, OidcConfiguration>();
    providers.put("rejected", contradictory);
    providers.put("valid", server.oidcConfiguration("confidential-client"));
    final var repository = newRepository(providers);

    // when the registrations are looked up repeatedly, after construction
    final var appender = captureFactoryLogs();
    try {
      for (int i = 0; i < 3; i++) {
        repository.findByRegistrationId("rejected");
        repository.findByRegistrationId("valid");
      }
    } finally {
      releaseFactoryLogs(appender);
    }

    // then no further warning is logged
    assertThat(appender.list).noneMatch(event -> event.getLevel() == Level.WARN);
  }

  private static ListAppender<ILoggingEvent> captureFactoryLogs() {
    final var appender = new ListAppender<ILoggingEvent>();
    appender.start();
    ((Logger) LoggerFactory.getLogger(ScopedClientRegistrationFactory.class)).addAppender(appender);
    return appender;
  }

  private static void releaseFactoryLogs(final ListAppender<ILoggingEvent> appender) {
    ((Logger) LoggerFactory.getLogger(ScopedClientRegistrationFactory.class))
        .detachAppender(appender);
    appender.stop();
  }

  @Test
  void shouldBuildAPublicRegistrationWithClientAuthenticationMethodNone() throws Exception {
    // given a public registration that leaves client-authentication-method unset
    server = OidcTestServer.startRsa("key");
    final var publicClient = server.oidcConfiguration("public-client");
    publicClient.setType("public");

    // when
    final var registration =
        newRepository(Map.of("oidc", publicClient)).findByRegistrationId("oidc");

    // then the method defaults to none rather than to client_secret_basic
    assertThat(registration.getClientAuthenticationMethod())
        .isEqualTo(ClientAuthenticationMethod.NONE);
  }

  private static LazyClientRegistrationRepository newRepository(
      final Map<String, OidcConfiguration> providers) {
    return new LazyClientRegistrationRepository(new ScopedClientRegistrationFactory(), providers);
  }
}
