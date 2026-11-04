/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static io.camunda.security.spring.scope.OidcScopeRuntimeTest.logIn;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;

import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.AuthenticationMethod;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.api.model.scope.ScopeReloadOutcome;
import io.camunda.security.core.port.in.PrimaryCredentialsReloadPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.oidc.LazyClientRegistrationRepository;
import io.camunda.security.spring.oidc.OidcBeansConfiguration;
import io.camunda.security.spring.oidc.OidcWebappClientBeansConfiguration;
import io.camunda.security.spring.oidc.ScopedOidcInfrastructureConfiguration;
import io.camunda.security.spring.scope.MockIdentityProvider.TokenRequest;
import io.camunda.security.spring.scope.ScopedSecurityChainConfigurationTest.ObjectMapperConfig;
import io.camunda.security.spring.security.BaseSecurityConfiguration;
import io.camunda.security.spring.security.OidcWebappSecurityConfiguration;
import io.camunda.security.spring.security.ScopedWebappSecurityChainBuilderConfiguration;
import java.lang.ref.WeakReference;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * The OIDC client secret of the primary (unscoped) webapp chain rotated at runtime, against a real
 * (loopback) OpenID provider.
 */
class PrimaryCredentialRotationTest {

  private static final Logger LOG = LoggerFactory.getLogger(PrimaryCredentialRotationTest.class);

  private MockIdentityProvider idp;

  @BeforeEach
  void startIdp() throws Exception {
    idp = MockIdentityProvider.start();
    idp.acceptSecrets("app", "s1");
  }

  @AfterEach
  void stopIdp() {
    idp.close();
  }

  @Test
  void shouldKeepTheSessionAndRefreshItsTokenWithTheRotatedSecret() throws Exception {
    // given
    idp.setAccessTokenLifetimeSeconds(1);
    runner()
        .run(
            ctx -> {
              final var browser = new TestBrowser(proxy(ctx));
              logIn(browser, idp, "", "oidc", "app");
              idp.acceptSecrets("app", "s1", "s2");

              // when
              final var result = port(ctx).rotateCredentials(primary("s2"));
              idp.acceptSecrets("app", "s2");

              // then
              assertThat(result.outcome()).isEqualTo(ScopeReloadOutcome.CREDENTIALS_ROTATED);
              await()
                  .atMost(Duration.ofSeconds(10))
                  .pollInterval(Duration.ofMillis(250))
                  .untilAsserted(
                      () -> {
                        assertThat(browser.get("/app/home").status()).isEqualTo(200);
                        assertThat(idp.tokenRequests())
                            .contains(new TokenRequest("refresh_token", "app", "secret:s2", true));
                      });
              logIn(new TestBrowser(proxy(ctx)), idp, "", "oidc", "app");
              assertThat(idp.tokenRequests())
                  .contains(new TokenRequest("authorization_code", "app", "secret:s2", true))
                  .noneMatch(request -> !request.granted() && !isCheck(request));
            });
  }

  @Test
  void shouldKeepThePreviousSecretWhenTheIdentityProviderRejectsTheNewOne() throws Exception {
    runner()
        .run(
            ctx -> {
              // when
              final var result = port(ctx).rotateCredentials(primary("wrong"));

              // then
              assertThat(result.outcome()).isEqualTo(ScopeReloadOutcome.KEPT_PREVIOUS);
              assertThat(result.failureCause())
                  .hasValueSatisfying(
                      failure ->
                          assertThat(failure.getMessage())
                              .contains("rejects", "HTTP 401")
                              .doesNotContain("wrong"));
              logIn(new TestBrowser(proxy(ctx)), idp, "", "oidc", "app");
              assertThat(idp.tokenRequests())
                  .contains(new TokenRequest("authorization_code", "app", "secret:s1", true));
            });
  }

  @Test
  void shouldKeepThePreviousSecretWhenTheIdentityProviderCannotBeAsked() throws Exception {
    runner()
        .run(
            ctx -> {
              // given
              registrations(ctx).findByRegistrationId("oidc");
              idp.acceptSecrets("app", "s1", "s2");
              idp.setAvailable(false);

              // when
              final var result = port(ctx).rotateCredentials(primary("s2"));

              // then
              assertThat(result.outcome()).isEqualTo(ScopeReloadOutcome.KEPT_PREVIOUS);
              idp.setAvailable(true);
              logIn(new TestBrowser(proxy(ctx)), idp, "", "oidc", "app");
              assertThat(idp.tokenRequests())
                  .contains(new TokenRequest("authorization_code", "app", "secret:s1", true));
            });
  }

  @Test
  void shouldRejectAChangeOfMoreThanTheCredentials() throws Exception {
    runner()
        .run(
            ctx -> {
              // given
              final var other = primary("s1");
              other.getOidc().setClientId("other-app");

              // when / then
              assertThatThrownBy(() -> port(ctx).rotateCredentials(other))
                  .isInstanceOf(IllegalArgumentException.class);
              assertThat(port(ctx).rotateCredentials(primary("s1")).outcome())
                  .isEqualTo(ScopeReloadOutcome.UNCHANGED);
            });
  }

  @Test
  void shouldReleaseTheRegistrationsOfEarlierRotations() throws Exception {
    runner()
        .run(
            ctx -> {
              // given
              final var browser = new TestBrowser(proxy(ctx));
              logIn(browser, idp, "", "oidc", "app");
              final List<WeakReference<Object>> earlier = new ArrayList<>();
              final List<Long> millis = new ArrayList<>();
              final var rotations = 50;

              // when
              for (int i = 2; i <= rotations + 1; i++) {
                earlier.add(new WeakReference<>(registrations(ctx).findByRegistrationId("oidc")));
                idp.acceptSecrets("app", "s" + (i - 1), "s" + i);
                final var result = port(ctx).rotateCredentials(primary("s" + i));
                assertThat(result.outcome()).isEqualTo(ScopeReloadOutcome.CREDENTIALS_ROTATED);
                millis.add(result.duration().toMillis());
                idp.acceptSecrets("app", "s" + i);
                assertThat(browser.get("/app/home").status()).isEqualTo(200);
              }

              // then
              assertThat(registrations(ctx).resolvedRegistrations()).hasSize(1);
              millis.sort(Long::compare);
              LOG.info(
                  "Primary credential rotation over {} rotations: p50 {} ms, max {} ms",
                  rotations,
                  millis.get(millis.size() / 2),
                  millis.getLast());
              ScopeRuntimeTestSupport.assertCollected(earlier.subList(1, earlier.size()));
            });
  }

  private static boolean isCheck(final TokenRequest request) {
    return "refresh_token".equals(request.grantType()) && !request.granted();
  }

  private AuthenticationConfiguration primary(final String secret) {
    final var authentication = new AuthenticationConfiguration();
    authentication.setMethod(AuthenticationMethod.OIDC);
    authentication.setOidc(
        OidcConfiguration.builder()
            .issuerUri(idp.issuer())
            .clientId("app")
            .clientSecret(secret)
            .redirectUri("http://localhost/sso-callback")
            .build());
    return authentication;
  }

  private WebApplicationContextRunner runner() {
    return new WebApplicationContextRunner()
        .withUserConfiguration(ObjectMapperConfig.class, OidcScopeRuntimeTest.Paths.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                BaseSecurityConfiguration.class,
                OidcWebappSecurityConfiguration.class,
                ScopedWebappSecurityChainBuilderConfiguration.class,
                AuthFailureHandlerConfiguration.class,
                OidcBeansConfiguration.class,
                OidcWebappClientBeansConfiguration.class,
                ScopedOidcInfrastructureConfiguration.class,
                PrimaryCredentialsReloadConfiguration.class))
        .withPropertyValues(
            "camunda.security.authentication.method=oidc",
            "camunda.security.authentication.oidc.client-id=app",
            "camunda.security.authentication.oidc.client-secret=s1",
            "camunda.security.authentication.oidc.redirect-uri=http://localhost/sso-callback",
            "camunda.security.authentication.oidc.issuer-uri=" + idp.issuer());
  }

  private static PrimaryCredentialsReloadPort port(final ApplicationContext ctx) {
    return ctx.getBean(PrimaryCredentialsReloadPort.class);
  }

  private static LazyClientRegistrationRepository registrations(final ApplicationContext ctx) {
    return (LazyClientRegistrationRepository) ctx.getBean(ClientRegistrationRepository.class);
  }

  private static FilterChainProxy proxy(final ApplicationContext ctx) {
    return new FilterChainProxy(
        List.of(ctx.getBean("oidcWebappSecurityFilterChain", SecurityFilterChain.class)));
  }
}
