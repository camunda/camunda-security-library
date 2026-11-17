/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import io.camunda.security.core.port.in.OidcProviderConfigurationPort;
import io.camunda.security.core.port.out.MembershipPort;
import io.camunda.security.core.port.out.MembershipPort.PrincipalType;
import io.camunda.security.core.port.out.MembershipQuery;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.context.CamundaAuthenticationBeansConfiguration;
import io.camunda.security.spring.converter.OidcTokenAuthenticationConverter;
import io.camunda.security.spring.converter.TokenClaimsConvertersByIssuer;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.security.BaseSecurityConfiguration;
import io.camunda.security.spring.security.OidcApiSecurityConfiguration;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.assertj.AssertableWebApplicationContext;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * The user Bearer token path on the API chain, against a real Keycloak.
 *
 * <p>The tokens are real. One comes from the authorization code flow with PKCE of a public client,
 * which is what c8ctl and Desktop Modeler run. The other comes from the client credentials flow of
 * the hybrid client. Both reach the same API chain, and the chain must tell them apart.
 *
 * <p>Keycloak adds the {@code client_id} claim to a service account token only, through the {@code
 * service_account} client scope. A user token carries {@code azp} with the same value, so {@code
 * client-id-claim} must name {@code client_id} and not {@code azp}. This test is the measurement
 * behind that row of the table in ADR-0048.
 *
 * <p>This test needs Docker. {@code ./mvnw verify} runs it, and {@code ./mvnw verify -DskipITs}
 * leaves it out.
 */
class KeycloakUserBearerTokenIT {

  private static final String API_CHAIN_BEAN = "oidcApiSecurityFilterChain";
  private static final String API_PATH = "/api/process-instances";
  private static final String REDIRECT_URI = "http://localhost/sso-callback";
  private static final String AUDIENCE = "camunda-api";

  @Test
  void aUserTokenOfAPublicClientAuthenticatesAsAUser() throws Exception {
    final var token =
        KeycloakTestServer.authorizationCodeTokenWithPkce(
            KeycloakTestServer.PUBLIC_REALM, "csl-public", null, REDIRECT_URI);

    runner()
        .run(
            ctx -> {
              final var authentication = callApiWith(ctx, token);

              assertThat(authentication.authenticatedUsername()).isNotBlank();
              assertThat(authentication.authenticatedClientId()).isNull();
              assertThat(authentication.authenticatedRoleIds()).containsExactly("operator");
            });
  }

  /**
   * The same user through two registrations. {@code sub} names the person, so the principal does
   * not change with the client the person signed in through, and the memberships of that person
   * hold for both.
   */
  @Test
  void aUserTokenOfAHybridClientResolvesToTheSamePrincipal() throws Exception {
    final var throughPublicClient =
        KeycloakTestServer.authorizationCodeTokenWithPkce(
            KeycloakTestServer.PUBLIC_REALM, "csl-public", null, REDIRECT_URI);
    final var throughHybridClient =
        KeycloakTestServer.authorizationCodeTokenWithPkce(
            KeycloakTestServer.PUBLIC_REALM, "csl-hybrid", "csl-hybrid-secret", REDIRECT_URI);

    runner()
        .run(
            ctx -> {
              final var fromPublic = callApiWith(ctx, throughPublicClient);
              final var fromHybrid = callApiWith(ctx, throughHybridClient);

              assertThat(fromHybrid.authenticatedUsername())
                  .isEqualTo(fromPublic.authenticatedUsername());
              assertThat(fromHybrid.authenticatedClientId()).isNull();
            });
  }

  @Test
  void aClientCredentialsTokenOfTheHybridClientStaysAClient() throws Exception {
    final var token =
        KeycloakTestServer.clientCredentialsToken(
            KeycloakTestServer.PUBLIC_REALM, "csl-hybrid", "csl-hybrid-secret");

    runner()
        .run(
            ctx -> {
              final var authentication = callApiWith(ctx, token);

              assertThat(authentication.authenticatedClientId()).isEqualTo("csl-hybrid");
              assertThat(authentication.authenticatedUsername()).isNull();
            });
  }

  @Test
  void aTokenForAnotherAudienceIsRejected() throws Exception {
    final var token =
        KeycloakTestServer.clientCredentialsToken(
            KeycloakTestServer.PUBLIC_REALM, "csl-other-audience", "csl-other-audience-secret");

    runner().run(ctx -> assertRejectedWithAReason(ctx, token));
  }

  /**
   * The token is a real one of the realm the chain reads keys from, so its signature is valid and
   * its audience is the expected one. Only the issuer the chain expects is another. Nothing but the
   * issuer check can refuse this token, so the test fails if that check goes away.
   */
  @Test
  void aTokenOfAnotherIssuerIsRejected() throws Exception {
    final var token =
        KeycloakTestServer.clientCredentialsToken(
            KeycloakTestServer.PUBLIC_REALM, "csl-hybrid", "csl-hybrid-secret");

    runnerExpectingAnotherIssuer().run(ctx -> assertRejectedWithAReason(ctx, token));
  }

  @Test
  void anExpiredTokenIsRejected() throws Exception {
    final var token =
        KeycloakTestServer.clientCredentialsToken(
            KeycloakTestServer.PUBLIC_REALM, "csl-short-lived", "csl-short-lived-secret");
    // The client issues a token that lives one second. Waiting on the expiry of that token, and
    // not on a fixed delay, keeps the test honest on a slow machine (ADR-0047).
    final var expiry = KeycloakTestServer.expiryOf(token);
    await().atMost(Duration.ofSeconds(30)).until(() -> Instant.now().isAfter(expiry));

    runner()
        .withUserConfiguration(NoClockSkew.class)
        .run(ctx -> assertRejectedWithAReason(ctx, token));
  }

  private static void assertRejectedWithAReason(
      final AssertableWebApplicationContext ctx, final String token) throws Exception {
    assertThat(ctx).hasNotFailed();
    final var proxy =
        new FilterChainProxy(List.of(ctx.getBean(API_CHAIN_BEAN, SecurityFilterChain.class)));
    final var response = new MockHttpServletResponse();

    proxy.doFilter(bearerRequest(token), response, new MockFilterChain());

    assertThat(response.getStatus()).isEqualTo(401);
    assertThat(response.getHeader(HttpHeaders.WWW_AUTHENTICATE))
        .as("the caller must learn why the token failed")
        .contains("error=\"invalid_token\"")
        .contains("error_description=");
  }

  private static CamundaAuthentication callApiWith(
      final AssertableWebApplicationContext ctx, final String token) throws Exception {
    assertThat(ctx).hasNotFailed();
    final var proxy =
        new FilterChainProxy(List.of(ctx.getBean(API_CHAIN_BEAN, SecurityFilterChain.class)));
    final var response = new MockHttpServletResponse();
    final var captured = new AtomicReference<Authentication>();

    proxy.doFilter(
        bearerRequest(token),
        response,
        (request, servletResponse) ->
            captured.set(SecurityContextHolder.getContext().getAuthentication()));

    assertThat(response.getStatus())
        .as("the chain refused the token: %s", response.getHeader(HttpHeaders.WWW_AUTHENTICATE))
        .isEqualTo(200);
    assertThat(captured.get()).as("no authentication reached the security context").isNotNull();
    return new OidcTokenAuthenticationConverter(
            ctx.getBean(LazyTokenClaimsConverter.class),
            new NoopOidcClaimsProvider(),
            ctx.getBean(TokenClaimsConvertersByIssuer.class))
        .convert(captured.get());
  }

  private static MockHttpServletRequest bearerRequest(final String token) {
    final var request = new MockHttpServletRequest("GET", API_PATH);
    request.setServletPath(API_PATH);
    request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token);
    return request;
  }

  private static WebApplicationContextRunner runner() {
    return new WebApplicationContextRunner()
        .withUserConfiguration(ObjectMapperConfig.class, StubPaths.class, StubMemberships.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                BaseSecurityConfiguration.class,
                OidcApiSecurityConfiguration.class,
                AuthFailureHandlerConfiguration.class,
                CamundaAuthenticationBeansConfiguration.class,
                OidcBeansConfiguration.class,
                OidcWebappClientBeansConfiguration.class,
                ScopedOidcInfrastructureConfiguration.class))
        .withPropertyValues(
            "camunda.security.authentication.method=oidc",
            "camunda.security.authentication.oidc.type=hybrid",
            "camunda.security.authentication.oidc.client-id=csl-hybrid",
            "camunda.security.authentication.oidc.client-secret=csl-hybrid-secret",
            "camunda.security.authentication.oidc.issuer-uri="
                + KeycloakTestServer.realmUrl(KeycloakTestServer.PUBLIC_REALM),
            "camunda.security.authentication.oidc.redirect-uri=" + REDIRECT_URI,
            "camunda.security.authentication.oidc.audiences=" + AUDIENCE,
            "camunda.security.authentication.oidc.user-info-enabled=false",
            // The recommended settings for Keycloak. client_id is machine-only, so the user name
            // claim stays on the stable sub, which is also the default of CSL.
            "camunda.security.authentication.oidc.username-claim=sub",
            "camunda.security.authentication.oidc.client-id-claim=client_id",
            "camunda.security.authentication.oidc.prefer-username-claim=false");
  }

  /**
   * The same chain, but it expects the issuer of the second realm while it reads the signing keys
   * of the first. A token of the first realm then has a valid signature and the expected audience,
   * and only its {@code iss} is another one. This isolates the issuer check from the signature
   * check and from the audience check.
   *
   * <p>The expected issuer is a realm that exists, because CSL discovers the configuration of the
   * issuer URI before it uses the explicit JWK Set URI, and a host name that resolves to nothing
   * fails the decoder instead of the token.
   */
  private static WebApplicationContextRunner runnerExpectingAnotherIssuer() {
    return runner()
        .withPropertyValues(
            "camunda.security.authentication.oidc.issuer-uri="
                + KeycloakTestServer.realmUrl(KeycloakTestServer.CONFIDENTIAL_REALM),
            "camunda.security.authentication.oidc.jwk-set-uri="
                + KeycloakTestServer.jwkSetUri(KeycloakTestServer.PUBLIC_REALM));
  }

  /**
   * The validators of the library add a clock skew of one minute, which no property changes today.
   * A token that lives one second would still pass. This override removes the skew, so the test
   * measures the expiry check itself and not the skew.
   */
  @Configuration
  static class NoClockSkew {

    @Bean
    TokenValidatorFactory tokenValidatorFactory(
        final OidcProviderConfigurationPort oidcProviderConfigurationPort) {
      return new TokenValidatorFactory(
          oidcProviderConfigurationPort.getOidcAuthenticationConfigurations(),
          Duration.ZERO,
          List.of());
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
      return StubSecurityPaths.builder().apiPaths("/api/**").build();
    }
  }

  /** Gives the user a role, so the test sees that memberships resolve for a Bearer principal. */
  @Configuration
  static class StubMemberships {

    @Bean
    MembershipPort membershipPort() {
      return new MembershipPort() {

        @Override
        public List<String> mappingRuleIds(final MembershipQuery query) {
          return List.of();
        }

        @Override
        public List<String> groupIds(final MembershipQuery query) {
          return List.of();
        }

        @Override
        public List<String> roleIds(final MembershipQuery query) {
          return query.principalType() == PrincipalType.USER ? List.of("operator") : List.of();
        }

        @Override
        public List<String> tenantIds(final MembershipQuery query) {
          return List.of();
        }
      };
    }
  }
}
