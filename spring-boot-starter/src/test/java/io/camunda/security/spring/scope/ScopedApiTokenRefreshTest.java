/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.camunda.security.api.context.CamundaSecurityScopeProvider;
import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.AuthenticationMethod;
import io.camunda.security.api.model.config.ScopedSecurityDescriptor;
import io.camunda.security.core.port.out.BasicAuthUserDetailsPort;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.filter.OAuth2RefreshTokenFilter;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.oidc.OidcTestServer;
import io.camunda.security.spring.security.BaseSecurityConfiguration;
import io.camunda.security.spring.security.BasicAuthApiSecurityConfiguration;
import io.camunda.security.spring.session.WebSessionTestAccess;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import io.camunda.security.spring.user.UserConfiguration;
import jakarta.servlet.http.Cookie;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.session.Session;
import org.springframework.session.web.http.SessionRepositoryFilter;

/**
 * Verifies that a scoped OIDC API chain refreshes the access token of a session-authenticated
 * caller, instead of serving the whole session with the expired token it was minted with
 * (camunda-security-library#662).
 */
class ScopedApiTokenRefreshTest {

  private static final String BASE_A = "/physical-tenants/a";
  private static final String COOKIE_A = ScopedSecurityChainRegistrar.sessionCookieName(BASE_A);
  private static final String API_PATH_A = BASE_A + "/api/authentication/me";
  private static final String REGISTRATION_ID = "oidc";
  private static final String PRINCIPAL_NAME = "alice";

  /**
   * The session attribute {@link HttpSessionOAuth2AuthorizedClientRepository} stores its clients
   * under. The constant is private there, so it is reproduced here — the very fact that the name is
   * derived from the class and not from an instance is what lets the API chain read what the login
   * flow on the webapp chain stored.
   */
  private static final String AUTHORIZED_CLIENTS_ATTRIBUTE =
      HttpSessionOAuth2AuthorizedClientRepository.class.getName() + ".AUTHORIZED_CLIENTS";

  /** Set per test; the stub client manager delegates every authorization attempt to it. */
  private static final AtomicReference<OAuth2AuthorizedClientProvider> PROVIDER =
      new AtomicReference<>();

  private static OidcTestServer serverA;

  @BeforeAll
  static void startOidcServer() throws Exception {
    serverA = OidcTestServer.startRsa("key-refresh-a");
  }

  @AfterAll
  static void stopOidcServer() {
    if (serverA != null) {
      serverA.stop();
    }
  }

  @BeforeEach
  void resetProvider() {
    PROVIDER.set(context -> null);
  }

  private WebApplicationContextRunner runner() {
    return baseRunner().withUserConfiguration(StubPaths.class, OneScopeProvider.class);
  }

  /** Everything but the {@link SecurityPathPort} and the scope provider, which vary per test. */
  private WebApplicationContextRunner baseRunner() {
    return new WebApplicationContextRunner()
        .withUserConfiguration(
            ObjectMapperConfig.class,
            StubUserDetailsPort.class,
            StubAuthorizedClientManagerFactory.class)
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

  @Test
  void installsTheRefreshFilterAfterTheAuthorizationFilter() {
    runner()
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();

              final var filters = apiChain(ctx).getFilters();
              final var refreshIndex = indexOf(filters, OAuth2RefreshTokenFilter.class);
              final var authorizationIndex = indexOf(filters, AuthorizationFilter.class);

              assertThat(refreshIndex)
                  .as("the scoped OIDC API chain must carry an OAuth2RefreshTokenFilter")
                  .isNotNegative();
              assertThat(refreshIndex)
                  .as(
                      "the refresh filter must run after AuthorizationFilter, as on the webapp chain")
                  .isGreaterThan(authorizationIndex);
            });
  }

  @Test
  void refreshesAnExpiredAccessTokenOnASessionAuthenticatedRequest() {
    runner()
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();

              final var refreshed =
                  accessToken("refreshed-token", Instant.now().plus(1, ChronoUnit.HOURS));
              PROVIDER.set(
                  context ->
                      new OAuth2AuthorizedClient(
                          context.getClientRegistration(),
                          PRINCIPAL_NAME,
                          refreshed,
                          new OAuth2RefreshToken("refresh-token", Instant.now())));

              final var chain = apiChain(ctx);
              final var repository = sessionRepository(chain);
              final var sessionId = seedSession(repository, expiredAuthorizedClient(true));

              final var response = get(chain, sessionId);

              assertThat(response.getStatus())
                  .as("a session-authenticated API request must succeed after the refresh")
                  .isEqualTo(200);
              assertThat(storedAccessToken(repository, sessionId).getTokenValue())
                  .as("the stored authorized client must hold the refreshed access token")
                  .isEqualTo("refreshed-token");
              assertThat(storedAccessToken(repository, sessionId).getExpiresAt())
                  .as("the refreshed access token must no longer be expired")
                  .isAfter(Instant.now());
            });
  }

  @Test
  void leavesAValidAccessTokenUntouched() {
    runner()
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();

              PROVIDER.set(
                  context -> {
                    throw new AssertionError(
                        "the refresh filter must not authorize a client whose token is still valid");
                  });

              final var chain = apiChain(ctx);
              final var repository = sessionRepository(chain);
              final var valid =
                  new OAuth2AuthorizedClient(
                      clientRegistration(),
                      PRINCIPAL_NAME,
                      accessToken("valid-token", Instant.now().plus(1, ChronoUnit.HOURS)),
                      new OAuth2RefreshToken("refresh-token", Instant.now()));
              final var sessionId = seedSession(repository, valid);

              final var response = get(chain, sessionId);

              assertThat(response.getStatus()).isEqualTo(200);
              assertThat(storedAccessToken(repository, sessionId).getTokenValue())
                  .isEqualTo("valid-token");
            });
  }

  @Test
  void rejectsTheRequestAndEndsTheSessionWhenTheTokenCannotBeRefreshed() {
    runner()
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();

              final var chain = apiChain(ctx);
              final var repository = sessionRepository(chain);
              // No refresh token at all — the filter force-logs-out without contacting the IdP.
              final var sessionId = seedSession(repository, expiredAuthorizedClient(false));

              final var response = get(chain, sessionId);

              assertThat(response.getStatus())
                  .as("an expired token that cannot be renewed must not authenticate the request")
                  .isEqualTo(401);
              assertThat(repository.findById(sessionId))
                  .as("the forced logout must invalidate the scope's session")
                  .isNull();
              final var cleared = response.getCookie(COOKIE_A);
              assertThat(cleared)
                  .as("the forced logout must expire the scope's own session cookie")
                  .isNotNull();
              assertThat(cleared.getMaxAge()).isZero();
              assertThat(cleared.getPath())
                  .as("the cookie must be cleared on the path the scope set it on")
                  .isEqualTo(BASE_A);
            });
  }

  @Test
  void leavesASessionThatHoldsNoOAuth2AuthenticationUntouched() {
    runner()
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();

              PROVIDER.set(
                  context -> {
                    throw new AssertionError(
                        "the refresh filter must ignore a non-OAuth2 authentication");
                  });

              final var chain = apiChain(ctx);
              final var repository = sessionRepository(chain);
              final var session = repository.createSession();
              session.setAttribute(
                  HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                  new SecurityContextImpl(
                      new UsernamePasswordAuthenticationToken(
                          PRINCIPAL_NAME, null, List.of(new SimpleGrantedAuthority("ROLE_USER")))));
              repository.save(session);

              final var response = get(chain, session.getId());

              assertThat(response.getStatus()).isEqualTo(200);
            });
  }

  /**
   * A scope whose host declares no webapp paths gets a working API chain and an inert webapp chain,
   * so the API chain's client-registration repository is the only one that scope builds. Validating
   * it in login mode would apply {@code requireUserInfoRequiredConsistency}, which throws for
   * {@code user-info-required=true} with {@code user-info-enabled=false} — a combination that is
   * inert without a login chain, and that used to start fine.
   */
  @Test
  void startsForAnApiOnlyScopeWhoseConfigurationOnlyALoginChainWouldReject() {
    baseRunner()
        .withUserConfiguration(ApiOnlyPaths.class, UserInfoRequiredWithoutUserInfoScope.class)
        .run(
            ctx -> {
              assertThat(ctx)
                  .as(
                      "user-info-required is inert for a scope with no login chain, so it must not"
                          + " fail the API chain's startup")
                  .hasNotFailed();
              assertThat(indexOf(apiChain(ctx).getFilters(), OAuth2RefreshTokenFilter.class))
                  .isNotNegative();
            });
  }

  // -------------------------------------------------------------------------
  // Fixtures
  // -------------------------------------------------------------------------

  private static MockHttpServletResponse get(
      final SecurityFilterChain chain, final String sessionId) throws Exception {
    final var proxy = new FilterChainProxy(List.of(chain));
    final var request = new MockHttpServletRequest("GET", API_PATH_A);
    request.setCookies(new Cookie(COOKIE_A, encodedCookieValue(sessionId)));
    final var response = new MockHttpServletResponse();
    proxy.doFilter(request, response, new MockFilterChain());
    return response;
  }

  /**
   * Seeds a session the way a completed login on the scope's webapp chain leaves it: an {@link
   * OAuth2AuthenticationToken} in the security context and the authorized client in the repository
   * attribute.
   */
  private static String seedSession(
      final org.springframework.session.SessionRepository<? extends Session> repository,
      final OAuth2AuthorizedClient authorizedClient) {
    final var session = repository.createSession();
    final var principal =
        new DefaultOidcUser(
            List.of(new SimpleGrantedAuthority("ROLE_USER")),
            OidcIdToken.withTokenValue("id-token").claim("sub", PRINCIPAL_NAME).build());
    session.setAttribute(
        HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
        new SecurityContextImpl(
            new OAuth2AuthenticationToken(principal, principal.getAuthorities(), REGISTRATION_ID)));
    final Map<String, OAuth2AuthorizedClient> clients = new HashMap<>();
    clients.put(REGISTRATION_ID, authorizedClient);
    session.setAttribute(AUTHORIZED_CLIENTS_ATTRIBUTE, clients);
    saveSession(repository, session);
    return session.getId();
  }

  @SuppressWarnings("unchecked")
  private static <S extends Session> void saveSession(
      final org.springframework.session.SessionRepository<S> repository, final Session session) {
    repository.save((S) session);
  }

  private static OAuth2AccessToken storedAccessToken(
      final org.springframework.session.SessionRepository<? extends Session> repository,
      final String sessionId) {
    final Map<String, OAuth2AuthorizedClient> clients =
        repository.findById(sessionId).getAttribute(AUTHORIZED_CLIENTS_ATTRIBUTE);
    assertThat(clients).containsKey(REGISTRATION_ID);
    return clients.get(REGISTRATION_ID).getAccessToken();
  }

  private static OAuth2AuthorizedClient expiredAuthorizedClient(final boolean withRefreshToken) {
    return new OAuth2AuthorizedClient(
        clientRegistration(),
        PRINCIPAL_NAME,
        accessToken("expired-token", Instant.now().minus(1, ChronoUnit.HOURS)),
        withRefreshToken ? new OAuth2RefreshToken("refresh-token", Instant.now()) : null);
  }

  private static OAuth2AccessToken accessToken(final String value, final Instant expiresAt) {
    return new OAuth2AccessToken(
        OAuth2AccessToken.TokenType.BEARER, value, expiresAt.minus(2, ChronoUnit.HOURS), expiresAt);
  }

  private static ClientRegistration clientRegistration() {
    return ClientRegistration.withRegistrationId(REGISTRATION_ID)
        .clientId("api-refresh-client")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
        .authorizationUri(serverA.issuerUri() + "/auth")
        .tokenUri(serverA.issuerUri() + "/token")
        .jwkSetUri(serverA.jwksUri())
        .build();
  }

  private static String encodedCookieValue(final String sessionId) {
    return Base64.getEncoder().encodeToString(sessionId.getBytes(StandardCharsets.UTF_8));
  }

  private static int indexOf(
      final List<jakarta.servlet.Filter> filters, final Class<?> filterType) {
    for (int i = 0; i < filters.size(); i++) {
      if (filterType.isInstance(filters.get(i))) {
        return i;
      }
    }
    return -1;
  }

  private static SecurityFilterChain apiChain(final ApplicationContext ctx) {
    final var names = ctx.getBeanNamesForType(SecurityFilterChain.class);
    final var name =
        Arrays.stream(names)
            .filter(n -> n.startsWith("scopedApiSecurityFilterChain-"))
            .findFirst()
            .orElseThrow(
                () ->
                    new AssertionError(
                        "No scoped API chain bean found; available chains: "
                            + Arrays.toString(names)));
    return ctx.getBean(name, SecurityFilterChain.class);
  }

  private static org.springframework.session.MapSessionRepository sessionRepository(
      final SecurityFilterChain chain) {
    final var sessionFilter =
        chain.getFilters().stream()
            .filter(SessionRepositoryFilter.class::isInstance)
            .map(f -> (SessionRepositoryFilter<?>) f)
            .findFirst()
            .orElseThrow(
                () -> new AssertionError("No SessionRepositoryFilter found on chain " + chain));
    return WebSessionTestAccess.mapRepositoryOf(sessionFilter);
  }

  // -------------------------------------------------------------------------
  // Inner configuration classes
  // -------------------------------------------------------------------------

  /**
   * Replaces the library default so the refresh goes through a real {@link
   * DefaultOAuth2AuthorizedClientManager} — success handler and repository write included — while
   * the token endpoint itself is stubbed by {@link #PROVIDER}.
   */
  @Configuration
  static class StubAuthorizedClientManagerFactory {

    @Bean
    OAuth2AuthorizedClientManagerFactory oauth2AuthorizedClientManagerFactory() {
      return (clientRegistrationRepository, authorizedClientRepository) -> {
        final var manager =
            new DefaultOAuth2AuthorizedClientManager(
                clientRegistrationRepository, authorizedClientRepository);
        manager.setAuthorizedClientProvider(context -> PROVIDER.get().authorize(context));
        return manager;
      };
    }
  }

  @Configuration
  static class OneScopeProvider {

    @Bean
    CamundaSecurityScopeProvider oneScopedDescriptor() {
      final var auth = new AuthenticationConfiguration();
      auth.setMethod(AuthenticationMethod.OIDC);
      auth.setOidc(serverA.oidcConfiguration("api-refresh-client"));
      return () -> List.of(new ScopedSecurityDescriptor(BASE_A, auth));
    }
  }

  @Configuration
  static class ApiOnlyPaths {

    @Bean
    SecurityPathPort securityPathPort() {
      return StubSecurityPaths.builder().apiPaths("/api/**").webappPaths().build();
    }
  }

  @Configuration
  static class UserInfoRequiredWithoutUserInfoScope {

    @Bean
    CamundaSecurityScopeProvider userInfoRequiredScope() {
      final var oidc = serverA.oidcConfiguration("api-refresh-client");
      oidc.setUserInfoRequired(true);
      oidc.setUserInfoEnabled(false);
      final var auth = new AuthenticationConfiguration();
      auth.setMethod(AuthenticationMethod.OIDC);
      auth.setOidc(oidc);
      return () -> List.of(new ScopedSecurityDescriptor(BASE_A, auth));
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
    BasicAuthUserDetailsPort userDetailsPort() {
      return username -> null;
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
