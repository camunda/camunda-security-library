/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.SESSION_COOKIE;
import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.filter.OAuth2RefreshTokenFilter;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.oidc.OidcBeansConfiguration;
import io.camunda.security.spring.oidc.OidcWebappClientBeansConfiguration;
import io.camunda.security.spring.oidc.ScopedOidcInfrastructureConfiguration;
import io.camunda.security.spring.session.WebSessionTestAccess;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import jakarta.servlet.Filter;
import jakarta.servlet.http.Cookie;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.session.web.http.SessionRepositoryFilter;

/**
 * Verifies that the primary OIDC API chain refreshes a session-authenticated caller's access token
 * the way the primary webapp chain does (camunda-security-library#662), and that it still builds in
 * a bearer-only deployment where no OAuth2 client beans exist.
 */
class OidcApiChainTokenRefreshTest {

  private static final String API_CHAIN_BEAN = "oidcApiSecurityFilterChain";
  private static final String API_PATH = "/api/authentication/me";
  private static final String REGISTRATION_ID = "oidc";
  private static final String PRINCIPAL_NAME = "alice";

  /** See the note on the same constant in {@code ScopedApiTokenRefreshTest}. */
  private static final String AUTHORIZED_CLIENTS_ATTRIBUTE =
      HttpSessionOAuth2AuthorizedClientRepository.class.getName() + ".AUTHORIZED_CLIENTS";

  private static final AtomicReference<OAuth2AuthorizedClientProvider> PROVIDER =
      new AtomicReference<>();

  private static final String[] OIDC_PROPERTIES = {
    "camunda.security.authentication.method=oidc",
    "camunda.security.authentication.oidc.jwk-set-uri=http://localhost/jwks",
    "camunda.security.authentication.oidc.client-id=test-client",
    "camunda.security.authentication.oidc.client-secret=secret",
    "camunda.security.authentication.oidc.authorization-uri=http://localhost/auth",
    "camunda.security.authentication.oidc.token-uri=http://localhost/token",
    "camunda.security.authentication.oidc.user-info-uri=http://localhost/userinfo",
    "camunda.security.authentication.oidc.redirect-uri=http://localhost/sso-callback"
  };

  private final WebApplicationContextRunner runner =
      new WebApplicationContextRunner()
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
          .withPropertyValues(OIDC_PROPERTIES);

  @BeforeEach
  void resetProvider() {
    PROVIDER.set(context -> null);
  }

  @Test
  void installsTheRefreshFilterAfterTheAuthorizationFilter() {
    runner.run(
        ctx -> {
          assertThat(ctx).hasNotFailed();

          final var filters = ctx.getBean(API_CHAIN_BEAN, SecurityFilterChain.class).getFilters();
          final var refreshIndex = indexOf(filters, OAuth2RefreshTokenFilter.class);

          assertThat(refreshIndex)
              .as("the primary OIDC API chain must carry an OAuth2RefreshTokenFilter")
              .isNotNegative();
          assertThat(refreshIndex)
              .as("the refresh filter must run after AuthorizationFilter, as on the webapp chain")
              .isGreaterThan(indexOf(filters, AuthorizationFilter.class));
        });
  }

  @Test
  void refreshesAnExpiredAccessTokenOnASessionAuthenticatedRequest() {
    runner
        .withUserConfiguration(StubAuthorizedClientManager.class)
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

              final var chain = ctx.getBean(API_CHAIN_BEAN, SecurityFilterChain.class);
              final var repository = sessionRepository(ctx);
              final var sessionId = seedSession(repository, expiredAuthorizedClient(true));

              final var response = get(chain, sessionId);

              assertThat(response.getStatus()).isEqualTo(200);
              assertThat(storedAccessToken(repository, sessionId).getTokenValue())
                  .as("the stored authorized client must hold the refreshed access token")
                  .isEqualTo("refreshed-token");
            });
  }

  @Test
  void rejectsTheRequestWhenTheTokenCannotBeRefreshed() {
    runner
        .withUserConfiguration(StubAuthorizedClientManager.class)
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();

              final var chain = ctx.getBean(API_CHAIN_BEAN, SecurityFilterChain.class);
              final var repository = sessionRepository(ctx);
              // No refresh token at all, so the filter force-logs-out without contacting the IdP.
              final var sessionId = seedSession(repository, expiredAuthorizedClient(false));

              final var response = get(chain, sessionId);

              assertThat(response.getStatus()).isEqualTo(401);
              assertThat(response.getHeader(HttpHeaders.WWW_AUTHENTICATE))
                  .as("the 401 must carry the chain's RFC 6750 bearer challenge")
                  .isNotNull()
                  .startsWith("Bearer");
              assertThat(repository.findById(sessionId))
                  .as("the forced logout must invalidate the session")
                  .isNull();
            });
  }

  @Test
  void buildsWithoutARefreshFilterWhenTheWebappChainIsDisabled() {
    runner
        .withUserConfiguration(StubJwtDecoder.class)
        .withPropertyValues("camunda.security.authentication.webapp-enabled=false")
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(ctx)
                  .as("a bearer-only deployment registers no OAuth2 authorized-client beans")
                  .doesNotHaveBean(OAuth2AuthorizedClientManager.class);

              final var filters =
                  ctx.getBean(API_CHAIN_BEAN, SecurityFilterChain.class).getFilters();

              assertThat(indexOf(filters, OAuth2RefreshTokenFilter.class))
                  .as(
                      "without a session login there is no stored token to refresh, so the chain"
                          + " must build exactly as it did before")
                  .isEqualTo(-1);
            });
  }

  // -------------------------------------------------------------------------
  // Fixtures
  // -------------------------------------------------------------------------

  private static MockHttpServletResponse get(
      final SecurityFilterChain chain, final String sessionId) throws Exception {
    final var proxy = new FilterChainProxy(List.of(chain));
    final var request = new MockHttpServletRequest("GET", API_PATH);
    request.setCookies(new Cookie(SESSION_COOKIE, encodedCookieValue(sessionId)));
    final var response = new MockHttpServletResponse();
    proxy.doFilter(request, response, new MockFilterChain());
    return response;
  }

  private static String seedSession(
      final SessionRepository<? extends Session> repository,
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
      final SessionRepository<S> repository, final Session session) {
    repository.save((S) session);
  }

  private static OAuth2AccessToken storedAccessToken(
      final SessionRepository<? extends Session> repository, final String sessionId) {
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
        .clientId("test-client")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("http://localhost/sso-callback")
        .authorizationUri("http://localhost/auth")
        .tokenUri("http://localhost/token")
        .jwkSetUri("http://localhost/jwks")
        .build();
  }

  private static String encodedCookieValue(final String sessionId) {
    return Base64.getEncoder().encodeToString(sessionId.getBytes(StandardCharsets.UTF_8));
  }

  private static org.springframework.session.MapSessionRepository sessionRepository(
      final ApplicationContext ctx) {
    return WebSessionTestAccess.mapRepositoryOf(ctx.getBean(SessionRepositoryFilter.class));
  }

  private static int indexOf(final List<Filter> filters, final Class<?> filterType) {
    for (int i = 0; i < filters.size(); i++) {
      if (filterType.isInstance(filters.get(i))) {
        return i;
      }
    }
    return -1;
  }

  // -------------------------------------------------------------------------
  // Inner configuration classes
  // -------------------------------------------------------------------------

  /**
   * Replaces the library default so the refresh runs through a real {@link
   * DefaultOAuth2AuthorizedClientManager}, success handler and repository write included, while the
   * token endpoint itself is stubbed by {@link #PROVIDER}.
   */
  @Configuration
  static class StubAuthorizedClientManager {

    @Bean
    OAuth2AuthorizedClientManager authorizedClientManager(
        final ClientRegistrationRepository clientRegistrationRepository,
        final OAuth2AuthorizedClientRepository authorizedClientRepository) {
      final var manager =
          new DefaultOAuth2AuthorizedClientManager(
              clientRegistrationRepository, authorizedClientRepository);
      manager.setAuthorizedClientProvider(context -> PROVIDER.get().authorize(context));
      return manager;
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
  static class StubJwtDecoder {

    @Bean
    JwtDecoder jwtDecoder() {
      return token -> {
        throw new JwtException("no decoder configured");
      };
    }
  }

  @Configuration
  static class StubPaths {

    @Bean
    SecurityPathPort securityPathPort() {
      return StubSecurityPaths.builder().webappPaths("/operate/**").build();
    }
  }
}
