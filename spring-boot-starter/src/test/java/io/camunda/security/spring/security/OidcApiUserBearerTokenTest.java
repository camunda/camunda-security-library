/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.AuthorizationScope;
import io.camunda.security.api.model.authz.EntityType;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.core.auth.RequiredAuthorization;
import io.camunda.security.core.authz.AuthorizationChecker;
import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import io.camunda.security.core.port.out.AuthorizationScopeRepositoryPort;
import io.camunda.security.core.port.out.MembershipPort;
import io.camunda.security.core.port.out.MembershipQuery;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.context.CamundaAuthenticationBeansConfiguration;
import io.camunda.security.spring.converter.OidcTokenAuthenticationConverter;
import io.camunda.security.spring.converter.TokenClaimsConvertersByIssuer;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.oidc.NoopOidcClaimsProvider;
import io.camunda.security.spring.oidc.OidcBeansConfiguration;
import io.camunda.security.spring.oidc.OidcWebappClientBeansConfiguration;
import io.camunda.security.spring.oidc.ScopedOidcInfrastructureConfiguration;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * The user Bearer token path on the OIDC API chain.
 *
 * <p>c8ctl and Desktop Modeler sign a user in themselves, as a public client with PKCE, and call
 * the API with the access token they receive. No session exists. These tests send such a token
 * through the real filter chain and check what the library makes of it: a user principal, the
 * memberships of that user, and an allowed call that passes next to a denied call that fails.
 *
 * <p>The machine path must not change. A client credentials token of a {@code hybrid} registration
 * stays a client, because it carries the client ID claim that the user token does not have.
 *
 * <p>See ADR-0048, and ADR-0011 for the rule that a Bearer token is only accepted on an API path.
 */
class OidcApiUserBearerTokenTest {

  private static final String API_CHAIN_BEAN = "oidcApiSecurityFilterChain";
  private static final String WEBAPP_CHAIN_BEAN = "oidcWebappSecurityFilterChain";
  private static final String ISSUER = "https://idp.example.com/realms/csl";
  private static final String API_PATH = "/api/process-instances";
  private static final String WEBAPP_PATH = "/operate/index.html";

  private static final String USER_TOKEN = "user-bearer-token";
  private static final String CLIENT_TOKEN = "client-credentials-token";
  private static final String UNKNOWN_TOKEN = "not-a-token";

  /**
   * The settings this task recommends for Keycloak: the client ID claim names a claim that only a
   * service account token carries, and the username claim wins for no token.
   */
  private static final String[] OIDC_PROPERTIES = {
    "camunda.security.authentication.method=oidc",
    "camunda.security.authentication.oidc.issuer-uri=" + ISSUER,
    "camunda.security.authentication.oidc.jwk-set-uri=http://localhost/jwks",
    "camunda.security.authentication.oidc.client-id=csl-hybrid",
    "camunda.security.authentication.oidc.client-secret=secret",
    "camunda.security.authentication.oidc.authorization-uri=http://localhost/auth",
    "camunda.security.authentication.oidc.token-uri=http://localhost/token",
    "camunda.security.authentication.oidc.redirect-uri=http://localhost/sso-callback",
    "camunda.security.authentication.oidc.username-claim=preferred_username",
    "camunda.security.authentication.oidc.client-id-claim=client_id",
    "camunda.security.authentication.oidc.prefer-username-claim=false"
  };

  private final WebApplicationContextRunner runner =
      new WebApplicationContextRunner()
          .withUserConfiguration(
              ObjectMapperConfig.class, StubPaths.class, StubMemberships.class, StubDecoder.class)
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class,
                  BaseSecurityConfiguration.class,
                  OidcApiSecurityConfiguration.class,
                  OidcWebappSecurityConfiguration.class,
                  ScopedWebappSecurityChainBuilderConfiguration.class,
                  AuthFailureHandlerConfiguration.class,
                  CamundaAuthenticationBeansConfiguration.class,
                  OidcBeansConfiguration.class,
                  OidcWebappClientBeansConfiguration.class,
                  ScopedOidcInfrastructureConfiguration.class))
          .withPropertyValues(OIDC_PROPERTIES);

  @Test
  void aUserBearerTokenAuthenticatesOnAnApiPathAsAUser() {
    runner.run(
        ctx -> {
          final var authentication = callApiWith(ctx, USER_TOKEN);

          assertThat(authentication.authenticatedUsername()).isEqualTo("alice");
          assertThat(authentication.authenticatedClientId()).isNull();
        });
  }

  @Test
  void theMembershipsOfTheUserGiveRolesGroupsAndTenants() {
    runner.run(
        ctx -> {
          final var authentication = callApiWith(ctx, USER_TOKEN);

          assertThat(authentication.authenticatedMappingRuleIds()).containsExactly("rule-alice");
          assertThat(authentication.authenticatedGroupIds()).containsExactly("operations");
          assertThat(authentication.authenticatedRoleIds()).containsExactly("operator");
          assertThat(authentication.authenticatedTenantIds()).containsExactly("tenant-a");
        });
  }

  /**
   * The whole path of one request, as a host wires it: the chain authenticates the Bearer token,
   * the host converts the principal, and the host checks the authorization of that principal before
   * it serves the resource. The caller sees 200 or 403.
   */
  @Test
  void anAllowedCallPassesAndADeniedCallFails() throws Exception {
    runner.run(
        ctx -> {
          assertThat(callResource(ctx, USER_TOKEN, "order-process"))
              .as("the role of the user holds a grant for this process definition")
              .isEqualTo(200);
          assertThat(callResource(ctx, USER_TOKEN, "payroll-process"))
              .as("no owner of the user holds a grant for this process definition")
              .isEqualTo(403);
        });
  }

  @Test
  void aClientCredentialsTokenOfAHybridRegistrationStaysAClient() {
    runner.run(
        ctx -> {
          final var authentication = callApiWith(ctx, CLIENT_TOKEN);

          assertThat(authentication.authenticatedClientId()).isEqualTo("csl-hybrid");
          assertThat(authentication.authenticatedUsername()).isNull();
        });
  }

  @Test
  void aBearerTokenOnAWebappPathIsRejected() throws Exception {
    runner.run(
        ctx -> {
          final var proxy =
              new FilterChainProxy(
                  List.of(
                      ctx.getBean(API_CHAIN_BEAN, SecurityFilterChain.class),
                      ctx.getBean(WEBAPP_CHAIN_BEAN, SecurityFilterChain.class)));
          final var response = new MockHttpServletResponse();

          proxy.doFilter(bearerRequest(WEBAPP_PATH, USER_TOKEN), response, new MockFilterChain());

          assertThat(response.getStatus())
              .as("ADR-0011: a Bearer token is only accepted on an API path")
              .isEqualTo(401);
        });
  }

  @Test
  void aTokenTheDecoderRefusesIsRejectedWithAReason() throws Exception {
    runner.run(
        ctx -> {
          final var proxy =
              new FilterChainProxy(List.of(ctx.getBean(API_CHAIN_BEAN, SecurityFilterChain.class)));
          final var response = new MockHttpServletResponse();

          proxy.doFilter(bearerRequest(API_PATH, UNKNOWN_TOKEN), response, new MockFilterChain());

          assertThat(response.getStatus()).isEqualTo(401);
          assertThat(response.getHeader(HttpHeaders.WWW_AUTHENTICATE))
              .as("the caller must learn why the token failed")
              .contains("invalid_token")
              .contains("The signature of the token is not valid");
        });
  }

  /**
   * Sends one Bearer request for a process definition and returns the status the caller sees. The
   * terminal filter stands in for the endpoint of the host: it resolves the principal of the
   * request and refuses the resource when that principal holds no grant for it.
   */
  private int callResource(
      final AssertableWebApplicationContext ctx, final String token, final String resourceId)
      throws Exception {
    assertThat(ctx).hasNotFailed();
    final var proxy =
        new FilterChainProxy(List.of(ctx.getBean(API_CHAIN_BEAN, SecurityFilterChain.class)));
    final var response = new MockHttpServletResponse();
    final var checker = new AuthorizationChecker(new StubScopes());
    final var converter = hostConverter(ctx);

    proxy.doFilter(
        bearerRequest(API_PATH + "/" + resourceId, token),
        response,
        (request, servletResponse) -> {
          final var authentication =
              converter.convert(SecurityContextHolder.getContext().getAuthentication());
          if (!checker.isAuthorized(
              AuthorizationScope.of(resourceId), authentication, readProcessDefinition())) {
            // The chain wraps the response, so the wrapper is what the endpoint writes to.
            ((HttpServletResponse) servletResponse).setStatus(403);
          }
        });

    return response.getStatus();
  }

  /**
   * Sends one Bearer request through the API chain and converts what the chain authenticated, as a
   * host does with {@code OidcTokenAuthenticationConverter}.
   */
  private CamundaAuthentication callApiWith(
      final AssertableWebApplicationContext ctx, final String token) throws Exception {
    assertThat(ctx).hasNotFailed();
    final var proxy =
        new FilterChainProxy(List.of(ctx.getBean(API_CHAIN_BEAN, SecurityFilterChain.class)));
    final var response = new MockHttpServletResponse();
    // The chain clears the security context when the request ends, so the terminal filter is the
    // only place a caller sees what the request authenticated.
    final var captured = new AtomicReference<Authentication>();

    proxy.doFilter(
        bearerRequest(API_PATH, token),
        response,
        (request, servletResponse) ->
            captured.set(SecurityContextHolder.getContext().getAuthentication()));

    assertThat(response.getStatus())
        .as("the chain did not authenticate the Bearer token")
        .isEqualTo(200);
    assertThat(captured.get()).as("no authentication reached the security context").isNotNull();
    return hostConverter(ctx).convert(captured.get());
  }

  /** The converter a host registers to turn a verified Bearer token into a Camunda principal. */
  private static OidcTokenAuthenticationConverter hostConverter(
      final AssertableWebApplicationContext ctx) {
    return new OidcTokenAuthenticationConverter(
        ctx.getBean(LazyTokenClaimsConverter.class),
        new NoopOidcClaimsProvider(),
        ctx.getBean(TokenClaimsConvertersByIssuer.class));
  }

  private static MockHttpServletRequest bearerRequest(final String path, final String token) {
    final var request = new MockHttpServletRequest("GET", path);
    request.setServletPath(path);
    request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token);
    return request;
  }

  private static RequiredAuthorization<Object> readProcessDefinition() {
    return RequiredAuthorization.of(b -> b.processDefinition().readProcessDefinition());
  }

  /** The authorization store of the host: the role of the user holds one grant. */
  private static final class StubScopes implements AuthorizationScopeRepositoryPort {

    private static final String GRANTED_RESOURCE_ID = "order-process";

    @Override
    public List<AuthorizationScope> findAuthorizedScopes(
        final Map<EntityType, Set<String>> ownerIds,
        final AuthorizationResourceType resourceType,
        final PermissionType permissionType) {
      return grants(ownerIds, resourceType, permissionType)
          ? List.of(AuthorizationScope.id(GRANTED_RESOURCE_ID))
          : List.of();
    }

    @Override
    public boolean hasAuthorizedScope(
        final Map<EntityType, Set<String>> ownerIds,
        final AuthorizationResourceType resourceType,
        final PermissionType permissionType,
        final List<String> resourceIds) {
      return grants(ownerIds, resourceType, permissionType)
          && resourceIds.contains(GRANTED_RESOURCE_ID);
    }

    @Override
    public Set<PermissionType> findPermissionTypes(
        final Map<EntityType, Set<String>> ownerIds,
        final AuthorizationResourceType resourceType,
        final List<String> resourceIds) {
      return hasAuthorizedScope(
              ownerIds, resourceType, PermissionType.READ_PROCESS_DEFINITION, resourceIds)
          ? Set.of(PermissionType.READ_PROCESS_DEFINITION)
          : Set.of();
    }

    private static boolean grants(
        final Map<EntityType, Set<String>> ownerIds,
        final AuthorizationResourceType resourceType,
        final PermissionType permissionType) {
      return resourceType == AuthorizationResourceType.PROCESS_DEFINITION
          && permissionType == PermissionType.READ_PROCESS_DEFINITION
          && ownerIds.getOrDefault(EntityType.ROLE, Set.of()).contains("operator");
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
      return StubSecurityPaths.builder()
          .apiPaths("/api/**")
          .webappPaths("/operate/**", "/login", "/logout")
          .build();
    }
  }

  /** Memberships of alice only; the machine principal resolves to nothing. */
  @Configuration
  static class StubMemberships {

    @Bean
    MembershipPort membershipPort() {
      return new MembershipPort() {

        @Override
        public List<String> mappingRuleIds(final MembershipQuery query) {
          return isAlice(query) ? List.of("rule-alice") : List.of();
        }

        @Override
        public List<String> groupIds(final MembershipQuery query) {
          return isAlice(query) ? List.of("operations") : List.of();
        }

        @Override
        public List<String> roleIds(final MembershipQuery query) {
          return isAlice(query) ? List.of("operator") : List.of();
        }

        @Override
        public List<String> tenantIds(final MembershipQuery query) {
          return isAlice(query) ? List.of("tenant-a") : List.of();
        }

        private boolean isAlice(final MembershipQuery query) {
          return "alice".equals(query.principalId());
        }
      };
    }
  }

  /**
   * Stands in for the identity provider. It returns the two token shapes a Keycloak realm issues: a
   * user token of a public client, which carries no {@code client_id}, and a service account token
   * of the hybrid client, which does.
   */
  @Configuration
  static class StubDecoder {

    @Bean
    JwtDecoder jwtDecoder() {
      return token ->
          switch (token) {
            case USER_TOKEN ->
                jwt(
                    token,
                    Map.of(
                        "iss", ISSUER,
                        "sub", "f:1b7c:alice",
                        "typ", "Bearer",
                        "azp", "csl-public",
                        "preferred_username", "alice",
                        "email", "alice@example.com"));
            case CLIENT_TOKEN ->
                jwt(
                    token,
                    Map.of(
                        "iss", ISSUER,
                        "sub", "f:1b7c:service-account",
                        "typ", "Bearer",
                        "azp", "csl-hybrid",
                        "client_id", "csl-hybrid",
                        "preferred_username", "service-account-csl-hybrid"));
            default -> throw new BadJwtException("The signature of the token is not valid");
          };
    }

    private static Jwt jwt(final String token, final Map<String, Object> claims) {
      return new Jwt(
          token,
          Instant.now().minusSeconds(60),
          Instant.now().plusSeconds(300),
          Map.of("alg", "RS256"),
          claims);
    }
  }
}
