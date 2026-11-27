/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import io.camunda.security.core.port.out.MembershipPort;
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
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.assertj.AssertableWebApplicationContext;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * The API chain under test, for the live identity provider tests.
 *
 * <p>It is the same chain that {@code KeycloakUserBearerTokenIT} drives. Only the issuer, the
 * audience and the three claim settings differ per provider, so the live tests add those and share
 * everything else from here.
 */
public final class LiveIdpApiChain {

  public static final String API_PATH = "/api/process-instances";
  public static final String ROLE_OF_A_USER = "operator";

  private static final String API_CHAIN_BEAN = "oidcApiSecurityFilterChain";

  private LiveIdpApiChain() {}

  /** The chain with everything but the provider settings, which the caller adds. */
  public static WebApplicationContextRunner runner() {
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
            "camunda.security.authentication.oidc.user-info-enabled=false");
  }

  /** Sends the token to the API chain and returns the authentication the chain resolved. */
  public static CamundaAuthentication callApiWith(
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

  /** Gives a user a role, so the test sees that memberships resolve for a Bearer principal. */
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
          return query.principalType() == MembershipPort.PrincipalType.USER
              ? List.of(ROLE_OF_A_USER)
              : List.of();
        }

        @Override
        public List<String> tenantIds(final MembershipQuery query) {
          return List.of();
        }
      };
    }
  }
}
