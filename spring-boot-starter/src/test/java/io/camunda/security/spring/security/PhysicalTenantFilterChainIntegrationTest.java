/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Proves the chain-split mechanics from ADR-0011:
 *
 * <ul>
 *   <li>The new per-tenant chain serves {@code /physical-tenants/{configuredId}/**}.
 *   <li>The existing top-level chain continues to serve non-prefixed requests.
 *   <li>{@code /physical-tenants/{unknown}/**} falls to the catch-all deny chain (404).
 *   <li>Per-tenant chain registers only when at least one tenant is configured.
 * </ul>
 *
 * Stubs the per-tenant {@link AuthenticationManager}s via {@link
 * PhysicalTenantAuthenticationManagers} and the top-level {@link JwtDecoder} so the test never
 * reaches a real IDP.
 */
class PhysicalTenantFilterChainIntegrationTest {

  private static final String DEFAULT_TOKEN = "token-default";
  private static final String ACME_TOKEN = "token-acme";
  private static final String GLOBEX_TOKEN = "token-globex";

  private final WebApplicationContextRunner runner =
      new WebApplicationContextRunner()
          .withUserConfiguration(
              StubPaths.class,
              StubTopLevelJwtDecoder.class,
              StubPhysicalTenantManagers.class,
              ObjectMapperConfig.class,
              TestController.class)
          .withConfiguration(
              org.springframework.boot.autoconfigure.AutoConfigurations.of(
                  CamundaSecurityConfiguration.class,
                  BaseSecurityConfiguration.class,
                  OidcApiSecurityConfiguration.class,
                  PhysicalTenantOidcApiSecurityConfiguration.class,
                  AuthFailureHandlerConfiguration.class))
          .withPropertyValues(
              "camunda.security.authentication.method=oidc",
              "camunda.security.authentication.oidc.issuer-uri=http://localhost/default-idp",
              "camunda.security.physical-tenants[0].id=acme",
              "camunda.security.physical-tenants[0].oidc.issuer-uri=http://localhost/acme-idp",
              "camunda.security.physical-tenants[1].id=globex",
              "camunda.security.physical-tenants[1].oidc.issuer-uri=http://localhost/globex-idp");

  @Test
  void topLevelChainAcceptsDefaultTokenAtNonTenantPath() throws Exception {
    runner.run(
        ctx -> {
          final MockMvc mvc = mvc(ctx);
          mvc.perform(get("/v2/x").header("Authorization", "Bearer " + DEFAULT_TOKEN))
              .andExpect(status().isOk());
        });
  }

  @Test
  void topLevelChainRejectsTenantTokenAtNonTenantPath() throws Exception {
    runner.run(
        ctx -> {
          final MockMvc mvc = mvc(ctx);
          mvc.perform(get("/v2/x").header("Authorization", "Bearer " + ACME_TOKEN))
              .andExpect(status().isUnauthorized());
        });
  }

  @Test
  void tenantChainAcceptsMatchingTenantToken() throws Exception {
    runner.run(
        ctx -> {
          final MockMvc mvc = mvc(ctx);
          mvc.perform(
                  get("/physical-tenants/acme/v2/x")
                      .header("Authorization", "Bearer " + ACME_TOKEN))
              .andExpect(status().isOk());
        });
  }

  @Test
  void tenantChainRejectsMismatchedTenantToken() throws Exception {
    runner.run(
        ctx -> {
          final MockMvc mvc = mvc(ctx);
          mvc.perform(
                  get("/physical-tenants/acme/v2/x")
                      .header("Authorization", "Bearer " + GLOBEX_TOKEN))
              .andExpect(status().isUnauthorized());
        });
  }

  @Test
  void unknownTenantFallsToCatchAllDeny() throws Exception {
    runner.run(
        ctx -> {
          final MockMvc mvc = mvc(ctx);
          mvc.perform(
                  get("/physical-tenants/unknown/v2/x")
                      .header("Authorization", "Bearer " + ACME_TOKEN))
              .andExpect(status().isNotFound());
        });
  }

  @Test
  void perTenantChainBeanRegisteredWhenTenantsConfigured() {
    runner.run(
        ctx ->
            assertThat(ctx)
                .hasBean("physicalTenantOidcApiSecurityFilterChain")
                .hasSingleBean(PhysicalTenantAuthenticationManagers.class));
  }

  @Test
  void contextFailsWhenConfigImportedButTenantsEmpty() {
    final WebApplicationContextRunner emptyRunner =
        new WebApplicationContextRunner()
            .withUserConfiguration(
                StubPaths.class, StubTopLevelJwtDecoder.class, ObjectMapperConfig.class)
            .withConfiguration(
                org.springframework.boot.autoconfigure.AutoConfigurations.of(
                    CamundaSecurityConfiguration.class,
                    BaseSecurityConfiguration.class,
                    OidcApiSecurityConfiguration.class,
                    PhysicalTenantOidcApiSecurityConfiguration.class,
                    AuthFailureHandlerConfiguration.class))
            .withPropertyValues(
                "camunda.security.authentication.method=oidc",
                "camunda.security.authentication.oidc.issuer-uri=http://localhost/default-idp");

    emptyRunner.run(
        ctx ->
            assertThat(ctx)
                .hasFailed()
                .getFailure()
                .hasMessageContaining("camunda.security.physical-tenants is empty"));
  }

  private static MockMvc mvc(final org.springframework.context.ApplicationContext ctx) {
    return MockMvcBuilders.webAppContextSetup(
            (org.springframework.web.context.WebApplicationContext) ctx)
        .apply(springSecurity())
        .build();
  }

  @Configuration
  static class StubPaths {
    @Bean
    SecurityPathPort securityPathPort() {
      return new SecurityPathPort() {
        @Override
        public Set<String> apiPaths() {
          return Set.of("/v2/**");
        }

        @Override
        public Set<String> unprotectedApiPaths() {
          return Set.of();
        }

        @Override
        public Set<String> unprotectedPaths() {
          return Set.of("/error");
        }

        @Override
        public Set<String> webappPaths() {
          return Set.of();
        }

        @Override
        public Set<String> webComponentNames() {
          return Set.of();
        }
      };
    }
  }

  @Configuration
  static class StubTopLevelJwtDecoder {
    @Bean
    JwtDecoder jwtDecoder() {
      return token -> {
        if (DEFAULT_TOKEN.equals(token)) {
          return Jwt.withTokenValue(token)
              .header("alg", "none")
              .subject("default-user")
              .claim("scope", "api")
              .build();
        }
        throw new BadJwtException("Top-level decoder rejected token: " + token);
      };
    }
  }

  @Configuration
  static class StubPhysicalTenantManagers {
    @Bean
    PhysicalTenantAuthenticationManagers physicalTenantAuthenticationManagers() {
      return new PhysicalTenantAuthenticationManagers(
          Map.of(
              "acme", stubManager(ACME_TOKEN, "acme-user"),
              "globex", stubManager(GLOBEX_TOKEN, "globex-user")));
    }

    private static AuthenticationManager stubManager(
        final String acceptedToken, final String subject) {
      return authentication -> {
        if (!(authentication instanceof BearerTokenAuthenticationToken bearer)) {
          throw new InvalidBearerTokenException("Not a bearer token");
        }
        if (!acceptedToken.equals(bearer.getToken())) {
          throw new InvalidBearerTokenException("Stub rejected token");
        }
        final Jwt jwt =
            Jwt.withTokenValue(bearer.getToken())
                .header("alg", "none")
                .subject(subject)
                .claim("scope", "api")
                .build();
        final Authentication result = new JwtAuthenticationToken(jwt, List.of());
        result.setAuthenticated(true);
        return result;
      };
    }
  }

  @Configuration
  static class ObjectMapperConfig {
    @Bean
    ObjectMapper objectMapper() {
      return new ObjectMapper();
    }
  }

  @RestController
  static class TestController {
    @RequestMapping("/**")
    String anything() {
      return "ok";
    }
  }
}
