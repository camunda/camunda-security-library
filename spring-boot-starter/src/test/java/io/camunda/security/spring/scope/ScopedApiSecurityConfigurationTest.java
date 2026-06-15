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
import io.camunda.security.core.port.out.BasicAuthUserDetailsPort.CamundaUserDetails;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.oidc.OidcTestServer;
import io.camunda.security.spring.oidc.ScopedOidcInfrastructureConfiguration;
import io.camunda.security.spring.security.BaseSecurityConfiguration;
import io.camunda.security.spring.security.BasicAuthApiSecurityConfiguration;
import io.camunda.security.spring.security.CamundaSecurityFilterChainConstants;
import io.camunda.security.spring.user.UserConfiguration;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Verifies the BDRPP-based registration in {@link ScopedApiSecurityConfiguration}:
 *
 * <ul>
 *   <li>No-op when no {@link CamundaSecurityScopeProvider} bean is present.
 *   <li>One extra {@link SecurityFilterChain} bean per descriptor when a provider is present.
 *   <li>Contributed chains match only their base-path scope and challenge unauthenticated requests.
 *   <li>Correct dispatch: requests under the contributed base path go to the contributed chain.
 * </ul>
 */
class ScopedApiSecurityConfigurationTest {

  private static final String SCOPED_BASE = "/example-scope/s1";
  private static final String SCOPED_V2 = SCOPED_BASE + "/v2/resource";
  private static final String SCOPED_OTHER = SCOPED_BASE + "/other";
  private static final String GLOBAL_V2 = "/v2/resource";

  // ---------------------------------------------------------------------------
  // Shared runner factory
  // ---------------------------------------------------------------------------

  /**
   * Creates a runner that loads the full CSL chain stack (BASIC mode) including the new {@link
   * ScopedApiSecurityConfiguration}. A {@link BasicAuthUserDetailsPort} mock and {@link
   * SecurityPathPort} stub are provided as user configuration so all CSL conditions are satisfied.
   */
  private WebApplicationContextRunner basicRunner() {
    return new WebApplicationContextRunner()
        .withUserConfiguration(ObjectMapperConfig.class, StubPaths.class, StubUserDetailsPort.class)
        .withConfiguration(
            // Deliberately NOT importing ScopedApiSecurityChainBuilderConfiguration or
            // ScopedOidcInfrastructureConfiguration here: ScopedApiSecurityConfiguration @Imports
            // both, so importing only the collector must yield a self-contained, working context.
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                BaseSecurityConfiguration.class,
                BasicAuthApiSecurityConfiguration.class,
                AuthFailureHandlerConfiguration.class,
                UserConfiguration.class,
                ScopedApiSecurityConfiguration.class))
        .withPropertyValues("camunda.security.authentication.method=basic");
  }

  // ---------------------------------------------------------------------------
  // 1. No-op test
  // ---------------------------------------------------------------------------

  @Test
  void noProviderBeanRegistersNoExtraChains() {
    // No CamundaSecurityScopeProvider bean — CSL chains only, no wrappers.
    basicRunner()
        .run(
            ctx -> {
              final var wrappers =
                  ctx.getBeansOfType(SecurityFilterChain.class).values().stream()
                      .filter(c -> c instanceof OrderedSecurityFilterChainWrapper)
                      .toList();
              assertThat(wrappers)
                  .as("BDRPP must register no wrapper chains when no provider bean is present")
                  .isEmpty();
            });
  }

  // ---------------------------------------------------------------------------
  // 2. One descriptor → one extra chain
  // ---------------------------------------------------------------------------

  @Test
  void oneDescriptorRegistersOneScopedChain() {
    basicRunner()
        .withUserConfiguration(SingleBasicDescriptorProvider.class)
        .run(
            ctx -> {
              // The BDRPP creates exactly one OrderedSecurityFilterChainWrapper
              final var wrappers =
                  ctx.getBeansOfType(SecurityFilterChain.class).values().stream()
                      .filter(c -> c instanceof OrderedSecurityFilterChainWrapper)
                      .toList();
              assertThat(wrappers)
                  .as("one contributed descriptor must produce exactly one wrapper chain")
                  .hasSize(1);

              final var contributed = (OrderedSecurityFilterChainWrapper) wrappers.getFirst();

              // The contributed chain must match the scoped V2 path
              final var scopedRequest = new MockHttpServletRequest("GET", SCOPED_V2);
              assertThat(contributed.matches(scopedRequest))
                  .as("contributed chain must match basePath + /v2/**")
                  .isTrue();

              // The contributed chain must NOT match the non-V2 path under the same base
              final var otherRequest = new MockHttpServletRequest("GET", SCOPED_OTHER);
              assertThat(contributed.matches(otherRequest))
                  .as("contributed chain must NOT match non-V2 path under the same base")
                  .isFalse();

              // The contributed chain must NOT match the global /v2/** path
              final var globalRequest = new MockHttpServletRequest("GET", GLOBAL_V2);
              assertThat(contributed.matches(globalRequest))
                  .as("contributed chain must NOT match the global /v2/** path")
                  .isFalse();
            });
  }

  @Test
  void oneDescriptorContributedChainChallengesUnauthenticated() {
    basicRunner()
        .withUserConfiguration(SingleBasicDescriptorProvider.class)
        .run(
            ctx -> {
              final var contributed = contributedChain(ctx);

              final var proxy = new FilterChainProxy(List.of(contributed));
              final var request = new MockHttpServletRequest("GET", SCOPED_V2);
              final var response = new MockHttpServletResponse();
              proxy.doFilter(request, response, new MockFilterChain());

              assertThat(response.getStatus())
                  .as("unauthenticated request to scoped V2 path must be challenged with 401")
                  .isEqualTo(401);
            });
  }

  // ---------------------------------------------------------------------------
  // 3. Disjoint scope dispatch
  // ---------------------------------------------------------------------------

  @Test
  void disjointScopeDispatched() {
    // CSL's own basicAuthApiSecurityFilterChain covers /v2/** (from StubPaths.apiPaths).
    // A contributed chain covers /example-scope/s1/v2/**.
    // A request to the contributed base path must be dispatched to the contributed chain.
    basicRunner()
        .withUserConfiguration(SingleBasicDescriptorProvider.class)
        .run(
            ctx -> {
              final var contributed = contributedChain(ctx);

              // Contributed chain matches the scoped path but not the global /v2/** path
              assertThat(contributed.matches(new MockHttpServletRequest("GET", SCOPED_V2)))
                  .as("contributed chain must match scoped path")
                  .isTrue();
              assertThat(contributed.matches(new MockHttpServletRequest("GET", GLOBAL_V2)))
                  .as("contributed chain must NOT match global /v2/** path")
                  .isFalse();

              // Unauthenticated request to the contributed path → 401 from the contributed chain
              final var proxy = new FilterChainProxy(List.of(contributed));
              final var response = new MockHttpServletResponse();
              proxy.doFilter(
                  new MockHttpServletRequest("GET", SCOPED_V2), response, new MockFilterChain());

              assertThat(response.getStatus())
                  .as("contributed chain must handle requests under its scoped base path (401)")
                  .isEqualTo(401);
            });
  }

  // ---------------------------------------------------------------------------
  // 4. Contributed chain accepts valid credentials
  // ---------------------------------------------------------------------------

  @Test
  void oneDescriptorContributedChainAcceptsValidCredentials() {
    basicRunner()
        .withUserConfiguration(SingleBasicDescriptorProvider.class)
        .run(
            ctx -> {
              final var encoder = ctx.getBean(PasswordEncoder.class);
              final var port = ctx.getBean(BasicAuthUserDetailsPort.class);
              Mockito.when(port.loadUser("alice"))
                  .thenReturn(new CamundaUserDetails("alice", encoder.encode("s3cret")));

              final var contributed = contributedChain(ctx);
              final var proxy = new FilterChainProxy(List.of(contributed));
              final var request = new MockHttpServletRequest("GET", SCOPED_V2);
              request.addHeader("Authorization", basicHeader("alice", "s3cret"));
              final var response = new MockHttpServletResponse();
              final var next = new MockFilterChain();

              proxy.doFilter(request, response, next);

              assertThat(next.getRequest())
                  .as("authenticated request must pass through the contributed chain")
                  .isNotNull();
              assertThat(response.getStatus()).isEqualTo(200);
            });
  }

  // ---------------------------------------------------------------------------
  // 5. Ordering: contributed chain sorts before the catch-all deny chain
  // ---------------------------------------------------------------------------

  @Test
  void contributedChainOrderedBeforeCatchAll() {
    // Contributed chains reuse ORDER_WEBAPP_API and must sort before the ORDER_UNHANDLED catch-all.
    basicRunner()
        .withUserConfiguration(SingleBasicDescriptorProvider.class)
        .run(
            ctx -> {
              final var contributed = contributedChain(ctx);
              assertThat(contributed.getOrder())
                  .as(
                      "contributed chain order must equal ORDER_WEBAPP_API (%d) and sort before"
                          + " ORDER_UNHANDLED (%d)",
                      CamundaSecurityFilterChainConstants.ORDER_WEBAPP_API,
                      CamundaSecurityFilterChainConstants.ORDER_UNHANDLED)
                  .isEqualTo(CamundaSecurityFilterChainConstants.ORDER_WEBAPP_API)
                  .isLessThan(CamundaSecurityFilterChainConstants.ORDER_UNHANDLED);
            });
  }

  // ---------------------------------------------------------------------------
  // 6. End-to-end ordering: contributed chain before catch-all in real FilterChainProxy
  // ---------------------------------------------------------------------------

  @Test
  void contributedChainHandledBeforeCatchAllInRealProxy() throws Exception {
    // Uses the real FilterChainProxy assembled by Spring Security from ALL SecurityFilterChain
    // beans — including the catch-all deny chain (ORDER_UNHANDLED) from BaseSecurityConfiguration.
    // A regression where the contributed chain sorts BEHIND the catch-all would produce 404
    // (deny-all sends SC_NOT_FOUND); 401 proves the contributed BASIC chain wins first.
    basicRunner()
        .withUserConfiguration(SingleBasicDescriptorProvider.class)
        .run(
            ctx -> {
              // Spring Security registers the FilterChainProxy under this well-known name.
              final var proxy = ctx.getBean("springSecurityFilterChain", FilterChainProxy.class);

              final var request = new MockHttpServletRequest("GET", SCOPED_V2);
              final var response = new MockHttpServletResponse();

              proxy.doFilter(request, response, new MockFilterChain());

              assertThat(response.getStatus())
                  .as(
                      "request to contributed-chain path must yield 401 (BASIC challenge) "
                          + "not 404 (catch-all deny), proving contributed chain sorts first")
                  .isNotEqualTo(404)
                  .isEqualTo(401);
            });
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  /**
   * Retrieves the single contributed {@link OrderedSecurityFilterChainWrapper} from the context.
   */
  private static OrderedSecurityFilterChainWrapper contributedChain(
      final org.springframework.context.ApplicationContext ctx) {
    final var wrappers =
        ctx.getBeansOfType(SecurityFilterChain.class).values().stream()
            .filter(c -> c instanceof OrderedSecurityFilterChainWrapper)
            .map(c -> (OrderedSecurityFilterChainWrapper) c)
            .toList();
    assertThat(wrappers).as("exactly one contributed chain expected").hasSize(1);
    return wrappers.getFirst();
  }

  private static String basicHeader(final String username, final String password) {
    final var token = (username + ":" + password).getBytes(StandardCharsets.UTF_8);
    return "Basic " + Base64.getEncoder().encodeToString(token);
  }

  // ---------------------------------------------------------------------------
  // Inner configuration / SPI stubs
  // ---------------------------------------------------------------------------

  // ---------------------------------------------------------------------------
  // 7. Duplicate basePath guard
  // ---------------------------------------------------------------------------

  @Test
  void duplicateBasePathFailsContextStartup() {
    basicRunner()
        .withUserConfiguration(DuplicateBasePathProvider.class)
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(ctx.getStartupFailure())
                  .isInstanceOf(IllegalStateException.class)
                  .hasMessageContaining("Duplicate scope basePath")
                  .hasMessageContaining(SCOPED_BASE);
            });
  }

  // ---------------------------------------------------------------------------
  // 8. Trailing-slash variant is treated as duplicate after normalization
  // ---------------------------------------------------------------------------

  @Test
  void trailingSlashVariantIsDetectedAsDuplicate() {
    basicRunner()
        .withUserConfiguration(TrailingSlashDuplicateBasePathProvider.class)
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(ctx.getStartupFailure())
                  .isInstanceOf(IllegalStateException.class)
                  .hasMessageContaining("Duplicate scope basePath")
                  .hasMessageContaining(SCOPED_BASE);
            });
  }

  // ---------------------------------------------------------------------------
  // 9. OIDC scoped chain works in BASIC global mode (per-scope-method agnosticism)
  // ---------------------------------------------------------------------------

  /**
   * Proves that a host can contribute an OIDC-scoped descriptor even when the cluster's global
   * authentication method is {@code basic}. {@link ScopedOidcInfrastructureConfiguration} provides
   * the per-scope OIDC factories unconditionally, so {@link
   * io.camunda.security.spring.oidc.ScopedJwtDecoderFactory} is present regardless of the global
   * method.
   *
   * <p>The test runs with {@code camunda.security.authentication.method=basic} (no OIDC global
   * mode) but contributes a descriptor whose auth method is OIDC with a local JWKS server. A valid
   * token signed by the scope's issuer passes; a token with an unregistered issuer yields 401.
   */
  @Test
  void oidcDescriptorUnderBasicGlobalModeBuildsSuccessfullyAndAuthenticatesCorrectly()
      throws Exception {
    final var server = OidcTestServer.startRsa("scope-key");
    try {
      final var oidcConfig = server.oidcConfiguration("scope-client");
      final var auth = new AuthenticationConfiguration();
      auth.setMethod(AuthenticationMethod.OIDC);
      auth.setOidc(oidcConfig);

      // Valid JWT signed by the scope's own JWKS server
      final var validToken = server.sign(server.issuerUri());
      // JWT claiming a different issuer — should be rejected by the scope's decoder
      final var wrongIssuerToken = server.sign("https://unregistered-idp.example.com");

      final var descriptor = new ScopedSecurityDescriptor(SCOPED_BASE, auth);
      final CamundaSecurityScopeProvider scopeProvider = () -> List.of(descriptor);

      // No manual ScopedOidcInfrastructureConfiguration import: the collector @Imports it, so the
      // ScopedJwtDecoderFactory must be present here even though the global method is basic.
      basicRunner()
          .withBean(CamundaSecurityScopeProvider.class, () -> scopeProvider)
          .run(
              ctx -> {
                assertThat(ctx)
                    .as(
                        "context must start successfully: ScopedJwtDecoderFactory must be present"
                            + " even in global basic mode")
                    .hasNotFailed();

                final var contributed = contributedChain(ctx);
                final var proxy = new FilterChainProxy(List.of(contributed));

                // Valid token → passes through (not 401)
                final var validReq = new MockHttpServletRequest("GET", SCOPED_V2);
                validReq.addHeader("Authorization", "Bearer " + validToken);
                final var validResp = new MockHttpServletResponse();
                final var next = new MockFilterChain();
                proxy.doFilter(validReq, validResp, next);
                assertThat(validResp.getStatus())
                    .as("valid scope token must be accepted (not 401)")
                    .isNotEqualTo(401);

                // Wrong issuer → 401
                final var wrongProxy = new FilterChainProxy(List.of(contributed));
                final var wrongReq = new MockHttpServletRequest("GET", SCOPED_V2);
                wrongReq.addHeader("Authorization", "Bearer " + wrongIssuerToken);
                final var wrongResp = new MockHttpServletResponse();
                wrongProxy.doFilter(wrongReq, wrongResp, new MockFilterChain());
                assertThat(wrongResp.getStatus())
                    .as("token from unregistered issuer must be rejected with 401")
                    .isEqualTo(401);
              });
    } finally {
      server.stop();
    }
  }

  // ---------------------------------------------------------------------------
  // 10. unprotected-api=true: scoped chain is permit-all (mirrors primary unprotected chain)
  // ---------------------------------------------------------------------------

  @Test
  void unprotectedApiTrueMakesContributedScopedChainPermitAll() throws Exception {
    // With unprotected-api=true an unauthenticated request to the scoped API path must pass
    // through (200), not be challenged (401) — the scoped chain mirrors UnprotectedApiSecurity.
    basicRunner()
        .withUserConfiguration(SingleBasicDescriptorProvider.class)
        .withPropertyValues("camunda.security.authentication.unprotected-api=true")
        .run(
            ctx -> {
              final var contributed = contributedChain(ctx);
              final var proxy = new FilterChainProxy(List.of(contributed));
              final var request = new MockHttpServletRequest("GET", SCOPED_V2);
              final var response = new MockHttpServletResponse();
              final var next = new MockFilterChain();

              proxy.doFilter(request, response, next);

              assertThat(next.getRequest())
                  .as(
                      "unauthenticated request to scoped path must pass through when"
                          + " unprotected-api=true")
                  .isNotNull();
              assertThat(response.getStatus())
                  .as("response status must be 200 (permit-all), not 401 (challenged)")
                  .isEqualTo(200);
            });
  }

  /**
   * Provides two descriptors whose basePaths differ only by a trailing slash — normalized they are
   * identical and must be rejected at startup.
   */
  @Configuration
  static class TrailingSlashDuplicateBasePathProvider {

    @Bean
    static CamundaSecurityScopeProvider trailingSlashDuplicateScopeProvider() {
      final var auth = new AuthenticationConfiguration();
      auth.setMethod(AuthenticationMethod.BASIC);
      return () ->
          List.of(
              new ScopedSecurityDescriptor(SCOPED_BASE, auth),
              new ScopedSecurityDescriptor(SCOPED_BASE + "/", auth));
    }
  }

  /** Provides two descriptors with the same basePath — must be rejected at startup. */
  @Configuration
  static class DuplicateBasePathProvider {

    @Bean
    static CamundaSecurityScopeProvider duplicateScopeProvider() {
      final var auth = new AuthenticationConfiguration();
      auth.setMethod(AuthenticationMethod.BASIC);
      return () ->
          List.of(
              new ScopedSecurityDescriptor(SCOPED_BASE, auth),
              new ScopedSecurityDescriptor(SCOPED_BASE, auth));
    }
  }

  /** Provides a single BASIC-auth descriptor for {@code /example-scope/s1}. */
  @Configuration
  static class SingleBasicDescriptorProvider {

    @Bean
    static CamundaSecurityScopeProvider singleScopeProvider() {
      final var auth = new AuthenticationConfiguration();
      auth.setMethod(AuthenticationMethod.BASIC);
      return () -> List.of(new ScopedSecurityDescriptor(SCOPED_BASE, auth));
    }
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
  static class StubUserDetailsPort {

    @Bean
    BasicAuthUserDetailsPort userDetailsPort() {
      return Mockito.mock(BasicAuthUserDetailsPort.class);
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
