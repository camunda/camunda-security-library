# Wire OidcAuthenticationEntryPoint SPI into ScopedWebappSecurityChainBuilder Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a host application override the `AuthenticationEntryPoint` used on OIDC webapp chains by registering an `OidcAuthenticationEntryPoint` bean, instead of always getting CSL's built-in `oidcWebappAuthenticationEntryPoint(...)` default.

**Architecture:** `OidcAuthenticationEntryPoint` (marker SPI extending `AuthenticationEntryPoint`) already exists in `io.camunda.security.spring.spi`. `ScopedWebappSecurityChainBuilder` currently builds its OIDC entry point inline via the static `oidcWebappAuthenticationEntryPoint(...)` helper at two call sites (the primary/non-scoped `buildOidcWebappChain` and the per-scope `buildOidcWebappChainInternal`). This plan threads an `ObjectProvider<OidcAuthenticationEntryPoint>` through the constructor — exactly the pattern already used for `HttpsRedirectCustomizer` (see `HttpsRedirectCustomizer` field/constructor param and `ScopedWebappSecurityChainBuilderConfiguration`) — and at each call site prefers the adopter-supplied bean over the built-in default.

**Tech Stack:** Java 21, Spring Boot 4, Spring Security, JUnit 5, AssertJ, `WebApplicationContextRunner`.

## Global Constraints

- Follow the exact `ObjectProvider` wiring pattern used for `httpsRedirectCustomizers` in `ScopedWebappSecurityChainBuilder` (field + constructor param, threaded straight through `ScopedWebappSecurityChainBuilderConfiguration` with no eager `.getIfAvailable(...)` default at bean-construction time).
- Every library-supplied default bean keeps `@ConditionalOnMissingBean` — no change needed here since `OidcAuthenticationEntryPointConfiguration` already provides that pattern for a *different* consumer; this plan does not touch that file.
- Both call sites that currently call `oidcWebappAuthenticationEntryPoint(...)` inline (`buildOidcWebappChain` and `buildOidcWebappChainInternal`) must honor the SPI — leaving one wired and the other not would make primary and scoped OIDC chains behave inconsistently for the same host configuration.
- Do not change the existing bearer-vs-browser behavior when no `OidcAuthenticationEntryPoint` bean is registered: `shouldReturn401ForBearerTokenRequests` (`ScopedWebappSecurityChainBuilderScopedTest`) and `bearerTokenOnProtectedWebappPathIsRejectedWith401` / `browserNavigationToProtectedWebappPathStillRedirectsToIdp` (`OidcWebappBearerTokenRejectedTest`) must keep passing unmodified.
- No new module/port/adapter/SPI is introduced (the SPI already exists) and no project-wide convention changes — per `docs/workflows/adr.md`, this is plumbing wiring an existing SPI into an existing builder, so **no new ADR is required**.
- Run `mvn verify` before considering the plan complete — clean run, `BUILD SUCCESS`.

---

### Task 1: Wire the SPI into `ScopedWebappSecurityChainBuilder` (scoped chain) and its configuration

**Files:**
- Modify: `spring-boot-starter/src/main/java/io/camunda/security/spring/security/ScopedWebappSecurityChainBuilder.java`
- Modify: `spring-boot-starter/src/main/java/io/camunda/security/spring/security/ScopedWebappSecurityChainBuilderConfiguration.java`
- Test: `spring-boot-starter/src/test/java/io/camunda/security/spring/security/ScopedWebappSecurityChainBuilderScopedTest.java`

**Interfaces:**
- Consumes: `io.camunda.security.spring.spi.OidcAuthenticationEntryPoint` (existing marker interface extending `org.springframework.security.web.AuthenticationEntryPoint`, no methods of its own).
- Produces: `ScopedWebappSecurityChainBuilder` constructor gains a new final trailing parameter `final ObjectProvider<OidcAuthenticationEntryPoint> oidcAuthenticationEntryPointProvider`. `buildOidcWebappChainInternal`'s exception-handling entry point now prefers a registered `OidcAuthenticationEntryPoint` bean over the static default. Later tasks (Task 2) reuse this same field for the primary chain's call site.

- [ ] **Step 1: Write the failing test — scoped chain uses a host-registered `OidcAuthenticationEntryPoint` instead of the default redirect**

Add this test method and the supporting `@Configuration` class to `ScopedWebappSecurityChainBuilderScopedTest.java`. Insert the test method after `shouldReturn401ForBearerTokenRequests` (after line 155, before `sessionRepositoryFilterIsInstalledBeforeSecurityContextHolderFilter`):

```java
  @Test
  void scopedChainUsesHostRegisteredOidcAuthenticationEntryPointWhenPresent() throws Exception {
    new WebApplicationContextRunner()
        .withUserConfiguration(
            ObjectMapperConfig.class,
            StubPaths.class,
            ScopedSingleIdpConfig.class,
            HostOidcAuthenticationEntryPointConfig.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                BaseSecurityConfiguration.class,
                AuthFailureHandlerConfiguration.class,
                ScopedOidcInfrastructureConfiguration.class,
                ScopedWebappSecurityChainBuilderConfiguration.class))
        .run(
            ctx -> {
              final var chain = ctx.getBean("scopedOidcTestChain", SecurityFilterChain.class);
              final var proxy = new FilterChainProxy(List.of(chain));
              final var request =
                  new MockHttpServletRequest("GET", BASE_PATH + "/operate/dashboard");
              final var response = new MockHttpServletResponse();

              proxy.doFilter(request, response, new MockFilterChain());

              assertThat(response.getStatus())
                  .as("host-registered entry point must handle the unauthenticated request")
                  .isEqualTo(HostOidcAuthenticationEntryPointConfig.STUB_STATUS);
            });
  }
```

Add the supporting configuration class alongside the other `@Configuration` classes at the bottom of the file (e.g. directly after `StubPathsWithOidcEndpoints`, before `ScopedBasicConfig`):

```java
  @Configuration
  static class HostOidcAuthenticationEntryPointConfig {

    static final int STUB_STATUS = 599;

    @Bean
    io.camunda.security.spring.spi.OidcAuthenticationEntryPoint oidcAuthenticationEntryPoint() {
      return (request, response, authException) -> response.setStatus(STUB_STATUS);
    }
  }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `mvn test -pl spring-boot-starter -Dtest=ScopedWebappSecurityChainBuilderScopedTest#scopedChainUsesHostRegisteredOidcAuthenticationEntryPointWhenPresent`

Expected: FAIL — `response.getStatus()` is `302` (the default redirect), not `599`, because the host bean is registered but not yet consumed by the builder.

- [ ] **Step 3: Add the field, constructor parameter, and import to `ScopedWebappSecurityChainBuilder`**

Add the import after the existing `io.camunda.security.spring.scope.OAuth2AuthorizedClientManagerFactory` import (line 30):

```java
import io.camunda.security.spring.spi.OidcAuthenticationEntryPoint;
```

Add the field directly after the existing `httpsRedirectCustomizers` field (line 97):

```java
  private final ObjectProvider<HttpsRedirectCustomizer> httpsRedirectCustomizers;
  private final ObjectProvider<OidcAuthenticationEntryPoint> oidcAuthenticationEntryPointProvider;
```

Add the constructor parameter as the new trailing parameter (after `httpsRedirectCustomizers` at line 113), and assign it in the constructor body (after line 127):

```java
  public ScopedWebappSecurityChainBuilder(
      final AuthFailureHandler authFailureHandler,
      final CamundaSecurityLibraryProperties properties,
      final SecurityPathPort pathPort,
      final ObjectProvider<OidcTokenEndpointCustomizer> tokenEndpointCustomizerProvider,
      final ObjectProvider<LogoutSuccessHandler> logoutSuccessHandlerProvider,
      final ObjectProvider<OidcUserService> oidcUserServiceProvider,
      final ObjectProvider<OAuth2AuthorizationRequestResolver> authorizationRequestResolverProvider,
      final ObjectProvider<WebAppAuthorizationCheckFilter> webAppAuthorizationFilterProvider,
      final ObjectProvider<DefaultLoginPageGeneratingFilter> oidcLoginPickerProvider,
      final ObjectProvider<AdminUserCheckFilter> adminUserCheckFilterProvider,
      final OAuth2AuthorizedClientManagerFactory authorizedClientManagerFactory,
      final ScopedClientRegistrationFactory scopedClientRegistrationFactory,
      final CorsConfigurationSource corsSource,
      final ObjectProvider<HttpsRedirectCustomizer> httpsRedirectCustomizers,
      final ObjectProvider<OidcAuthenticationEntryPoint> oidcAuthenticationEntryPointProvider) {
    this.authFailureHandler = authFailureHandler;
    this.properties = properties;
    this.pathPort = pathPort;
    this.tokenEndpointCustomizerProvider = tokenEndpointCustomizerProvider;
    this.logoutSuccessHandlerProvider = logoutSuccessHandlerProvider;
    this.oidcUserServiceProvider = oidcUserServiceProvider;
    this.authorizationRequestResolverProvider = authorizationRequestResolverProvider;
    this.webAppAuthorizationFilterProvider = webAppAuthorizationFilterProvider;
    this.oidcLoginPickerProvider = oidcLoginPickerProvider;
    this.adminUserCheckFilterProvider = adminUserCheckFilterProvider;
    this.authorizedClientManagerFactory = authorizedClientManagerFactory;
    this.scopedClientRegistrationFactory = scopedClientRegistrationFactory;
    this.corsSource = corsSource;
    this.httpsRedirectCustomizers = httpsRedirectCustomizers;
    this.oidcAuthenticationEntryPointProvider = oidcAuthenticationEntryPointProvider;
  }
```

- [ ] **Step 4: Consume the provider in `buildOidcWebappChainInternal`**

Replace the `exceptionHandling` block in `buildOidcWebappChainInternal` (currently lines 501–506):

```java
            .exceptionHandling(
                eh ->
                    eh.authenticationEntryPoint(
                            oidcWebappAuthenticationEntryPoint(
                                clientRegistrationRepository, loginUrl, authorizationBaseUri))
                        .accessDeniedHandler(authFailureHandler))
```

with:

```java
            .exceptionHandling(
                eh ->
                    eh.authenticationEntryPoint(
                            resolveOidcAuthenticationEntryPoint(
                                clientRegistrationRepository, loginUrl, authorizationBaseUri))
                        .accessDeniedHandler(authFailureHandler))
```

Add the new private helper method right after the existing `oidcWebappAuthenticationEntryPoint(...)` overloads (after line 413, before the `resolveOauthRedirectTarget` block at line 415):

```java
  /**
   * Prefers a host-registered {@link OidcAuthenticationEntryPoint} bean over the library default,
   * following the same "adopter hook with a built-in fallback" pattern as {@link
   * HttpsRedirectCustomizer}. {@code ObjectProvider.getIfAvailable(Supplier)} can't be used directly
   * here because the fallback factory returns {@link AuthenticationEntryPoint}, not the narrower
   * {@link OidcAuthenticationEntryPoint} type the provider is parameterized on.
   *
   * <p><b>Note:</b> this adopts <em>any</em> {@link OidcAuthenticationEntryPoint} bean in context,
   * including {@link OidcAuthenticationEntryPointConfiguration}'s own library-supplied default (used
   * today only by {@code JwtCookieAuthenticationFilter}, and not currently imported by any active
   * chain — see that class's Javadoc). That default is a plain redirect with no bearer-vs-browser
   * distinction; co-importing {@link OidcAuthenticationEntryPointConfiguration} alongside this
   * builder replaces the bearer-aware {@code DelegatingAuthenticationEntryPoint} fallback below and
   * changes bearer-token requests from 401 to a redirect. This is a known, intentional consequence
   * of adopting the SPI wholesale (matching how {@code JwtCookieAuthenticationFilter} already treats
   * the same bean) — see {@code
   * scopedChainAdoptsLibraryDefaultOidcEntryPointWhenBothConfigurationsArePresent} for the
   * characterization test pinning this behavior so a future change to precedence is made
   * deliberately, not accidentally.
   */
  private AuthenticationEntryPoint resolveOidcAuthenticationEntryPoint(
      final ClientRegistrationRepository clientRegistrationRepository,
      final String loginUrl,
      final String authorizationBaseUri) {
    final var hostEntryPoint = oidcAuthenticationEntryPointProvider.getIfAvailable();
    return hostEntryPoint != null
        ? hostEntryPoint
        : oidcWebappAuthenticationEntryPoint(
            clientRegistrationRepository, loginUrl, authorizationBaseUri);
  }
```

- [ ] **Step 5: Update `ScopedWebappSecurityChainBuilderConfiguration` to thread the new provider through**

In `spring-boot-starter/src/main/java/io/camunda/security/spring/security/ScopedWebappSecurityChainBuilderConfiguration.java`, add the import after `io.camunda.security.spring.scope.OAuth2AuthorizedClientManagerFactory` (line 18):

```java
import io.camunda.security.spring.spi.OidcAuthenticationEntryPoint;
```

Add a new trailing parameter to the `scopedWebappSecurityChainBuilder` bean method (after `httpsRedirectCustomizers` at line 61) and pass it through to the constructor call (after line 76):

```java
  @Bean
  @ConditionalOnMissingBean
  public ScopedWebappSecurityChainBuilder scopedWebappSecurityChainBuilder(
      final AuthFailureHandler authFailureHandler,
      final CamundaSecurityLibraryProperties properties,
      final SecurityPathPort pathPort,
      final ObjectProvider<OidcTokenEndpointCustomizer> tokenEndpointCustomizerProvider,
      final ObjectProvider<LogoutSuccessHandler> logoutSuccessHandlerProvider,
      final ObjectProvider<OidcUserService> oidcUserServiceProvider,
      final ObjectProvider<OAuth2AuthorizationRequestResolver> authorizationRequestResolverProvider,
      final ObjectProvider<WebAppAuthorizationCheckFilter> webAppAuthorizationFilterProvider,
      final ObjectProvider<DefaultLoginPageGeneratingFilter> oidcLoginPickerProvider,
      final ObjectProvider<AdminUserCheckFilter> adminUserCheckFilterProvider,
      final OAuth2AuthorizedClientManagerFactory authorizedClientManagerFactory,
      final ScopedClientRegistrationFactory scopedClientRegistrationFactory,
      final ObjectProvider<CorsConfigurationSource> corsSourceProvider,
      final ObjectProvider<HttpsRedirectCustomizer> httpsRedirectCustomizers,
      final ObjectProvider<OidcAuthenticationEntryPoint> oidcAuthenticationEntryPointProvider) {
    return new ScopedWebappSecurityChainBuilder(
        authFailureHandler,
        properties,
        pathPort,
        tokenEndpointCustomizerProvider,
        logoutSuccessHandlerProvider,
        oidcUserServiceProvider,
        authorizationRequestResolverProvider,
        webAppAuthorizationFilterProvider,
        oidcLoginPickerProvider,
        adminUserCheckFilterProvider,
        authorizedClientManagerFactory,
        scopedClientRegistrationFactory,
        corsSourceProvider.getIfAvailable(NoOpCorsConfigurationSource::new),
        httpsRedirectCustomizers,
        oidcAuthenticationEntryPointProvider);
  }
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `mvn test -pl spring-boot-starter -Dtest=ScopedWebappSecurityChainBuilderScopedTest#scopedChainUsesHostRegisteredOidcAuthenticationEntryPointWhenPresent`

Expected: PASS

- [ ] **Step 7: Run the full test class to confirm no regressions, especially the bearer-token default-fallback test**

Run: `mvn test -pl spring-boot-starter -Dtest=ScopedWebappSecurityChainBuilderScopedTest`

Expected: PASS — all tests in the class green, including `shouldReturn401ForBearerTokenRequests` and `anonymousRequestToProtectedScopedPathRedirectsToLogin` (both exercise the no-host-bean default path, unaffected by this change).

- [ ] **Step 8: Write a characterization test pinning the co-import interaction with `OidcAuthenticationEntryPointConfiguration`**

`resolveOidcAuthenticationEntryPoint` cannot distinguish "a host registered `OidcAuthenticationEntryPoint`" from "CSL's own `OidcAuthenticationEntryPointConfiguration` default bean got imported into the same context" — both are just an `OidcAuthenticationEntryPoint` bean. That default bean is a plain redirect with no bearer/browser distinction, so if it is ever co-imported with the scoped builder, bearer-token requests stop getting 401 and get redirected instead. This is intentional (adopting the SPI wholesale, same as `JwtCookieAuthenticationFilter` already does) but easy to trip over by accident in future wiring changes, so pin it explicitly.

Add this test to `ScopedWebappSecurityChainBuilderScopedTest.java`, directly after the test added in Step 1:

```java
  @Test
  void scopedChainAdoptsLibraryDefaultOidcEntryPointWhenBothConfigurationsArePresent()
      throws Exception {
    new WebApplicationContextRunner()
        .withUserConfiguration(ObjectMapperConfig.class, StubPaths.class, ScopedSingleIdpConfig.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                BaseSecurityConfiguration.class,
                AuthFailureHandlerConfiguration.class,
                ScopedOidcInfrastructureConfiguration.class,
                ScopedWebappSecurityChainBuilderConfiguration.class,
                OidcAuthenticationEntryPointConfiguration.class))
        .run(
            ctx -> {
              final var chain = ctx.getBean("scopedOidcTestChain", SecurityFilterChain.class);
              final var proxy = new FilterChainProxy(List.of(chain));
              final var request =
                  new MockHttpServletRequest("GET", BASE_PATH + "/operate/dashboard");
              request.addHeader("Authorization", "Bearer sometoken");
              final var response = new MockHttpServletResponse();

              proxy.doFilter(request, response, new MockFilterChain());

              // Documents current, intentional behavior: co-importing CSL's own
              // OidcAuthenticationEntryPointConfiguration default bean is adopted the same way a
              // host override would be, replacing the bearer-aware DelegatingAuthenticationEntryPoint
              // fallback. Bearer requests are therefore redirected (302), not rejected with 401, once
              // that configuration is present. If this assertion ever needs to change, update the
              // Javadoc on ScopedWebappSecurityChainBuilder#resolveOidcAuthenticationEntryPoint too.
              assertThat(response.getStatus())
                  .as(
                      "co-importing OidcAuthenticationEntryPointConfiguration replaces the"
                          + " bearer-aware fallback, so bearer requests are redirected rather than"
                          + " rejected with 401")
                  .isEqualTo(302);
            });
  }
```

- [ ] **Step 9: Run the new characterization test**

Run: `mvn test -pl spring-boot-starter -Dtest=ScopedWebappSecurityChainBuilderScopedTest#scopedChainAdoptsLibraryDefaultOidcEntryPointWhenBothConfigurationsArePresent`

Expected: PASS — confirms the documented co-import behavior.

- [ ] **Step 10: Commit**

```bash
git add spring-boot-starter/src/main/java/io/camunda/security/spring/security/ScopedWebappSecurityChainBuilder.java \
        spring-boot-starter/src/main/java/io/camunda/security/spring/security/ScopedWebappSecurityChainBuilderConfiguration.java \
        spring-boot-starter/src/test/java/io/camunda/security/spring/security/ScopedWebappSecurityChainBuilderScopedTest.java
git commit -m "feat(webapp): honor OidcAuthenticationEntryPoint SPI on scoped OIDC chains"
```

---

### Task 2: Wire the same SPI provider into the primary (non-scoped) `buildOidcWebappChain`

**Files:**
- Modify: `spring-boot-starter/src/main/java/io/camunda/security/spring/security/ScopedWebappSecurityChainBuilder.java`
- Test: `spring-boot-starter/src/test/java/io/camunda/security/spring/security/OidcWebappBearerTokenRejectedTest.java`

**Interfaces:**
- Consumes: `oidcAuthenticationEntryPointProvider` field and `resolveOidcAuthenticationEntryPoint(...)` helper added in Task 1 (same class, so no signature to thread — the helper's 3-arg overload already covers this call site since `buildOidcWebappChain` also has an `authorizationBaseUri`-equivalent value of `"/oauth2/authorization"` baked into the 2-arg `oidcWebappAuthenticationEntryPoint` overload).
- Produces: nothing new consumed by later tasks — this is the last production-code task.

- [ ] **Step 1: Write the failing test — primary chain uses a host-registered `OidcAuthenticationEntryPoint`**

Add this test method to `OidcWebappBearerTokenRejectedTest.java`, after `browserNavigationToProtectedWebappPathStillRedirectsToIdp` (after line 140):

```java
  @Test
  void hostRegisteredOidcAuthenticationEntryPointIsUsedInsteadOfDefaultRedirect() throws Exception {
    new WebApplicationContextRunner()
        .withUserConfiguration(
            ObjectMapperConfig.class,
            StubPaths.class,
            SingleIdpClientRegistration.class,
            HostOidcAuthenticationEntryPointConfig.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                BaseSecurityConfiguration.class,
                OidcWebappSecurityConfiguration.class,
                ScopedWebappSecurityChainBuilderConfiguration.class,
                AuthFailureHandlerConfiguration.class,
                OidcBeansConfiguration.class,
                ScopedOidcInfrastructureConfiguration.class))
        .withPropertyValues(OIDC_PROPERTIES)
        .run(
            ctx -> {
              final var chain = ctx.getBean(OIDC_CHAIN_BEAN, SecurityFilterChain.class);
              final var proxy = new FilterChainProxy(List.of(chain));
              final var request = new MockHttpServletRequest("GET", "/operate/dashboard");
              final var response = new MockHttpServletResponse();

              proxy.doFilter(request, response, new MockFilterChain());

              assertThat(response.getStatus())
                  .as("host-registered entry point must handle the unauthenticated request")
                  .isEqualTo(HostOidcAuthenticationEntryPointConfig.STUB_STATUS);
              assertThat(response.getRedirectedUrl())
                  .as("host entry point replaces the default IdP redirect")
                  .isNull();
            });
  }

  @Configuration
  static class HostOidcAuthenticationEntryPointConfig {

    static final int STUB_STATUS = 598;

    @Bean
    io.camunda.security.spring.spi.OidcAuthenticationEntryPoint oidcAuthenticationEntryPoint() {
      return (request, response, authException) -> response.setStatus(STUB_STATUS);
    }
  }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `mvn test -pl spring-boot-starter -Dtest=OidcWebappBearerTokenRejectedTest#hostRegisteredOidcAuthenticationEntryPointIsUsedInsteadOfDefaultRedirect`

Expected: FAIL — `response.getStatus()` is `302` and `response.getRedirectedUrl()` is non-null, because `buildOidcWebappChain` still calls the static default directly.

- [ ] **Step 3: Consume the provider in `buildOidcWebappChain`**

In `ScopedWebappSecurityChainBuilder.java`, replace the `exceptionHandling` block in `buildOidcWebappChain` (currently lines 171–176):

```java
            .exceptionHandling(
                eh ->
                    eh.authenticationEntryPoint(
                            oidcWebappAuthenticationEntryPoint(
                                clientRegistrationRepository, loginUrl))
                        .accessDeniedHandler(authFailureHandler))
```

with:

```java
            .exceptionHandling(
                eh ->
                    eh.authenticationEntryPoint(
                            resolveOidcAuthenticationEntryPoint(
                                clientRegistrationRepository, loginUrl, "/oauth2/authorization"))
                        .accessDeniedHandler(authFailureHandler))
```

This reuses the exact 3-arg `resolveOidcAuthenticationEntryPoint(...)` helper added in Task 1 — `"/oauth2/authorization"` is the same literal the 2-arg `oidcWebappAuthenticationEntryPoint(...)` overload already delegates to internally (see lines 392–396), so behavior for the no-host-bean case is unchanged.

- [ ] **Step 4: Run the test to verify it passes**

Run: `mvn test -pl spring-boot-starter -Dtest=OidcWebappBearerTokenRejectedTest#hostRegisteredOidcAuthenticationEntryPointIsUsedInsteadOfDefaultRedirect`

Expected: PASS

- [ ] **Step 5: Run the full test class to confirm no regressions**

Run: `mvn test -pl spring-boot-starter -Dtest=OidcWebappBearerTokenRejectedTest`

Expected: PASS — all tests green, including `bearerTokenOnProtectedWebappPathIsRejectedWith401` and `browserNavigationToProtectedWebappPathStillRedirectsToIdp` (both exercise the no-host-bean default path).

- [ ] **Step 6: Commit**

```bash
git add spring-boot-starter/src/main/java/io/camunda/security/spring/security/ScopedWebappSecurityChainBuilder.java \
        spring-boot-starter/src/test/java/io/camunda/security/spring/security/OidcWebappBearerTokenRejectedTest.java
git commit -m "feat(webapp): honor OidcAuthenticationEntryPoint SPI on the primary OIDC webapp chain"
```

---

### Task 3: Full module verification

**Files:** none (verification only)

**Interfaces:** none

- [ ] **Step 1: Run the full spring-boot-starter test suite**

Run: `mvn test -pl spring-boot-starter`

Expected: `BUILD SUCCESS`, no failing tests.

- [ ] **Step 2: Run the full verification build**

Run: `mvn verify`

Expected: `BUILD SUCCESS`. This also runs Spotless formatting checks and ArchUnit boundary tests — confirm neither the new field/constructor param nor the new test configuration classes trip either.

- [ ] **Step 3: Note the PR description doc callout**

This change is user-visible to host-application operators embedding CSL (specifically Hub, per issue #528's stated purpose as a pre-activation gate for #308). Add this note verbatim to the PR description under a "Docs" heading — no camunda-docs page edit is needed yet because the SPI itself predates this change and was not previously documented as consumed by the webapp chain builder specifically; this PR only makes an existing extension point apply to a second call site:

> **Docs:** No camunda-docs update required. `OidcAuthenticationEntryPoint` was already a documented-in-code SPI (see its Javadoc); this change makes `ScopedWebappSecurityChainBuilder`'s primary and per-scope OIDC webapp chains honor a host-registered bean of that type, in addition to the existing consumer (`JwtCookieAuthenticationFilter`). No new configuration property or default behavior change for hosts that don't register the bean.

No commit needed for this step — it is a note for the PR description, not a file change.

---

## Self-Review

- **Spec coverage:** Issue asks for `ObjectProvider<OidcAuthenticationEntryPoint>` wired into constructor (Task 1, Step 3) and `buildOidcWebappChainInternal` (Task 1, Step 4) with fallback to the current default (Task 1, Step 4 helper) — covered. The primary `buildOidcWebappChain` call site is also wired (Task 2) to keep primary/scoped behavior consistent, flagged explicitly in Global Constraints as a deliberate scope decision beyond the issue's literal text.
- **Placeholder scan:** No TBD/TODO; every step has concrete code and exact file line anchors from the current source.
- **Type consistency:** `resolveOidcAuthenticationEntryPoint` is defined once in Task 1 and reused unchanged in Task 2 with matching signature `(ClientRegistrationRepository, String, String) -> AuthenticationEntryPoint`. Field name `oidcAuthenticationEntryPointProvider` and helper name match between the class body added in Task 1 and consumed in Task 2.
- **Opus plan review follow-up:** addressed the "should fix" finding that `resolveOidcAuthenticationEntryPoint` can't distinguish a host override from CSL's own (currently-unimported) `OidcAuthenticationEntryPointConfiguration` default bean — added a Javadoc note on the helper (Task 1, Step 4) and a characterization test (Task 1, Steps 8–9) pinning the co-import behavior so a future change to precedence is deliberate.
