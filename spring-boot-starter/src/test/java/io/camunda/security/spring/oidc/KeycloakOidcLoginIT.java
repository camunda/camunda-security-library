/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.security.BaseSecurityConfiguration;
import io.camunda.security.spring.security.OidcWebappSecurityConfiguration;
import io.camunda.security.spring.security.ScopedWebappSecurityChainBuilderConfiguration;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Redirect;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.assertj.AssertableWebApplicationContext;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

/**
 * The OIDC login of CSL against a real identity provider.
 *
 * <p>Keycloak enforces PKCE for the public client of its realm, and it refuses a token request that
 * carries no verifier or one that does not match the challenge. A login that completes here
 * therefore proves the complete exchange, and not only the parameters that CSL writes. The
 * confidential client of the second realm runs the same flow with a secret, in the same
 * configuration, so each provider follows its own type.
 *
 * <p>The test drives the real filter chain with mock requests and carries the session cookie from
 * one request to the next, as a browser does. A real HTTP client performs the two steps that belong
 * to the browser alone: the sign-in form of Keycloak, and its redirect back to the application.
 *
 * <p>This test needs Docker. {@code ./mvnw verify} runs it, and {@code ./mvnw verify -DskipITs}
 * leaves it out.
 */
@Testcontainers
class KeycloakOidcLoginIT {

  private static final String PUBLIC_REGISTRATION = "public-client";
  private static final String CONFIDENTIAL_REGISTRATION = "confidential-client";
  private static final String USERNAME = "alice";
  private static final String PASSWORD = "s3cret";
  private static final String CALLBACK_PATH = "/sso-callback";
  private static final String WEBAPP_PATH = "/operate/index.html";
  private static final String OIDC_CHAIN_BEAN = "oidcWebappSecurityFilterChain";
  private static final Pattern FORM_ACTION = Pattern.compile("action=\"([^\"]+)\"");

  @Container
  private static final GenericContainer<?> KEYCLOAK =
      new GenericContainer<>(DockerImageName.parse("quay.io/keycloak/keycloak:26.4"))
          .withExposedPorts(8080)
          .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
          .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
          .withCopyFileToContainer(
              MountableFile.forClasspathResource("keycloak/csl-public-realm.json"),
              "/opt/keycloak/data/import/csl-public-realm.json")
          .withCopyFileToContainer(
              MountableFile.forClasspathResource("keycloak/csl-confidential-realm.json"),
              "/opt/keycloak/data/import/csl-confidential-realm.json")
          .withCommand("start-dev", "--import-realm")
          .waitingFor(
              Wait.forHttp("/realms/csl-public/.well-known/openid-configuration")
                  .forPort(8080)
                  .forStatusCode(200)
                  .withStartupTimeout(Duration.ofMinutes(3)));

  @Test
  void shouldCompleteTheLoginOfAPublicClientWithPkce() {
    runner()
        .run(
            ctx -> {
              final var browser = new Browser(ctx);

              final var authorizationUrl = browser.startLogin(PUBLIC_REGISTRATION);

              assertThat(authorizationUrl)
                  .contains("client_id=csl-public")
                  .contains("code_challenge=")
                  .contains("code_challenge_method=S256");

              final var loggedIn = browser.signInAndReturn(authorizationUrl);

              assertThat(loggedIn.registrationId()).isEqualTo(PUBLIC_REGISTRATION);
              assertThat(loggedIn.authorizedClient().getAccessToken().getTokenValue()).isNotBlank();
              assertThat(loggedIn.authorizedClient().getRefreshToken()).isNotNull();
            });
  }

  @Test
  void shouldRefreshTheSessionOfAPublicClientWithoutAClientSecret() {
    runner()
        .run(
            ctx -> {
              final var browser = new Browser(ctx);
              final var loggedIn = browser.signInAndReturn(browser.startLogin(PUBLIC_REGISTRATION));

              final var refreshed = browser.refresh(loggedIn);

              assertThat(refreshed.getAccessToken().getTokenValue())
                  .isNotBlank()
                  .isNotEqualTo(loggedIn.authorizedClient().getAccessToken().getTokenValue());
            });
  }

  @Test
  void shouldRevokeTheRefreshTokenOfAPublicClientOnLogout() {
    runner()
        .run(
            ctx -> {
              final var browser = new Browser(ctx);
              final var loggedIn = browser.signInAndReturn(browser.startLogin(PUBLIC_REGISTRATION));
              final var refreshToken = loggedIn.authorizedClient().getRefreshToken();

              browser.logOut();

              assertThatExceptionOfType(OAuth2AuthorizationException.class)
                  .as("Keycloak still accepts a refresh token that logout revoked")
                  .isThrownBy(() -> exchange(loggedIn.authorizedClient(), refreshToken))
                  .extracting(failure -> failure.getError().getErrorCode())
                  .isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
            });
  }

  @Test
  void shouldCompleteTheLoginOfAConfidentialClientWithItsSecret() {
    runner()
        .run(
            ctx -> {
              final var browser = new Browser(ctx);

              final var authorizationUrl = browser.startLogin(CONFIDENTIAL_REGISTRATION);
              final var loggedIn = browser.signInAndReturn(authorizationUrl);

              assertThat(authorizationUrl).contains("client_id=csl-confidential");
              assertThat(loggedIn.registrationId()).isEqualTo(CONFIDENTIAL_REGISTRATION);
              assertThat(loggedIn.authorizedClient().getClientRegistration().getClientSecret())
                  .isEqualTo("csl-confidential-secret");
              assertThat(loggedIn.authorizedClient().getAccessToken().getTokenValue()).isNotBlank();
            });
  }

  /**
   * The state the refresh filter acts on: the access token has expired and the refresh token is the
   * live one of the session. A manager declines to refresh a token that is still valid.
   */
  private static OAuth2AuthorizedClient expired(final OAuth2AuthorizedClient authorizedClient) {
    return new OAuth2AuthorizedClient(
        authorizedClient.getClientRegistration(),
        authorizedClient.getPrincipalName(),
        new OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            authorizedClient.getAccessToken().getTokenValue(),
            Instant.now().minus(2, ChronoUnit.HOURS),
            Instant.now().minus(1, ChronoUnit.HOURS)),
        authorizedClient.getRefreshToken());
  }

  /** Asks Keycloak for a new access token, which a revoked refresh token cannot buy. */
  private static void exchange(
      final OAuth2AuthorizedClient authorizedClient, final OAuth2RefreshToken refreshToken) {
    new RestClientRefreshTokenTokenResponseClient()
        .getTokenResponse(
            new OAuth2RefreshTokenGrantRequest(
                authorizedClient.getClientRegistration(),
                authorizedClient.getAccessToken(),
                refreshToken));
  }

  private static Authentication authentication(final HttpServletRequest request) {
    final var context =
        (SecurityContext)
            request
                .getSession()
                .getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
    assertThat(context).as("the session holds no security context").isNotNull();
    return context.getAuthentication();
  }

  /** The cookies a browser would hold next, with the ones the application deleted left out. */
  private static Cookie[] merge(final Cookie[] held, final Cookie[] fromResponse) {
    final Map<String, Cookie> byName = new LinkedHashMap<>();
    Arrays.stream(held).forEach(cookie -> byName.put(cookie.getName(), cookie));
    for (final var cookie : fromResponse) {
      if (cookie.getMaxAge() == 0) {
        byName.remove(cookie.getName());
      } else {
        byName.put(cookie.getName(), cookie);
      }
    }
    return byName.values().toArray(new Cookie[0]);
  }

  private static URI signInAtKeycloak(final String authorizationUrl) throws Exception {
    final var http =
        HttpClient.newBuilder()
            .followRedirects(Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    final var loginPage =
        http.send(
            HttpRequest.newBuilder(URI.create(authorizationUrl)).GET().build(),
            BodyHandlers.ofString());
    assertThat(loginPage.statusCode()).as("Keycloak served no login page").isEqualTo(200);

    final var form =
        "username="
            + URLEncoder.encode(USERNAME, UTF_8)
            + "&password="
            + URLEncoder.encode(PASSWORD, UTF_8)
            + "&credentialId=";
    final var submitted =
        http.send(
            HttpRequest.newBuilder(URI.create(loginFormAction(loginPage.body())))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", cookiesOf(loginPage))
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build(),
            BodyHandlers.ofString());

    assertThat(submitted.statusCode())
        .as("Keycloak did not sign the user in: %s", submitted.body())
        .isEqualTo(302);
    return URI.create(submitted.headers().firstValue("Location").orElseThrow());
  }

  /**
   * The cookies of a response, as a request header. Keycloak keeps the state of a login in them,
   * and the {@code CookieManager} of the JDK stores no cookie of a host name without a dot.
   */
  private static String cookiesOf(final HttpResponse<String> response) {
    return response.headers().allValues("set-cookie").stream()
        .map(header -> header.split(";", 2)[0])
        .collect(Collectors.joining("; "));
  }

  private static String loginFormAction(final String html) {
    final var matcher = FORM_ACTION.matcher(html);
    assertThat(matcher.find()).as("no form on the Keycloak login page").isTrue();
    return matcher.group(1).replace("&amp;", "&");
  }

  private static Map<String, String> queryParameters(final URI uri) {
    return Arrays.stream(uri.getRawQuery().split("&"))
        .map(pair -> pair.split("=", 2))
        .collect(
            Collectors.toMap(
                pair -> URLDecoder.decode(pair[0], UTF_8),
                pair -> pair.length > 1 ? URLDecoder.decode(pair[1], UTF_8) : ""));
  }

  private WebApplicationContextRunner runner() {
    return new WebApplicationContextRunner()
        .withUserConfiguration(ObjectMapperConfig.class, StubPaths.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                BaseSecurityConfiguration.class,
                OidcWebappSecurityConfiguration.class,
                ScopedWebappSecurityChainBuilderConfiguration.class,
                AuthFailureHandlerConfiguration.class,
                OidcBeansConfiguration.class,
                OidcWebappClientBeansConfiguration.class,
                ScopedOidcInfrastructureConfiguration.class))
        .withPropertyValues(oidcProperties());
  }

  private static String[] oidcProperties() {
    final var publicProvider =
        "camunda.security.authentication.providers.oidc." + PUBLIC_REGISTRATION + ".";
    final var confidentialProvider =
        "camunda.security.authentication.providers.oidc." + CONFIDENTIAL_REGISTRATION + ".";
    return new String[] {
      "camunda.security.authentication.method=oidc",
      "camunda.security.csrf.enabled=false",
      publicProvider + "type=public",
      publicProvider + "client-id=csl-public",
      publicProvider + "issuer-uri=" + realmUrl("csl-public"),
      publicProvider + "redirect-uri={baseUrl}" + CALLBACK_PATH,
      confidentialProvider + "type=confidential",
      confidentialProvider + "client-id=csl-confidential",
      confidentialProvider + "client-secret=csl-confidential-secret",
      confidentialProvider + "issuer-uri=" + realmUrl("csl-confidential"),
      confidentialProvider + "redirect-uri={baseUrl}" + CALLBACK_PATH
    };
  }

  private static String keycloakBaseUrl() {
    return "http://" + KEYCLOAK.getHost() + ":" + KEYCLOAK.getMappedPort(8080);
  }

  private static String realmUrl(final String realm) {
    return keycloakBaseUrl() + "/realms/" + realm;
  }

  /** What one login produced: the session of the user, and the client that holds their tokens. */
  private record LoggedIn(
      String registrationId, OAuth2AuthorizedClient authorizedClient, HttpServletRequest request) {}

  /**
   * One user agent against the application: it keeps the session cookie across requests, which is
   * what ties the authorization request, the callback and the session together.
   */
  private final class Browser {

    private final FilterChainProxy chain;
    private Cookie[] cookies = new Cookie[0];

    private Browser(final AssertableWebApplicationContext ctx) {
      assertThat(ctx).hasNotFailed();
      chain =
          new FilterChainProxy(List.of(ctx.getBean(OIDC_CHAIN_BEAN, SecurityFilterChain.class)));
    }

    /** Asks the application to log in, and returns where it sends the user. */
    private String startLogin(final String registrationId) throws Exception {
      final var response =
          send(request("GET", "/oauth2/authorization/" + registrationId), new MockFilterChain());

      assertThat(response.getStatus()).isEqualTo(302);
      final var location = response.getRedirectedUrl();
      assertThat(location).startsWith(keycloakBaseUrl());
      return location;
    }

    /** Signs the user in at Keycloak, hands the code to the application, and reads the session. */
    private LoggedIn signInAndReturn(final String authorizationUrl) throws Exception {
      final var callbackParameters = queryParameters(signInAtKeycloak(authorizationUrl));
      assertThat(callbackParameters).containsKey("code");

      final var callback = request("GET", CALLBACK_PATH);
      callbackParameters.forEach(callback::addParameter);
      final var response = send(callback, new MockFilterChain());

      assertThat(response.getStatus()).isEqualTo(302);
      assertThat(response.getRedirectedUrl())
          .as("the application did not complete the login")
          .doesNotContain("error");
      return session();
    }

    /**
     * Reads the session the login produced. The request reaches the end of the chain only for a
     * user the application authenticated, so the status also says that the session works.
     */
    private LoggedIn session() throws Exception {
      final var terminal = new MockFilterChain();
      final var response = send(request("GET", WEBAPP_PATH), terminal);

      assertThat(response.getStatus())
          .as("the session of the login does not authenticate the next request")
          .isEqualTo(200);
      final var request = (HttpServletRequest) terminal.getRequest();
      final var authentication = authentication(request);
      final var registrationId =
          ((OAuth2AuthenticationToken) authentication).getAuthorizedClientRegistrationId();
      final var authorizedClient =
          new HttpSessionOAuth2AuthorizedClientRepository()
              .loadAuthorizedClient(registrationId, authentication, request);
      assertThat(authorizedClient).as("the session holds no authorized client").isNotNull();
      return new LoggedIn(registrationId, authorizedClient, request);
    }

    /**
     * Refreshes through the chain, and not through a manager of the test: the session gets an
     * expired access token, and the next request makes the refresh filter of CSL renew it with the
     * authorized client manager that the application wires into the chain.
     */
    private OAuth2AuthorizedClient refresh(final LoggedIn loggedIn) throws Exception {
      final var repository = new HttpSessionOAuth2AuthorizedClientRepository();
      final var authentication = authentication(loggedIn.request());
      // The save runs inside a request, so the session store holds it for the next one.
      send(
          request("GET", WEBAPP_PATH),
          (request, response) ->
              repository.saveAuthorizedClient(
                  expired(loggedIn.authorizedClient()),
                  authentication,
                  (HttpServletRequest) request,
                  (HttpServletResponse) response));

      return session().authorizedClient();
    }

    private void logOut() throws Exception {
      final var response = send(request("POST", "/logout"), new MockFilterChain());

      assertThat(response.getStatus()).isEqualTo(302);
    }

    private MockHttpServletResponse send(
        final MockHttpServletRequest request, final FilterChain terminal) throws Exception {
      request.setCookies(cookies);
      final var response = new MockHttpServletResponse();
      chain.doFilter(request, response, terminal);
      cookies = merge(cookies, response.getCookies());
      return response;
    }

    private MockHttpServletRequest request(final String method, final String path) {
      final var request = new MockHttpServletRequest(method, path);
      request.setServletPath(path);
      return request;
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
          .webappPaths("/operate/**", CALLBACK_PATH, "/login", "/logout", "/oauth2/**")
          .build();
    }
  }
}
