/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withBadRequest;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import java.net.SocketTimeoutException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.RequestMatcher;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

/**
 * Unit tests for {@link RefreshTokenRevocationLogoutHandler} (ADR-0032).
 *
 * <p>Two properties matter beyond "a request was sent". First, the request has to authenticate the
 * way the same client authenticates at the token endpoint, or the provider rejects it and the
 * refresh token silently survives the logout. Second, nothing the provider does may surface to the
 * user, whose local session is already gone by the time this handler runs.
 */
@ExtendWith(MockitoExtension.class)
class RefreshTokenRevocationLogoutHandlerTest {

  private static final String REGISTRATION_ID = "oidc";
  private static final String CLIENT_ID = "client-id";
  private static final String CLIENT_SECRET = "client-secret";
  private static final String REVOCATION_ENDPOINT = "https://idp.example.com/oauth2/revoke";
  private static final String REFRESH_TOKEN_VALUE = "the-refresh-token";

  /**
   * The logger {@code DefaultRestClient} writes its request-body DEBUG line to. Named by string:
   * the class is package-private in {@code org.springframework.web.client}.
   */
  private static final String REST_CLIENT_LOGGER =
      "org.springframework.web.client.DefaultRestClient";

  private static final String JWT_BEARER_ASSERTION_TYPE =
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

  @Mock private ClientRegistrationRepository clientRegistrationRepository;
  @Mock private OAuth2AuthorizedClientRepository authorizedClientRepository;

  private MockHttpServletRequest request;
  private MockHttpServletResponse response;
  private RestClient.Builder restClientBuilder;
  private MockRestServiceServer server;

  @BeforeEach
  void setUp() {
    request = new MockHttpServletRequest();
    response = new MockHttpServletResponse();
    restClientBuilder = RestClient.builder();
    server = MockRestServiceServer.bindTo(restClientBuilder).bufferContent().build();
  }

  @Test
  void shouldRevokeRefreshTokenWithBasicClientAuthentication() {
    // given a client_secret_basic registration publishing a revocation endpoint
    final var registration = registration(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).build();
    givenAuthorizedSession(registration);
    server
        .expect(requestTo(REVOCATION_ENDPOINT))
        .andExpect(post())
        .andExpect(
            headers(
                headers ->
                    assertThat(headers.getFirst(HttpHeaders.AUTHORIZATION))
                        .isEqualTo(basicAuth(CLIENT_ID, CLIENT_SECRET))))
        .andExpect(
            formBody(
                fields ->
                    assertThat(fields)
                        .containsEntry("token", REFRESH_TOKEN_VALUE)
                        .containsEntry("token_type_hint", "refresh_token")
                        // For this method the credentials belong in the header only; duplicating
                        // them into the body is what RFC 6749 §2.3.1 tells servers to reject.
                        .doesNotContainKeys("client_id", "client_secret")))
        .andRespond(withSuccess());

    // when the user logs out
    handler(null).logout(request, response, authentication(registration));

    // then the refresh token was revoked at the provider
    server.verify();
  }

  @Test
  void shouldRevokeRefreshTokenWithPostClientAuthentication() {
    // given a client_secret_post registration
    final var registration = registration(ClientAuthenticationMethod.CLIENT_SECRET_POST).build();
    givenAuthorizedSession(registration);
    server
        .expect(requestTo(REVOCATION_ENDPOINT))
        .andExpect(
            headers(
                headers ->
                    assertThat(headers.headerNames()).doesNotContain(HttpHeaders.AUTHORIZATION)))
        .andExpect(
            formBody(
                fields ->
                    assertThat(fields)
                        .containsEntry("client_id", CLIENT_ID)
                        .containsEntry("client_secret", CLIENT_SECRET)
                        .containsEntry("token", REFRESH_TOKEN_VALUE)))
        .andRespond(withSuccess());

    // when the user logs out
    handler(null).logout(request, response, authentication(registration));

    // then the credentials travelled in the body instead of the header
    server.verify();
  }

  @Test
  void shouldRevokeRefreshTokenWithPrivateKeyJwtClientAuthentication() throws Exception {
    // given a private_key_jwt registration and a resolvable signing key
    final var registration = registration(ClientAuthenticationMethod.PRIVATE_KEY_JWT).build();
    givenAuthorizedSession(registration);
    server
        .expect(requestTo(REVOCATION_ENDPOINT))
        .andExpect(
            formBody(
                fields ->
                    assertThat(fields)
                        .containsEntry("client_id", CLIENT_ID)
                        .containsEntry("client_assertion_type", JWT_BEARER_ASSERTION_TYPE)
                        .containsEntry("token", REFRESH_TOKEN_VALUE)
                        .doesNotContainKey("client_secret")
                        .hasEntrySatisfying(
                            "client_assertion", assertion -> assertThat(assertion).isNotBlank())))
        .andRespond(withSuccess());

    // when the user logs out
    handler(jwkResolver(rsaJwk())).logout(request, response, authentication(registration));

    // then a signed client assertion authenticated the request
    server.verify();
  }

  @Test
  void shouldSkipRevocationWhenProviderPublishesNoRevocationEndpoint() {
    // given a provider whose metadata carries no revocation endpoint, as MS Entra's does not
    final var registration =
        registration(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .providerConfigurationMetadata(Map.of())
            .build();
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(registration);

    // when the user logs out
    handler(null).logout(request, response, authentication(registration));

    // then no request is attempted at all
    server.verify();
  }

  @Test
  void shouldSkipRevocationWhenSessionHasNoRefreshToken() {
    // given a session whose authorized client never received a refresh token
    final var registration = registration(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).build();
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(registration);
    when(authorizedClientRepository.loadAuthorizedClient(
            eq(REGISTRATION_ID), any(Authentication.class), any()))
        .thenReturn(new OAuth2AuthorizedClient(registration, "principal", accessToken(), null));

    // when the user logs out
    handler(null).logout(request, response, authentication(registration));

    // then there is nothing to revoke and no request is attempted
    server.verify();
  }

  @Test
  void shouldSkipRevocationWhenAuthenticationIsNotOidc() {
    // given a non-OAuth2 authentication, as the basic-auth chain produces
    final Authentication authentication =
        UsernamePasswordAuthenticationToken.authenticated("demo", "demo", List.of());

    // when the user logs out
    handler(null).logout(request, response, authentication);

    // then no request is attempted
    server.verify();
  }

  @Test
  void shouldSkipRevocationWhenRegistrationIsUnknown() {
    // given an authentication naming a registration the repository does not hold
    final var registration = registration(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).build();
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID)).thenReturn(null);

    // when the user logs out
    handler(null).logout(request, response, authentication(registration));

    // then no request is attempted
    server.verify();
  }

  @Test
  void shouldSkipRevocationWhenClientAuthenticatesWithClientSecretJwt() {
    // given a registration on client_secret_jwt, which CSL cannot sign an assertion for: its
    // permitted methods are client_secret_basic and private_key_jwt, so there is no octet key
    final var registration = registration(ClientAuthenticationMethod.CLIENT_SECRET_JWT).build();
    // A full session, so the only thing standing between this and a request is the guard itself.
    givenAuthorizedSession(registration);

    // when the user logs out
    handler(null).logout(request, response, authentication(registration));

    // then nothing is sent, rather than an assertion the provider would reject
    server.verify();
  }

  /**
   * The class promises the token value is never logged. {@code DefaultRestClient#logBody} appends
   * the body object to a DEBUG line before handing it to a message converter, so passing the form
   * as a {@code MultiValueMap} to {@code body(Object)} would put the refresh token and the client
   * secret in that line. This asserts on Spring's own logger, not on our wire format, because the
   * wire format is identical either way — it is the log that differs.
   */
  @Test
  void shouldNeverLogTheRefreshTokenOrClientSecretWhileSendingTheRequest() {
    // given Spring's REST client logging turned up to DEBUG
    final var appender = attachRestClientDebugAppender();
    try {
      final var registration = registration(ClientAuthenticationMethod.CLIENT_SECRET_POST).build();
      givenAuthorizedSession(registration);
      server
          .expect(requestTo(REVOCATION_ENDPOINT))
          .andExpect(
              headers(
                  headers ->
                      assertThat(headers.getContentType())
                          .isEqualTo(MediaType.APPLICATION_FORM_URLENCODED)))
          .andExpect(
              formBody(
                  fields ->
                      assertThat(fields)
                          .containsEntry("token", REFRESH_TOKEN_VALUE)
                          .containsEntry("client_secret", CLIENT_SECRET)))
          .andRespond(withSuccess());

      // when the user logs out
      handler(null).logout(request, response, authentication(registration));

      // then the request went out, and neither secret reached the log
      server.verify();
      // No "not empty" guard: the fix produces no body log line at all. What keeps this test
      // from passing vacuously is springLogsTheFormBodyWhenItIsPassedToBodyObject below.
      assertThat(appender.list)
          .extracting(ILoggingEvent::getFormattedMessage)
          .noneMatch(line -> line.contains(REFRESH_TOKEN_VALUE))
          .noneMatch(line -> line.contains(CLIENT_SECRET));
    } finally {
      detachRestClientDebugAppender(appender);
    }
  }

  @Test
  void shouldFormUrlEncodeReservedCharactersInTheBody() {
    // given a refresh token containing characters that must be escaped in a form body
    final var registration = registration(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).build();
    final var awkwardToken = "a+b&c=d e/f";
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(registration);
    when(authorizedClientRepository.loadAuthorizedClient(
            eq(REGISTRATION_ID), any(Authentication.class), any()))
        .thenReturn(
            new OAuth2AuthorizedClient(
                registration,
                "principal",
                accessToken(),
                new OAuth2RefreshToken(awkwardToken, Instant.now())));
    server
        .expect(requestTo(REVOCATION_ENDPOINT))
        .andExpect(formBody(fields -> assertThat(fields).containsEntry("token", awkwardToken)))
        .andRespond(withSuccess());

    // when the user logs out
    handler(null).logout(request, response, authentication(registration));

    // then the provider receives the token verbatim after decoding
    server.verify();
  }

  @Test
  void shouldCompleteLogoutWhenProviderRejectsRevocation() {
    // given a provider that answers the revocation request with 400
    final var registration = registration(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).build();
    givenAuthorizedSession(registration);
    server.expect(requestTo(REVOCATION_ENDPOINT)).andRespond(withBadRequest());
    final var logoutHandler = handler(null);
    final var authentication = authentication(registration);

    // when the user logs out
    // then the rejection is swallowed: the local session is already gone either way
    assertThatCode(() -> logoutHandler.logout(request, response, authentication))
        .doesNotThrowAnyException();
    server.verify();
  }

  /**
   * Regression for the non-2xx check: a 3xx must take the failure path. {@code isError()} — what
   * this used to test — is 4xx/5xx only, so a redirect would have been logged as a successful
   * revocation. The client is configured not to follow redirects, so nothing was revoked. The
   * assertion is on the handler's own log because the status is the only observable difference:
   * logout completes either way.
   */
  @Test
  void shouldTreatARedirectFromTheRevocationEndpointAsAFailure() {
    // given a revocation endpoint answering with a redirect
    final var appender = attachHandlerDebugAppender();
    try {
      final var registration = registration(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).build();
      givenAuthorizedSession(registration);
      server.expect(requestTo(REVOCATION_ENDPOINT)).andRespond(withStatus(HttpStatus.FOUND));
      final var logoutHandler = handler(null);
      final var authentication = authentication(registration);

      // when the user logs out
      assertThatCode(() -> logoutHandler.logout(request, response, authentication))
          .doesNotThrowAnyException();

      // then the request was made and reported as unconfirmed, not as a revocation
      server.verify();
      assertThat(appender.list)
          .extracting(ILoggingEvent::getFormattedMessage)
          .anyMatch(line -> line.contains("did not confirm the refresh-token revocation"))
          .noneMatch(line -> line.startsWith("Revoked the refresh token"));
    } finally {
      detachHandlerDebugAppender(appender);
    }
  }

  @Test
  void shouldCompleteLogoutWhenProviderIsUnreachable() {
    // given a provider whose revocation endpoint cannot be reached
    final var registration = registration(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).build();
    givenAuthorizedSession(registration);
    server
        .expect(requestTo(REVOCATION_ENDPOINT))
        .andRespond(
            req -> {
              throw new SocketTimeoutException("connect timed out");
            });
    final var logoutHandler = handler(null);
    final var authentication = authentication(registration);

    // when the user logs out
    // then logout still completes
    assertThatCode(() -> logoutHandler.logout(request, response, authentication))
        .doesNotThrowAnyException();
    // and the request really was attempted: without this the test also passes when an earlier
    // guard returns and no revocation is tried, which is not the path under test.
    server.verify();
  }

  /**
   * A failure while signing the assertion — a missing or unreadable keystore, typically — must stay
   * attributable to one provider, and must not carry the exception's own message into the log.
   */
  @Test
  void shouldNameTheRegistrationWhenTheAssertionCannotBeSigned() {
    // given a private_key_jwt registration whose signing key cannot be resolved
    final var registration = registration(ClientAuthenticationMethod.PRIVATE_KEY_JWT).build();
    givenAuthorizedSession(registration);
    final var appender = attachHandlerDebugAppender();
    try {
      final Function<ClientRegistration, JWK> failing =
          reg -> {
            throw new IllegalStateException("keystore /etc/secret.p12 is unreadable");
          };

      // when the user logs out
      handler(failing).logout(request, response, authentication(registration));

      // then the warning names the registration and omits the exception's message
      assertThat(appender.list)
          .extracting(ILoggingEvent::getFormattedMessage)
          .anyMatch(line -> line.contains(REGISTRATION_ID))
          .noneMatch(line -> line.contains("/etc/secret.p12"));
    } finally {
      detachHandlerDebugAppender(appender);
    }
  }

  @Test
  void shouldCompleteLogoutWhenAssertionSigningKeyIsUnavailable() {
    // given a private_key_jwt registration but no resolver to sign an assertion with
    final var registration = registration(ClientAuthenticationMethod.PRIVATE_KEY_JWT).build();
    givenAuthorizedSession(registration);
    server.expect(requestTo(REVOCATION_ENDPOINT)).andRespond(withBadRequest());
    final var logoutHandler = handler(null);
    final var authentication = authentication(registration);

    // when the user logs out
    // then logout completes rather than failing on the missing key
    assertThatCode(() -> logoutHandler.logout(request, response, authentication))
        .doesNotThrowAnyException();
    server.verify();
  }

  /**
   * Pins the hazard the test above avoids, so that one cannot pass vacuously: a wrong logger name,
   * or a future Spring that stops logging request bodies, fails here instead of silently turning
   * the negative assertion into a tautology.
   */
  @Test
  void springLogsTheFormBodyWhenItIsPassedToBodyObject() {
    // given the same form the handler builds, handed to body(Object) as it was before the fix,
    // with Spring's REST client logging at DEBUG
    final var appender = attachRestClientDebugAppender();
    try {
      final MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
      form.set("token", REFRESH_TOKEN_VALUE);
      server.expect(requestTo(REVOCATION_ENDPOINT)).andRespond(withSuccess());

      // when the request is sent through the message-converter path
      restClientBuilder
          .build()
          .post()
          .uri(REVOCATION_ENDPOINT)
          .contentType(MediaType.APPLICATION_FORM_URLENCODED)
          .body(form)
          .retrieve()
          .onStatus(anyStatus -> true, (req, res) -> {})
          .toBodilessEntity();

      // then the token lands in the log, which is exactly why the handler streams instead
      assertThat(appender.list)
          .extracting(ILoggingEvent::getFormattedMessage)
          .anyMatch(line -> line.contains(REFRESH_TOKEN_VALUE));
    } finally {
      detachRestClientDebugAppender(appender);
    }
  }

  private static ListAppender<ILoggingEvent> attachHandlerDebugAppender() {
    final Logger logger =
        (Logger) LoggerFactory.getLogger(RefreshTokenRevocationLogoutHandler.class);
    logger.setLevel(Level.DEBUG);
    final ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);
    return appender;
  }

  private static void detachHandlerDebugAppender(final ListAppender<ILoggingEvent> appender) {
    final Logger logger =
        (Logger) LoggerFactory.getLogger(RefreshTokenRevocationLogoutHandler.class);
    logger.detachAppender(appender);
    logger.setLevel(null);
  }

  private static ListAppender<ILoggingEvent> attachRestClientDebugAppender() {
    final Logger logger = (Logger) LoggerFactory.getLogger(REST_CLIENT_LOGGER);
    logger.setLevel(Level.DEBUG);
    final ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);
    return appender;
  }

  private static void detachRestClientDebugAppender(final ListAppender<ILoggingEvent> appender) {
    final Logger logger = (Logger) LoggerFactory.getLogger(REST_CLIENT_LOGGER);
    logger.detachAppender(appender);
    logger.setLevel(null);
  }

  private RefreshTokenRevocationLogoutHandler handler(
      final Function<ClientRegistration, JWK> jwkResolver) {
    return new RefreshTokenRevocationLogoutHandler(
        clientRegistrationRepository,
        authorizedClientRepository,
        jwkResolver,
        restClientBuilder.build());
  }

  private void givenAuthorizedSession(final ClientRegistration registration) {
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(registration);
    when(authorizedClientRepository.loadAuthorizedClient(
            eq(REGISTRATION_ID), any(Authentication.class), any()))
        .thenReturn(
            new OAuth2AuthorizedClient(
                registration,
                "principal",
                accessToken(),
                new OAuth2RefreshToken(REFRESH_TOKEN_VALUE, Instant.now())));
  }

  /**
   * Asserts on the decoded form fields rather than a raw body substring, so percent-encoding cannot
   * make an assertion pass or fail by accident, and so absent fields can be asserted too.
   */
  private static RequestMatcher formBody(final Consumer<Map<String, String>> assertion) {
    return request ->
        assertion.accept(formFields(((MockClientHttpRequest) request).getBodyAsString()));
  }

  private static RequestMatcher requestTo(final String uri) {
    return request -> assertThat(request.getURI()).hasToString(uri);
  }

  private static RequestMatcher post() {
    return request -> assertThat(request.getMethod()).isEqualTo(HttpMethod.POST);
  }

  /**
   * The header counterpart of {@link #formBody}. Spring's own header matchers cannot be used here:
   * Spring's own {@code MockRestRequestMatchers} are not used anywhere in this test: every one of
   * them resolves through a {@code Matcher}-typed overload, which drags Hamcrest onto the compile
   * classpath, and CSL tests are AssertJ-only.
   */
  private static RequestMatcher headers(final Consumer<HttpHeaders> assertion) {
    return request -> assertion.accept(request.getHeaders());
  }

  private static Map<String, String> formFields(final String body) {
    if (body.isEmpty()) {
      return Map.of();
    }
    return Arrays.stream(body.split("&"))
        .map(pair -> pair.split("=", 2))
        .collect(
            Collectors.toMap(
                pair -> URLDecoder.decode(pair[0], StandardCharsets.UTF_8),
                pair -> pair.length > 1 ? URLDecoder.decode(pair[1], StandardCharsets.UTF_8) : "",
                (first, second) -> first));
  }

  private static ClientRegistration.Builder registration(
      final ClientAuthenticationMethod clientAuthenticationMethod) {
    return ClientRegistration.withRegistrationId(REGISTRATION_ID)
        .clientId(CLIENT_ID)
        .clientSecret(CLIENT_SECRET)
        .clientAuthenticationMethod(clientAuthenticationMethod)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/sso-callback")
        .authorizationUri("https://idp.example.com/oauth2/authorize")
        .tokenUri("https://idp.example.com/oauth2/token")
        .jwkSetUri("https://idp.example.com/oauth2/jwks")
        .userNameAttributeName("sub")
        .scope("openid")
        .providerConfigurationMetadata(Map.of("revocation_endpoint", REVOCATION_ENDPOINT));
  }

  private static OAuth2AccessToken accessToken() {
    return new OAuth2AccessToken(
        OAuth2AccessToken.TokenType.BEARER,
        "the-access-token",
        Instant.now(),
        Instant.now().plusSeconds(300));
  }

  private static OAuth2AuthenticationToken authentication(final ClientRegistration registration) {
    final var idToken =
        new OidcIdToken(
            "id-token", Instant.now(), Instant.now().plusSeconds(300), Map.of("sub", "principal"));
    final var user = new DefaultOidcUser(List.of(new SimpleGrantedAuthority("ROLE_USER")), idToken);
    return new OAuth2AuthenticationToken(
        user, user.getAuthorities(), registration.getRegistrationId());
  }

  private static Function<ClientRegistration, JWK> jwkResolver(final JWK jwk) {
    return registration -> jwk;
  }

  private static JWK rsaJwk() throws Exception {
    final var generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    final var pair = generator.generateKeyPair();
    return new RSAKey.Builder((RSAPublicKey) pair.getPublic())
        .privateKey((RSAPrivateKey) pair.getPrivate())
        .keyUse(KeyUse.SIGNATURE)
        .algorithm(JWSAlgorithm.RS256)
        .keyID("revocation-test")
        .build();
  }

  private static String basicAuth(final String clientId, final String clientSecret) {
    return "Basic "
        + Base64.getEncoder()
            .encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
  }
}
