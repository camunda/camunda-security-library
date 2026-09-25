/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.converter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import io.camunda.security.spring.oidc.JWSKeySelectorFactory;
import io.camunda.security.spring.oidc.OidcAccessTokenDecoderFactory;
import io.camunda.security.spring.oidc.OidcTestServer;
import io.camunda.security.spring.oidc.TokenValidatorFactory;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;

/**
 * Regression test for camunda-security-library#649: the interactive login flow resolved {@code
 * additional-jwk-set-uris} from an issuer-keyed map, so a provider configured with explicit
 * endpoints and no {@code issuer-uri} silently lost its supplementary key sets and the converter
 * fell back to ID-token claims.
 *
 * <p>End-to-end rather than mocked at the decoder: two local JWKS servers stand in for the primary
 * and the additional endpoint, each serving a distinct signing key, and the access token is signed
 * with the key that only the additional endpoint publishes. Only a converter that actually forwards
 * the additional URI into {@link OidcAccessTokenDecoderFactory} can decode it.
 */
@ExtendWith(MockitoExtension.class)
final class OidcUserAuthenticationConverterAdditionalJwksTest {

  private static final String REGISTRATION_ID = "oidc";
  private static final String ACCESS_TOKEN_ONLY_CLAIM = "groups";

  @Mock private OAuth2AuthorizedClientRepository authorizedClientRepository;
  @Mock private LazyTokenClaimsConverter tokenClaimsConverter;
  @Mock private HttpServletRequest request;

  private OidcTestServer primary;
  private OidcTestServer additional;
  private ListAppender<ILoggingEvent> logAppender;
  private Logger converterLogger;

  @AfterEach
  void tearDown() {
    if (primary != null) {
      primary.stop();
    }
    if (additional != null) {
      additional.stop();
    }
    if (converterLogger != null && logAppender != null) {
      converterLogger.detachAppender(logAppender);
      logAppender.stop();
    }
  }

  @Test
  void shouldUseAccessTokenClaimsWhenSignedByAdditionalJwksAndNoIssuerUriConfigured()
      throws Exception {
    startJwksServers();
    final var converter =
        converter(null, new AdditionalJwkSetUrisByRegistrationId(additionalUrisByRegistrationId()));

    final var claims = convert(converter, additional.sign(null, accessTokenClaims()));

    assertThat(claims).containsEntry(ACCESS_TOKEN_ONLY_CLAIM, List.of("admins"));
    assertThat(fallbackWarnings()).isEmpty();
  }

  @Test
  void shouldFallBackToIdTokenClaimsWhenAdditionalJwksUrisAreNotResolved() throws Exception {
    // Pins the failure the fix removes: without the additional URI the token signed by the
    // additional endpoint's key cannot be verified, so the converter silently sources claims from
    // the ID token instead. Keeps the test above from passing vacuously.
    startJwksServers();
    final var converter = converter(null, AdditionalJwkSetUrisByRegistrationId.empty());

    final var claims = convert(converter, additional.sign(null, accessTokenClaims()));

    assertThat(claims).doesNotContainKey(ACCESS_TOKEN_ONLY_CLAIM).containsEntry("source", "id");
    assertThat(fallbackWarnings()).hasSize(1);
  }

  @Test
  void shouldUseAccessTokenClaimsWhenSignedByAdditionalJwksAndIssuerUriConfigured()
      throws Exception {
    // The issuer-keyed path a multi-provider deployment relies on: every registration declares an
    // issuer-uri, and the token is validated against it as well as verified against both key sets.
    startJwksServers();
    final var issuerUri = primary.issuerUri();
    final var converter =
        converter(
            issuerUri, new AdditionalJwkSetUrisByRegistrationId(additionalUrisByRegistrationId()));

    final var claims = convert(converter, additional.sign(issuerUri, accessTokenClaims()));

    assertThat(claims).containsEntry(ACCESS_TOKEN_ONLY_CLAIM, List.of("admins"));
    assertThat(claims).containsEntry("iss", issuerUri);
    assertThat(fallbackWarnings()).isEmpty();
  }

  private void startJwksServers() throws Exception {
    primary = OidcTestServer.startRsa("primary-key");
    additional = OidcTestServer.startRsa("additional-key");
  }

  private Map<String, List<String>> additionalUrisByRegistrationId() {
    return Map.of(REGISTRATION_ID, List.of(additional.jwksUri()));
  }

  private static Map<String, Object> accessTokenClaims() {
    return Map.of(ACCESS_TOKEN_ONLY_CLAIM, List.of("admins"));
  }

  /**
   * Builds the converter over a real {@link OidcAccessTokenDecoderFactory}, with the provider
   * configuration the host would have bound from {@code camunda.security.authentication.oidc.*}.
   */
  private OidcUserAuthenticationConverter converter(
      final String issuerUri, final AdditionalJwkSetUrisByRegistrationId additionalJwkSetUris) {
    final var configuration =
        OidcConfiguration.builder()
            .clientId("test-client")
            .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
            .issuerUri(issuerUri)
            .authorizationUri(primary.issuerUri() + "/auth")
            .tokenUri(primary.issuerUri() + "/token")
            .jwkSetUri(primary.jwksUri())
            .additionalJwkSetUris(List.of(additional.jwksUri()))
            .build();
    final var decoderFactory =
        new OidcAccessTokenDecoderFactory(
            new JWSKeySelectorFactory(),
            new TokenValidatorFactory(
                Map.of(REGISTRATION_ID, configuration),
                OidcConfiguration.DEFAULT_CLOCK_SKEW,
                List.of()));
    return new OidcUserAuthenticationConverter(
        authorizedClientRepository,
        decoderFactory,
        tokenClaimsConverter,
        request,
        additionalJwkSetUris);
  }

  /**
   * Drives the converter over a full {@link OAuth2AuthenticationToken} and returns the claims it
   * handed to the {@link LazyTokenClaimsConverter}. The ID token carries {@code source=id} and none
   * of the access token's claims, so the source of the returned map is unambiguous.
   */
  private Map<String, Object> convert(
      final OidcUserAuthenticationConverter converter, final String accessTokenValue) {
    final var now = Instant.now();
    final var idToken =
        new OidcIdToken(
            "id-token", now, now.plusSeconds(60), Map.of("sub", "alice", "source", "id"));
    final var principal =
        new DefaultOidcUser(List.of(new SimpleGrantedAuthority("ROLE_USER")), idToken);
    final var authentication =
        new OAuth2AuthenticationToken(principal, principal.getAuthorities(), REGISTRATION_ID);
    final var accessToken =
        new OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER, accessTokenValue, now, now.plusSeconds(60));
    when(authorizedClientRepository.loadAuthorizedClient(REGISTRATION_ID, authentication, request))
        .thenReturn(
            new OAuth2AuthorizedClient(clientRegistration(), principal.getName(), accessToken));
    when(tokenClaimsConverter.convert(anyMap()))
        .thenReturn(CamundaAuthentication.of(b -> b.user("alice")));
    captureConverterLogs();

    converter.convert(authentication);

    @SuppressWarnings("unchecked")
    final ArgumentCaptor<Map<String, Object>> captor = ArgumentCaptor.forClass(Map.class);
    verify(tokenClaimsConverter).convert(captor.capture());
    return captor.getValue();
  }

  /**
   * The registration the login produced, always without {@code issuerUri} — the decoder resolves
   * supplementary key sets by registration ID, so the registration never needs to carry an issuer
   * for them to be found.
   */
  private ClientRegistration clientRegistration() {
    return ClientRegistration.withRegistrationId(REGISTRATION_ID)
        .clientId("test-client")
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .authorizationUri(primary.issuerUri() + "/auth")
        .tokenUri(primary.issuerUri() + "/token")
        .jwkSetUri(primary.jwksUri())
        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
        .build();
  }

  private void captureConverterLogs() {
    converterLogger = (Logger) LoggerFactory.getLogger(OidcUserAuthenticationConverter.class);
    logAppender = new ListAppender<>();
    logAppender.start();
    converterLogger.addAppender(logAppender);
  }

  private List<String> fallbackWarnings() {
    return logAppender.list.stream()
        .filter(event -> event.getLevel() == Level.WARN)
        .map(ILoggingEvent::getFormattedMessage)
        .filter(message -> message.contains("Falling back to ID Token claims"))
        .toList();
  }
}
