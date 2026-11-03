/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static io.camunda.security.spring.security.ExpiredSessionRefreshTokenRevocation.AUTHORIZED_CLIENTS_ATTRIBUTE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.web.context.HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.spring.oidc.LazyClientRegistrationRepository;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.function.Supplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.session.MapSession;
import org.springframework.session.Session;

/** Unit tests for {@link ExpiredSessionRefreshTokenRevocation} (ADR-0043). */
@ExtendWith(MockitoExtension.class)
class ExpiredSessionRefreshTokenRevocationTest {

  private static final String REGISTRATION_ID = "oidc";
  private static final String CLIENT_ID = "client-id";
  private static final String TOKEN_URI = "https://idp.example.com/oauth2/token";
  private static final String ISSUER = "https://idp.example.com";
  private static final String REVOCATION_URI = "https://idp.example.com/oauth2/revoke";

  @Mock private ExecutorService executor;
  @Mock private ClientRegistrationRepository firstRepository;
  @Mock private ClientRegistrationRepository secondRepository;
  @Mock private LazyClientRegistrationRepository lazyRepository;
  @Mock private LazyClientRegistrationRepository otherLazyRepository;
  @Mock private RefreshTokenRevoker firstRevoker;
  @Mock private RefreshTokenRevoker secondRevoker;

  private ExpiredSessionRefreshTokenRevocation revocation;
  private ListAppender<ILoggingEvent> logs;

  @BeforeEach
  void setUp() {
    revocation = new ExpiredSessionRefreshTokenRevocation(executor);
    logs = new ListAppender<>();
    logs.start();
    logger().addAppender(logs);
  }

  @AfterEach
  void tearDown() {
    logger().detachAppender(logs);
  }

  @Test
  void shouldReadTheAuthorizedClientsFromTheAttributeSpringStoresThemIn() {
    // given - the repository the webapp chains store authorized clients with
    final var request = new MockHttpServletRequest();
    final var client = authorizedClient(registration(CLIENT_ID, TOKEN_URI), "refresh");
    new HttpSessionOAuth2AuthorizedClientRepository()
        .saveAuthorizedClient(
            client, oauth2Authentication(), request, new MockHttpServletResponse());

    // then
    assertThat(request.getSession().getAttribute(AUTHORIZED_CLIENTS_ATTRIBUTE))
        .isEqualTo(Map.of(REGISTRATION_ID, client));
  }

  @Test
  void shouldRevokeThroughTheChainThatOwnsTheRegistration() {
    // given
    runInline();
    final var registration = registration(CLIENT_ID, TOKEN_URI);
    final var client = authorizedClient(registration, "refresh");
    when(firstRepository.findByRegistrationId(REGISTRATION_ID)).thenReturn(registration);
    revocation.register(firstRepository, firstRevoker);

    // when
    revocation.revoke(expiredSession(client));

    // then
    final ArgumentCaptor<Supplier<OAuth2AuthorizedClient>> supplier = supplierCaptor();
    verify(firstRevoker).revoke(eq(registration), supplier.capture());
    assertThat(supplier.getValue().get()).isSameAs(client);
  }

  @Test
  void shouldSkipAChainThatUsesTheRegistrationIdForAnotherClient() {
    // given - two scopes, one registration ID, different providers
    runInline();
    final var owning = registration(CLIENT_ID, TOKEN_URI);
    final var client = authorizedClient(owning, "refresh");
    when(firstRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(registration(CLIENT_ID, "https://other-idp.example.com/oauth2/token"));
    when(secondRepository.findByRegistrationId(REGISTRATION_ID)).thenReturn(owning);
    revocation.register(firstRepository, firstRevoker);
    revocation.register(secondRepository, secondRevoker);

    // when
    revocation.revoke(expiredSession(client));

    // then
    verifyNoInteractions(firstRevoker);
    verify(secondRevoker).revoke(eq(owning), any());
  }

  @Test
  void shouldNotLookUpAChainConfiguredForAnotherClient() {
    // given - the lookup would start discovery of an unrelated provider
    runInline();
    final var registration = registration(CLIENT_ID, TOKEN_URI);
    final var otherClient = new OidcConfiguration();
    otherClient.setClientId("other-client-id");
    when(lazyRepository.providers()).thenReturn(Map.of(REGISTRATION_ID, otherClient));
    when(secondRepository.findByRegistrationId(REGISTRATION_ID)).thenReturn(registration);
    revocation.register(lazyRepository, firstRevoker);
    revocation.register(secondRepository, secondRevoker);

    // when
    revocation.revoke(expiredSession(authorizedClient(registration, "refresh")));

    // then
    verify(lazyRepository, never()).findByRegistrationId(any());
    verifyNoInteractions(firstRevoker);
    verify(secondRevoker).revoke(eq(registration), any());
  }

  @Test
  void shouldNotLookUpAChainConfiguredForTheSameClientAtAnotherProvider() {
    // given - same client ID, but the configuration names another issuer and token endpoint
    runInline();
    final var registration =
        ClientRegistration.withClientRegistration(registration(CLIENT_ID, TOKEN_URI))
            .issuerUri(ISSUER)
            .build();
    final var otherIssuer = new OidcConfiguration();
    otherIssuer.setClientId(CLIENT_ID);
    otherIssuer.setIssuerUri("https://other-idp.example.com");
    final var otherTokenUri = new OidcConfiguration();
    otherTokenUri.setClientId(CLIENT_ID);
    otherTokenUri.setTokenUri("https://other-idp.example.com/oauth2/token");
    when(lazyRepository.providers()).thenReturn(Map.of(REGISTRATION_ID, otherIssuer));
    when(otherLazyRepository.providers()).thenReturn(Map.of(REGISTRATION_ID, otherTokenUri));
    when(secondRepository.findByRegistrationId(REGISTRATION_ID)).thenReturn(registration);
    revocation.register(lazyRepository, firstRevoker);
    revocation.register(otherLazyRepository, firstRevoker);
    revocation.register(secondRepository, secondRevoker);

    // when
    revocation.revoke(expiredSession(authorizedClient(registration, "refresh")));

    // then
    verify(lazyRepository, never()).findByRegistrationId(any());
    verify(otherLazyRepository, never()).findByRegistrationId(any());
    verifyNoInteractions(firstRevoker);
    verify(secondRevoker).revoke(eq(registration), any());
  }

  @Test
  void shouldLookUpAChainWhoseIssuerDiffersOnlyByATrailingSlash() {
    // given
    runInline();
    final var registration =
        ClientRegistration.withClientRegistration(registration(CLIENT_ID, TOKEN_URI))
            .issuerUri(ISSUER)
            .build();
    final var config = new OidcConfiguration();
    config.setClientId(CLIENT_ID);
    config.setIssuerUri(ISSUER + "/");
    when(lazyRepository.providers()).thenReturn(Map.of(REGISTRATION_ID, config));
    when(lazyRepository.findByRegistrationId(REGISTRATION_ID)).thenReturn(registration);
    revocation.register(lazyRepository, firstRevoker);

    // when
    revocation.revoke(expiredSession(authorizedClient(registration, "refresh")));

    // then
    verify(firstRevoker).revoke(eq(registration), any());
  }

  @Test
  void shouldRevokeOnceWhenSeveralChainsOwnTheClientWithTheSameRevocationSettings() {
    // given
    runInline();
    final var registration = registration(CLIENT_ID, TOKEN_URI, REVOCATION_URI);
    when(firstRepository.findByRegistrationId(REGISTRATION_ID)).thenReturn(registration);
    when(secondRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(registration(CLIENT_ID, TOKEN_URI, REVOCATION_URI));
    revocation.register(firstRepository, firstRevoker);
    revocation.register(secondRepository, secondRevoker);

    // when
    revocation.revoke(expiredSession(authorizedClient(registration, "refresh")));

    // then
    verify(firstRevoker).revoke(eq(registration), any());
    verifyNoInteractions(secondRevoker);
  }

  @Test
  void shouldNotRevokeWhenTheChainsThatOwnTheClientDisagreeOnRevocation() {
    // given - one scope opted out of revocation, the other did not
    runInline();
    final var enabled = registration(CLIENT_ID, TOKEN_URI, REVOCATION_URI);
    when(firstRepository.findByRegistrationId(REGISTRATION_ID)).thenReturn(enabled);
    when(secondRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(registration(CLIENT_ID, TOKEN_URI));
    revocation.register(firstRepository, firstRevoker);
    revocation.register(secondRepository, secondRevoker);
    final var session = expiredSession(authorizedClient(enabled, "refresh"));

    // when
    revocation.revoke(session);
    revocation.revoke(session);

    // then
    verifyNoInteractions(firstRevoker, secondRevoker);
    assertThat(logs.list)
        .filteredOn(event -> event.getLevel() == Level.WARN)
        .singleElement()
        .satisfies(
            event ->
                assertThat(event.getFormattedMessage())
                    .contains("different refresh-token revocation settings"));
  }

  @Test
  void shouldNotRevokeWhenAChainThatMayOwnTheClientCannotBeResolved() {
    // given - the unresolved chain may be a scope that opted out of revocation
    runInline();
    final var registration = registration(CLIENT_ID, TOKEN_URI, REVOCATION_URI);
    when(firstRepository.findByRegistrationId(REGISTRATION_ID)).thenReturn(registration);
    when(secondRepository.findByRegistrationId(REGISTRATION_ID))
        .thenThrow(new IllegalStateException("discovery failed"));
    revocation.register(firstRepository, firstRevoker);
    revocation.register(secondRepository, secondRevoker);

    // when
    revocation.revoke(expiredSession(authorizedClient(registration, "refresh")));

    // then
    verifyNoInteractions(firstRevoker, secondRevoker);
  }

  @Test
  void shouldWarnOnceWhileARegistrationCannotBeResolvedAndAgainAfterItRecovers() {
    // given a chain whose lookup fails twice, then resolves, then fails again
    runInline();
    final var registration = registration(CLIENT_ID, TOKEN_URI, REVOCATION_URI);
    when(firstRepository.findByRegistrationId(REGISTRATION_ID))
        .thenThrow(new IllegalStateException("discovery failed"))
        .thenThrow(new IllegalStateException("discovery failed"))
        .thenReturn(registration)
        .thenThrow(new IllegalStateException("discovery failed"));
    revocation.register(firstRepository, firstRevoker);
    final var session = expiredSession(authorizedClient(registration, "refresh"));

    // when
    revocation.revoke(session);
    revocation.revoke(session);
    revocation.revoke(session);
    revocation.revoke(session);

    // then one WARN for each outage, and the session in between is revoked
    assertThat(logs.list)
        .filteredOn(event -> event.getLevel() == Level.WARN)
        .hasSize(2)
        .allSatisfy(
            event ->
                assertThat(event.getFormattedMessage())
                    .contains("Could not resolve OIDC registration")
                    .doesNotContain("refresh-token-value"));
    verify(firstRevoker).revoke(eq(registration), any());
  }

  @Test
  void shouldNotRevokeWhenNoChainOwnsTheRegistration() {
    // given
    runInline();
    final var registration = registration(CLIENT_ID, TOKEN_URI);
    revocation.register(firstRepository, firstRevoker);

    // when
    revocation.revoke(expiredSession(authorizedClient(registration, "refresh")));

    // then
    verifyNoInteractions(firstRevoker);
  }

  @Test
  void shouldNotScheduleAnythingForASessionWithoutARefreshToken() {
    // given
    revocation.register(firstRepository, firstRevoker);
    final var client = authorizedClient(registration(CLIENT_ID, TOKEN_URI), null);

    // when
    revocation.revoke(expiredSession(client));

    // then
    verifyNoInteractions(executor, firstRepository, firstRevoker);
  }

  @Test
  void shouldNotScheduleAnythingForASessionThatIsNotAnOidcLogin() {
    // given
    revocation.register(firstRepository, firstRevoker);
    final var session = new MapSession();
    session.setAttribute(
        SPRING_SECURITY_CONTEXT_KEY,
        new SecurityContextImpl(new UsernamePasswordAuthenticationToken("user", "password")));

    // when
    revocation.revoke(session);

    // then
    verifyNoInteractions(executor, firstRepository, firstRevoker);
  }

  @Test
  void shouldNotScheduleAnythingWhenNoChainIsRegistered() {
    // when
    revocation.revoke(expiredSession(authorizedClient(registration(CLIENT_ID, TOKEN_URI), "x")));

    // then
    verifyNoInteractions(executor);
  }

  @Test
  void shouldWarnOnceWhileTheQueueStaysFull() {
    // given
    doThrow(new RejectedExecutionException("full")).when(executor).execute(any());
    revocation.register(firstRepository, firstRevoker);
    final var session =
        expiredSession(authorizedClient(registration(CLIENT_ID, TOKEN_URI), "refresh"));

    // when
    revocation.revoke(session);
    revocation.revoke(session);

    // then
    assertThat(logs.list)
        .filteredOn(event -> event.getLevel() == Level.WARN)
        .singleElement()
        .satisfies(
            event ->
                assertThat(event.getFormattedMessage())
                    .contains("Dropping refresh-token revocations")
                    .doesNotContain("refresh-token-value"));
  }

  @Test
  void shouldNeverThrowOnAnUnreadableSession() {
    // given
    revocation.register(firstRepository, firstRevoker);
    final var session = new MapSession();
    session.setAttribute(
        SPRING_SECURITY_CONTEXT_KEY, new SecurityContextImpl(oauth2Authentication()));
    session.setAttribute(AUTHORIZED_CLIENTS_ATTRIBUTE, "not a map");

    // then
    assertThatCode(() -> revocation.revoke(session)).doesNotThrowAnyException();
    verifyNoInteractions(executor);
  }

  @Test
  void shouldShutDownTheExecutorOnClose() {
    // when
    revocation.close();

    // then
    verify(executor).shutdown();
  }

  private void runInline() {
    doAnswer(
            invocation -> {
              invocation.<Runnable>getArgument(0).run();
              return null;
            })
        .when(executor)
        .execute(any());
  }

  @SuppressWarnings({"unchecked", "rawtypes"})
  private static ArgumentCaptor<Supplier<OAuth2AuthorizedClient>> supplierCaptor() {
    return (ArgumentCaptor) ArgumentCaptor.forClass(Supplier.class);
  }

  private static Session expiredSession(final OAuth2AuthorizedClient client) {
    final var session = new MapSession();
    session.setAttribute(
        SPRING_SECURITY_CONTEXT_KEY, new SecurityContextImpl(oauth2Authentication()));
    session.setAttribute(AUTHORIZED_CLIENTS_ATTRIBUTE, Map.of(REGISTRATION_ID, client));
    return session;
  }

  private static OAuth2AuthenticationToken oauth2Authentication() {
    final var idToken =
        new OidcIdToken(
            "id-token", Instant.now(), Instant.now().plusSeconds(60), Map.of("sub", "user"));
    final var authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
    return new OAuth2AuthenticationToken(
        new DefaultOidcUser(authorities, idToken), authorities, REGISTRATION_ID);
  }

  private static ClientRegistration registration(final String clientId, final String tokenUri) {
    return registration(clientId, tokenUri, null);
  }

  private static ClientRegistration registration(
      final String clientId, final String tokenUri, final String revocationUri) {
    return ClientRegistration.withRegistrationId(REGISTRATION_ID)
        .clientId(clientId)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("https://app.example.com/sso-callback")
        .authorizationUri("https://idp.example.com/oauth2/authorize")
        .tokenUri(tokenUri)
        .providerConfigurationMetadata(
            revocationUri == null ? Map.of() : Map.of("revocation_endpoint", revocationUri))
        .build();
  }

  private static OAuth2AuthorizedClient authorizedClient(
      final ClientRegistration registration, final String refreshToken) {
    final var accessToken =
        new OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            "access-token",
            Instant.now(),
            Instant.now().plusSeconds(60));
    return new OAuth2AuthorizedClient(
        registration,
        "user",
        accessToken,
        refreshToken == null ? null : new OAuth2RefreshToken(refreshToken, Instant.now()));
  }

  private static Logger logger() {
    return (Logger) LoggerFactory.getLogger(ExpiredSessionRefreshTokenRevocation.class);
  }
}
