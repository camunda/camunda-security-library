/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static io.camunda.security.spring.security.ExpiredSessionRefreshTokenRevocation.AUTHORIZED_CLIENTS_ATTRIBUTE;
import static io.camunda.security.spring.security.ExpiredSessionRefreshTokenRevocation.LOOKUP_BACKOFF;
import static io.camunda.security.spring.security.ExpiredSessionRefreshTokenRevocation.MAX_LANES;
import static io.camunda.security.spring.security.ExpiredSessionRefreshTokenRevocation.QUEUE_CAPACITY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.web.context.HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.spring.oidc.LazyClientRegistrationRepository;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicLong;
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
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
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
  private static final HttpSessionOAuth2AuthorizedClientRepository SESSION_CLIENTS =
      new HttpSessionOAuth2AuthorizedClientRepository();

  @Mock private ExecutorService executor;
  @Mock private ClientRegistrationRepository firstRepository;
  @Mock private ClientRegistrationRepository secondRepository;
  @Mock private LazyClientRegistrationRepository lazyRepository;
  @Mock private LazyClientRegistrationRepository otherLazyRepository;
  @Mock private RefreshTokenRevoker firstRevoker;
  @Mock private RefreshTokenRevoker secondRevoker;

  private ExpiredSessionRefreshTokenRevocation revocation;
  private ListAppender<ILoggingEvent> logs;
  private final AtomicLong now = new AtomicLong();
  private final List<Runnable> held = new CopyOnWriteArrayList<>();

  @BeforeEach
  void setUp() {
    revocation = revocationWithCapacity(QUEUE_CAPACITY, Duration.ofSeconds(5));
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
    revocation.register(firstRepository, SESSION_CLIENTS, firstRevoker);

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
    revocation.register(firstRepository, SESSION_CLIENTS, firstRevoker);
    revocation.register(secondRepository, SESSION_CLIENTS, secondRevoker);

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
    revocation.register(lazyRepository, SESSION_CLIENTS, firstRevoker);
    revocation.register(secondRepository, SESSION_CLIENTS, secondRevoker);

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
    revocation.register(lazyRepository, SESSION_CLIENTS, firstRevoker);
    revocation.register(otherLazyRepository, SESSION_CLIENTS, firstRevoker);
    revocation.register(secondRepository, SESSION_CLIENTS, secondRevoker);

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
    revocation.register(lazyRepository, SESSION_CLIENTS, firstRevoker);

    // when
    revocation.revoke(expiredSession(authorizedClient(registration, "refresh")));

    // then
    verify(firstRevoker).revoke(eq(registration), any());
  }

  @Test
  void shouldRevokeASessionStoredBeforeTheProviderSwitchedToIssuerDiscovery() {
    // given - the session has no issuer, because the provider then used explicit endpoints
    runInline();
    final var stored = registration(CLIENT_ID, TOKEN_URI);
    final var discovered =
        ClientRegistration.withClientRegistration(stored).issuerUri(ISSUER).build();
    final var config = new OidcConfiguration();
    config.setClientId(CLIENT_ID);
    config.setIssuerUri(ISSUER);
    when(lazyRepository.providers()).thenReturn(Map.of(REGISTRATION_ID, config));
    when(lazyRepository.findByRegistrationId(REGISTRATION_ID)).thenReturn(discovered);
    revocation.register(lazyRepository, SESSION_CLIENTS, firstRevoker);

    // when
    revocation.revoke(expiredSession(authorizedClient(stored, "refresh")));

    // then
    verify(firstRevoker).revoke(eq(discovered), any());
  }

  @Test
  void shouldRevokeOnceWhenSeveralChainsOwnTheClientWithTheSameRevocationSettings() {
    // given
    runInline();
    final var registration = registration(CLIENT_ID, TOKEN_URI, REVOCATION_URI);
    when(firstRepository.findByRegistrationId(REGISTRATION_ID)).thenReturn(registration);
    when(secondRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(registration(CLIENT_ID, TOKEN_URI, REVOCATION_URI));
    revocation.register(firstRepository, SESSION_CLIENTS, firstRevoker);
    revocation.register(secondRepository, SESSION_CLIENTS, secondRevoker);

    // when
    revocation.revoke(expiredSession(authorizedClient(registration, "refresh")));

    // then
    verify(firstRevoker).revoke(eq(registration), any());
    verify(secondRevoker, never()).revoke(any(), any());
  }

  @Test
  void shouldRevokeThroughTheChainThatAuthenticatesLikeTheSession() {
    // given - two chains own the client; the first uses an authentication the revoker cannot send
    runInline();
    final var basic = registration(CLIENT_ID, TOKEN_URI, REVOCATION_URI);
    final var secretJwt =
        ClientRegistration.withClientRegistration(basic)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
            .build();
    when(firstRepository.findByRegistrationId(REGISTRATION_ID)).thenReturn(secretJwt);
    when(secondRepository.findByRegistrationId(REGISTRATION_ID)).thenReturn(basic);
    revocation.register(firstRepository, SESSION_CLIENTS, firstRevoker);
    revocation.register(secondRepository, SESSION_CLIENTS, secondRevoker);

    // when - the session logged in through the client_secret_basic chain
    revocation.revoke(expiredSession(authorizedClient(basic, "refresh")));

    // then
    verify(firstRevoker, never()).revoke(any(), any());
    verify(secondRevoker).revoke(eq(basic), any());
  }

  @Test
  void shouldRevokeThroughAChainThatCanSignWhenTheFirstHasNoSigningKey() {
    // given - two private_key_jwt chains own the client; only the second has a signing key
    runInline();
    final var keyJwt =
        ClientRegistration.withClientRegistration(
                registration(CLIENT_ID, TOKEN_URI, REVOCATION_URI))
            .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
            .build();
    when(firstRepository.findByRegistrationId(REGISTRATION_ID)).thenReturn(keyJwt);
    when(secondRepository.findByRegistrationId(REGISTRATION_ID)).thenReturn(keyJwt);
    when(firstRevoker.canAuthenticate(keyJwt)).thenReturn(false);
    when(secondRevoker.canAuthenticate(keyJwt)).thenReturn(true);
    revocation.register(firstRepository, SESSION_CLIENTS, firstRevoker);
    revocation.register(secondRepository, SESSION_CLIENTS, secondRevoker);

    // when
    revocation.revoke(expiredSession(authorizedClient(keyJwt, "refresh")));

    // then
    verify(firstRevoker, never()).revoke(any(), any());
    verify(secondRevoker).revoke(eq(keyJwt), any());
  }

  @Test
  void shouldNotRevokeWhenTheChainsThatOwnTheClientDisagreeOnRevocation() {
    // given - one scope opted out of revocation, the other did not
    runInline();
    final var enabled = registration(CLIENT_ID, TOKEN_URI, REVOCATION_URI);
    when(firstRepository.findByRegistrationId(REGISTRATION_ID)).thenReturn(enabled);
    when(secondRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(registration(CLIENT_ID, TOKEN_URI));
    revocation.register(firstRepository, SESSION_CLIENTS, firstRevoker);
    revocation.register(secondRepository, SESSION_CLIENTS, secondRevoker);
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
    revocation.register(firstRepository, SESSION_CLIENTS, firstRevoker);
    revocation.register(secondRepository, SESSION_CLIENTS, secondRevoker);

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
    revocation.register(firstRepository, SESSION_CLIENTS, firstRevoker);
    final var session = expiredSession(authorizedClient(registration, "refresh"));

    // when - each after the back-off, so each looks the registration up
    for (int i = 0; i < 4; i++) {
      now.addAndGet(LOOKUP_BACKOFF.toNanos() + 1);
      revocation.revoke(session);
    }

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
    revocation.register(firstRepository, SESSION_CLIENTS, firstRevoker);

    // when
    revocation.revoke(expiredSession(authorizedClient(registration, "refresh")));

    // then
    verifyNoInteractions(firstRevoker);
  }

  @Test
  void shouldNotScheduleAnythingForASessionWithoutARefreshToken() {
    // given
    revocation.register(firstRepository, SESSION_CLIENTS, firstRevoker);
    final var client = authorizedClient(registration(CLIENT_ID, TOKEN_URI), null);

    // when
    revocation.revoke(expiredSession(client));

    // then
    verifyNoInteractions(executor, firstRepository, firstRevoker);
  }

  @Test
  void shouldNotScheduleAnythingForASessionThatIsNotAnOidcLogin() {
    // given
    revocation.register(firstRepository, SESSION_CLIENTS, firstRevoker);
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
  void shouldNotLookUpARegistrationAgainDuringTheBackOff() {
    // given a chain whose provider cannot be reached
    runInline();
    final var registration = registration(CLIENT_ID, TOKEN_URI, REVOCATION_URI);
    when(firstRepository.findByRegistrationId(REGISTRATION_ID))
        .thenThrow(new IllegalStateException("discovery timed out"));
    revocation.register(firstRepository, SESSION_CLIENTS, firstRevoker);
    final var session = expiredSession(authorizedClient(registration, "refresh"));

    // when
    revocation.revoke(session);
    revocation.revoke(session);
    now.addAndGet(LOOKUP_BACKOFF.toNanos() + 1);
    revocation.revoke(session);

    // then the second session does not start another discovery, the third does
    verify(firstRepository, times(2)).findByRegistrationId(REGISTRATION_ID);
    verifyNoInteractions(firstRevoker);
  }

  @Test
  void shouldWarnOnceWhileALaneStaysFullAndAgainForTheNextBacklog() {
    // given a lane with room for two revocations, whose revocations are held
    revocation = revocationWithCapacity(2, Duration.ofSeconds(5));
    holdTasks();
    revocation.register(firstRepository, SESSION_CLIENTS, firstRevoker);
    final var session = expiredSession(authorizedClient(registration(CLIENT_ID, TOKEN_URI), "r"));

    // when the lane fills, and the worker finishes one task while new ones keep it full
    revocation.revoke(session);
    revocation.revoke(session);
    revocation.revoke(session);
    held.removeFirst().run();
    revocation.revoke(session);
    revocation.revoke(session);
    // and then the backlog drains, and the lane fills again
    held.removeFirst().run();
    held.removeFirst().run();
    revocation.revoke(session);
    revocation.revoke(session);
    revocation.revoke(session);

    // then one WARN per backlog, not one per finished task
    assertThat(logs.list)
        .filteredOn(event -> event.getLevel() == Level.WARN)
        .hasSize(2)
        .allSatisfy(
            event ->
                assertThat(event.getFormattedMessage())
                    .contains("its revocation queue is full")
                    .contains(TOKEN_URI)
                    .doesNotContain("refresh-token-value"));
  }

  @Test
  void shouldNotLetAFullLaneHoldUpTheRevocationsOfAnotherProvider() {
    // given the lane of an unreachable provider is full
    revocation = revocationWithCapacity(1, Duration.ofSeconds(5));
    holdTasks();
    revocation.register(firstRepository, SESSION_CLIENTS, firstRevoker);
    final var down =
        expiredSession(
            authorizedClient(registration(CLIENT_ID, "https://down.example.com/token"), "r"));
    revocation.revoke(down);
    revocation.revoke(down);

    // when a session of another provider expires
    revocation.revoke(expiredSession(authorizedClient(registration(CLIENT_ID, TOKEN_URI), "r")));

    // then its revocation is queued on its own lane
    assertThat(held).hasSize(2);
  }

  @Test
  void shouldLetTheSweepWaitForRoomInAFullLane() throws Exception {
    // given a full lane whose worker finishes its task shortly
    revocation = revocationWithCapacity(1, Duration.ofSeconds(5));
    holdTasks();
    revocation.register(firstRepository, SESSION_CLIENTS, firstRevoker);
    final var session = expiredSession(authorizedClient(registration(CLIENT_ID, TOKEN_URI), "r"));
    revocation.revokeFromSweep(session, () -> session);
    final var worker =
        Thread.ofVirtual()
            .start(
                () -> {
                  sleep(Duration.ofMillis(100));
                  held.removeFirst().run();
                });

    // when
    revocation.revokeFromSweep(session, () -> session);
    worker.join();

    // then the sweep's revocation is queued, not dropped
    assertThat(held).hasSize(1);
    assertThat(logs.list).noneMatch(event -> event.getLevel() == Level.WARN);
  }

  @Test
  void shouldNotRevokeFromTheSweepWhenTheSessionIsNoLongerExpired() {
    // given a lane with room for one revocation
    revocation = revocationWithCapacity(1, Duration.ofSeconds(5));
    runInline();
    final var registration = registration(CLIENT_ID, TOKEN_URI);
    when(firstRepository.findByRegistrationId(REGISTRATION_ID)).thenReturn(registration);
    revocation.register(firstRepository, SESSION_CLIENTS, firstRevoker);
    final var session = expiredSession(authorizedClient(registration, "refresh"));

    // when a request, such as a heartbeat, used the session while the sweep waited
    revocation.revokeFromSweep(session, () -> null);

    // then nothing is revoked, and the lane has its room back
    verify(firstRevoker, never()).revoke(any(), any());
    revocation.revoke(session);
    verify(firstRevoker).revoke(eq(registration), any());
  }

  @Test
  void shouldRevokeFromTheSweepTheTokenTheSessionHoldsNow() {
    // given a session whose token was refreshed after the sweep's snapshot
    runInline();
    final var registration = registration(CLIENT_ID, TOKEN_URI);
    when(firstRepository.findByRegistrationId(REGISTRATION_ID)).thenReturn(registration);
    revocation.register(firstRepository, SESSION_CLIENTS, firstRevoker);
    final var refreshed = authorizedClient(registration, "refreshed");

    // when
    revocation.revokeFromSweep(
        expiredSession(authorizedClient(registration, "stale")), () -> expiredSession(refreshed));

    // then
    final ArgumentCaptor<Supplier<OAuth2AuthorizedClient>> supplier = supplierCaptor();
    verify(firstRevoker).revoke(eq(registration), supplier.capture());
    assertThat(supplier.getValue().get()).isSameAs(refreshed);
  }

  @Test
  void shouldLetTheSweepWaitOnlyOncePerBacklog() {
    // given a full lane whose worker does not finish
    final var sweepWait = Duration.ofMillis(500);
    revocation = revocationWithCapacity(1, sweepWait);
    holdTasks();
    revocation.register(firstRepository, SESSION_CLIENTS, firstRevoker);
    final var session = expiredSession(authorizedClient(registration(CLIENT_ID, TOKEN_URI), "r"));
    revocation.revokeFromSweep(session, () -> session);

    // when
    final long firstDrop = timed(() -> revocation.revokeFromSweep(session, () -> session));
    final long secondDrop = timed(() -> revocation.revokeFromSweep(session, () -> session));

    // then only the first drop waited
    assertThat(firstDrop).isGreaterThanOrEqualTo(sweepWait.toMillis());
    assertThat(secondDrop).isLessThan(sweepWait.toMillis() / 2);
    assertThat(held).hasSize(1);
  }

  @Test
  void shouldRedactTheTokenEndpointInTheQueueFullWarning() {
    // given a full lane whose token endpoint carries credentials and a query secret
    revocation = revocationWithCapacity(1, Duration.ofSeconds(5));
    holdTasks();
    revocation.register(firstRepository, SESSION_CLIENTS, firstRevoker);
    final var session =
        expiredSession(
            authorizedClient(
                registration(CLIENT_ID, "https://user:secret@idp.example.com/token?key=abc"), "r"));

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
                    .contains("@idp.example.com/token")
                    .doesNotContain("user")
                    .doesNotContain("secret")
                    .doesNotContain("key=abc"));
  }

  @Test
  void shouldNotExceedTheLaneBoundForConcurrentNewProviders() throws Exception {
    // given
    holdTasks();
    revocation.register(firstRepository, SESSION_CLIENTS, firstRevoker);
    final int providers = MAX_LANES * 3;
    final var start = new CountDownLatch(1);
    final List<Thread> threads = new ArrayList<>();
    for (int i = 0; i < providers; i++) {
      final var session =
          expiredSession(
              authorizedClient(registration(CLIENT_ID, "https://idp-" + i + ".example.com"), "r"));
      threads.add(
          Thread.ofPlatform()
              .start(
                  () -> {
                    awaitQuietly(start);
                    revocation.revoke(session);
                  }));
    }

    // when
    start.countDown();
    for (final Thread thread : threads) {
      thread.join();
    }

    // then the providers beyond the bound share one more lane
    assertThat(revocation.laneCount()).isEqualTo(MAX_LANES + 1);
  }

  @Test
  void shouldStopWaitingInTheSweepOnceTheBacklogUsedItsBudget() throws Exception {
    // given a full lane of two whose worker frees one place every 100 ms, so the backlog never
    // drains, and a 300 ms budget
    revocation = revocationWithCapacity(2, Duration.ofSeconds(1), Duration.ofMillis(300));
    holdTasks();
    revocation.register(firstRepository, SESSION_CLIENTS, firstRevoker);
    final var session = expiredSession(authorizedClient(registration(CLIENT_ID, TOKEN_URI), "r"));
    revocation.revokeFromSweep(session, () -> session);
    revocation.revokeFromSweep(session, () -> session);
    final var worker =
        Thread.ofPlatform()
            .daemon()
            .start(
                () -> {
                  while (!Thread.currentThread().isInterrupted()) {
                    sleep(Duration.ofMillis(100));
                    if (!held.isEmpty()) {
                      held.removeFirst().run();
                    }
                  }
                });

    // when the sweep keeps finding the lane full
    final long elapsed =
        timed(
            () -> {
              for (int i = 0; i < 20; i++) {
                revocation.revokeFromSweep(session, () -> session);
              }
            });
    worker.interrupt();
    worker.join();

    // then it waited about the budget, not once for each session, and then dropped
    assertThat(elapsed).isLessThan(1_000);
    assertThat(logs.list)
        .filteredOn(event -> event.getLevel() == Level.WARN)
        .anySatisfy(
            event ->
                assertThat(event.getFormattedMessage()).contains("its revocation queue is full"));
  }

  @Test
  void shouldNotCheckHowOwnersAuthenticateWhenThereIsNoRevocationEndpoint() {
    // given two chains of one client whose provider has no revocation endpoint
    runInline();
    final var registration = registration(CLIENT_ID, TOKEN_URI);
    when(firstRepository.findByRegistrationId(REGISTRATION_ID)).thenReturn(registration);
    when(secondRepository.findByRegistrationId(REGISTRATION_ID)).thenReturn(registration);
    revocation.register(firstRepository, SESSION_CLIENTS, firstRevoker);
    revocation.register(secondRepository, SESSION_CLIENTS, secondRevoker);

    // when
    revocation.revoke(expiredSession(authorizedClient(registration, "refresh")));

    // then the first owner's revoker takes its no-endpoint path, and no signing key is loaded
    verify(firstRevoker).revoke(eq(registration), any());
    verify(firstRevoker, never()).canAuthenticate(any());
    verify(secondRevoker, never()).canAuthenticate(any());
  }

  @Test
  void shouldNotCheckHowTheOnlyOwnerAuthenticates() {
    // given one private_key_jwt chain, whose check would load its signing key
    runInline();
    final var registration =
        ClientRegistration.withClientRegistration(
                registration(CLIENT_ID, TOKEN_URI, REVOCATION_URI))
            .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
            .build();
    when(firstRepository.findByRegistrationId(REGISTRATION_ID)).thenReturn(registration);
    revocation.register(firstRepository, SESSION_CLIENTS, firstRevoker);

    // when
    revocation.revoke(expiredSession(authorizedClient(registration, "refresh")));

    // then the key is loaded once, to sign the request
    verify(firstRevoker).revoke(eq(registration), any());
    verify(firstRevoker, never()).canAuthenticate(any());
  }

  @Test
  void shouldRevokeThroughTheChainWithTheSecretOfTheSession() {
    // given two chains of one client during a secret rotation; the session used the new secret
    runInline();
    final var oldSecret =
        ClientRegistration.withClientRegistration(
                registration(CLIENT_ID, TOKEN_URI, REVOCATION_URI))
            .clientSecret("old-secret")
            .build();
    final var newSecret =
        ClientRegistration.withClientRegistration(oldSecret).clientSecret("new-secret").build();
    when(firstRepository.findByRegistrationId(REGISTRATION_ID)).thenReturn(oldSecret);
    when(secondRepository.findByRegistrationId(REGISTRATION_ID)).thenReturn(newSecret);
    when(firstRevoker.canAuthenticate(any())).thenReturn(true);
    when(secondRevoker.canAuthenticate(any())).thenReturn(true);
    revocation.register(firstRepository, SESSION_CLIENTS, firstRevoker);
    revocation.register(secondRepository, SESSION_CLIENTS, secondRevoker);

    // when
    revocation.revoke(expiredSession(authorizedClient(newSecret, "refresh")));

    // then
    verify(firstRevoker, never()).revoke(any(), any());
    verify(secondRevoker).revoke(eq(newSecret), any());
  }

  @Test
  void shouldRevokeThroughTheChainWhoseSigningKeyLoads() {
    // given two chains of one private_key_jwt client; the first chain's keystore is unreadable
    runInline();
    final var registration =
        ClientRegistration.withClientRegistration(
                registration(CLIENT_ID, TOKEN_URI, REVOCATION_URI))
            .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
            .build();
    final var broken =
        spy(
            new RefreshTokenRevoker(
                ignored -> {
                  throw new IllegalStateException("keystore not found");
                }));
    final var healthy = spy(new RefreshTokenRevoker(ignored -> signingKey()));
    doNothing().when(healthy).revoke(any(), any());
    when(firstRepository.findByRegistrationId(REGISTRATION_ID)).thenReturn(registration);
    when(secondRepository.findByRegistrationId(REGISTRATION_ID)).thenReturn(registration);
    revocation.register(firstRepository, SESSION_CLIENTS, broken);
    revocation.register(secondRepository, SESSION_CLIENTS, healthy);

    // when
    revocation.revoke(expiredSession(authorizedClient(registration, "refresh")));

    // then
    verify(healthy).revoke(eq(registration), any());
    verify(broken, never()).revoke(any(), any());
  }

  @Test
  void shouldWarnWhenAChainDoesNotStoreItsAuthorizedClientsInTheSession() {
    // when
    revocation.register(
        firstRepository, mock(OAuth2AuthorizedClientRepository.class), firstRevoker);

    // then
    assertThat(logs.list)
        .filteredOn(event -> event.getLevel() == Level.WARN)
        .singleElement()
        .satisfies(
            event ->
                assertThat(event.getFormattedMessage())
                    .contains("not in the web session")
                    .contains("Logout still revokes them"));
  }

  @Test
  void shouldNeverThrowOnAnUnreadableSession() {
    // given
    revocation.register(firstRepository, SESSION_CLIENTS, firstRevoker);
    final var session = new MapSession();
    session.setAttribute(
        SPRING_SECURITY_CONTEXT_KEY, new SecurityContextImpl(oauth2Authentication()));
    session.setAttribute(AUTHORIZED_CLIENTS_ATTRIBUTE, "not a map");

    // then
    assertThatCode(() -> revocation.revoke(session)).doesNotThrowAnyException();
    verifyNoInteractions(executor);
  }

  @Test
  void shouldShutDownTheLanesOnClose() {
    // given a lane
    runInline();
    revocation.register(firstRepository, SESSION_CLIENTS, firstRevoker);
    revocation.revoke(expiredSession(authorizedClient(registration(CLIENT_ID, TOKEN_URI), "r")));

    // when
    revocation.close();

    // then
    verify(executor).shutdown();
  }

  private ExpiredSessionRefreshTokenRevocation revocationWithCapacity(
      final int capacity, final Duration sweepWait) {
    return revocationWithCapacity(capacity, sweepWait, Duration.ofMinutes(5));
  }

  private ExpiredSessionRefreshTokenRevocation revocationWithCapacity(
      final int capacity, final Duration sweepWait, final Duration sweepWaitBudget) {
    return new ExpiredSessionRefreshTokenRevocation(
        () -> executor, capacity, sweepWait, sweepWaitBudget, now::get);
  }

  /** Queues the revocations instead of running them; a test runs them from {@link #held}. */
  private void holdTasks() {
    doAnswer(
            invocation -> {
              held.add(invocation.getArgument(0));
              return null;
            })
        .when(executor)
        .execute(any());
  }

  private static void awaitQuietly(final CountDownLatch latch) {
    try {
      latch.await();
    } catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  private static RSAKey signingKey() {
    try {
      return new RSAKeyGenerator(2048).keyID("kid").generate();
    } catch (final JOSEException e) {
      throw new IllegalStateException(e);
    }
  }

  private static long timed(final Runnable action) {
    final long start = System.nanoTime();
    action.run();
    return Duration.ofNanos(System.nanoTime() - start).toMillis();
  }

  private static void sleep(final Duration duration) {
    try {
      Thread.sleep(duration);
    } catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
    }
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
