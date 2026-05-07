/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.context.holder;

import static io.camunda.security.spring.context.holder.HttpSessionBasedAuthenticationHolder.CAMUNDA_AUTHENTICATION_SESSION_HOLDER_KEY;
import static io.camunda.security.spring.context.holder.HttpSessionBasedAuthenticationHolder.LAST_REFRESH_ATTR;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.config.AuthenticationConfiguration;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpSession;

@ExtendWith(MockitoExtension.class)
public class HttpSessionBasedAuthenticationHolderTest {

  @Mock private HttpServletRequest request;
  @Mock private AuthenticationConfiguration authenticationConfiguration;
  private HttpSessionBasedAuthenticationHolder holder;

  @BeforeEach
  void setup() {
    when(authenticationConfiguration.getAuthenticationRefreshInterval()).thenReturn("PT1S");
    holder = new HttpSessionBasedAuthenticationHolder(request, authenticationConfiguration);
  }

  @Test
  public void shouldSupportWhenSessionExists() {
    // given
    final var session = mock(HttpSession.class);
    when(request.getSession(eq(false))).thenReturn(session);

    // when
    final var result = holder.supports();

    // then
    assertThat(result).isTrue();
  }

  @Test
  public void shouldNotSupportWhenSessionDoesNotExist() {
    // given
    when(request.getSession(eq(false))).thenReturn(null);

    // when
    final var result = holder.supports();

    // then
    assertThat(result).isFalse();
  }

  @Test
  public void shouldReturnAuthentication() {
    // given
    final var authentication = mock(CamundaAuthentication.class);
    final var session = new MockHttpSession();

    when(request.getSession(eq(false))).thenReturn(session);
    holder.set(authentication);

    // when
    final var result = holder.get();

    // then
    assertThat(result).isEqualTo(authentication);
  }

  @Test
  public void shouldAddAuthenticationToSession() {
    // given
    final var authentication = mock(CamundaAuthentication.class);
    final var session = mock(HttpSession.class);

    when(request.getSession(eq(false))).thenReturn(session);

    // when
    holder.set(authentication);

    // then
    verify(session, times(1))
        .setAttribute(eq(CAMUNDA_AUTHENTICATION_SESSION_HOLDER_KEY), eq(authentication));
  }

  @Test
  public void shouldClearAuthenticationFromSession() {
    // given
    final var session = mock(HttpSession.class);
    when(request.getSession(eq(false))).thenReturn(session);

    // when
    holder.clear();

    // then
    verify(session, times(1)).removeAttribute(eq(CAMUNDA_AUTHENTICATION_SESSION_HOLDER_KEY));
  }

  @Test
  public void shouldReturnNullIfAuthenticationNotRefreshed() throws InterruptedException {
    // given
    final var authentication = mock(CamundaAuthentication.class);
    final var session = new MockHttpSession();
    when(authenticationConfiguration.getAuthenticationRefreshInterval()).thenReturn("PT0.1S");
    holder = new HttpSessionBasedAuthenticationHolder(request, authenticationConfiguration);
    when(request.getSession(eq(false))).thenReturn(session);
    holder.set(authentication);
    Thread.sleep(110L);

    // when
    final var result = holder.get();

    // then
    assertThat(result).isEqualTo(null);
  }

  @Test
  public void shouldClearAuthenticationAndUpdateLastRefreshWhenIntervalExpires() {
    // given: a session with authentication set and a last-refresh timestamp in the past
    final var authentication = mock(CamundaAuthentication.class);
    final var session = new MockHttpSession();
    when(authenticationConfiguration.getAuthenticationRefreshInterval()).thenReturn("PT1S");
    holder = new HttpSessionBasedAuthenticationHolder(request, authenticationConfiguration);
    when(request.getSession(eq(false))).thenReturn(session);
    holder.set(authentication);

    // Manually backdate the last-refresh attribute to simulate interval expiry
    final Instant expiredRefresh = Instant.now().minusSeconds(2);
    session.setAttribute(LAST_REFRESH_ATTR, expiredRefresh);

    // when
    final var result = holder.get();

    // then: authentication is cleared and last-refresh is updated
    assertThat(result).isNull();
    final Instant updatedRefresh = (Instant) session.getAttribute(LAST_REFRESH_ATTR);
    assertThat(updatedRefresh).isAfter(expiredRefresh);
  }

  @Test
  public void shouldReturnAuthenticationWhenWithinRefreshInterval() {
    // given: authentication set and last-refresh is recent
    final var authentication = mock(CamundaAuthentication.class);
    final var session = new MockHttpSession();
    when(authenticationConfiguration.getAuthenticationRefreshInterval()).thenReturn("PT30S");
    holder = new HttpSessionBasedAuthenticationHolder(request, authenticationConfiguration);
    when(request.getSession(eq(false))).thenReturn(session);
    holder.set(authentication);

    // when: retrieved before the interval expires
    final var result = holder.get();

    // then: the cached authentication is returned unchanged
    assertThat(result).isEqualTo(authentication);
  }

  @Test
  public void shouldInitializeRefreshAttributesOnFirstSet() {
    // given
    final var authentication = mock(CamundaAuthentication.class);
    final var session = new MockHttpSession();
    when(request.getSession(eq(false))).thenReturn(session);

    // when
    holder.set(authentication);

    // then: both refresh attributes are initialized
    assertThat(session.getAttribute(LAST_REFRESH_ATTR)).isInstanceOf(Instant.class);
    assertThat(session.getAttribute(LAST_REFRESH_ATTR + "_LOCK"))
        .isNotNull()
        .isNotInstanceOf(String.class);
  }

  @Test
  public void shouldNotReinitializeRefreshAttributesOnSubsequentSet() {
    // given: a session that already has refresh attributes
    final var authentication = mock(CamundaAuthentication.class);
    final var session = new MockHttpSession();
    when(request.getSession(eq(false))).thenReturn(session);
    holder.set(authentication);
    final Instant firstRefresh = (Instant) session.getAttribute(LAST_REFRESH_ATTR);
    final Object firstLock = session.getAttribute(LAST_REFRESH_ATTR + "_LOCK");

    // when: set is called again
    holder.set(authentication);

    // then: the existing refresh attributes are not overwritten
    assertThat(session.getAttribute(LAST_REFRESH_ATTR)).isEqualTo(firstRefresh);
    assertThat(session.getAttribute(LAST_REFRESH_ATTR + "_LOCK")).isSameAs(firstLock);
  }
}
