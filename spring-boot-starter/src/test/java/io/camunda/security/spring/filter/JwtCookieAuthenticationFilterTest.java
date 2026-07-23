/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import io.camunda.security.core.port.out.MembershipPort;
import io.camunda.security.spring.spi.JwtCookieTokenPort;
import io.camunda.security.spring.spi.OidcAuthenticationEntryPoint;
import jakarta.servlet.http.Cookie;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

@ExtendWith(MockitoExtension.class)
class JwtCookieAuthenticationFilterTest {

  private static final String COOKIE_NAME = "X-Camunda-Authorization";
  private static final String COOKIE_VALUE = "test.jwt.token";

  @Mock private JwtCookieTokenPort tokenPort;
  @Mock private LazyTokenClaimsConverter tokenClaimsConverter;
  @Mock private OidcAuthenticationEntryPoint authenticationEntryPoint;
  @Mock private MembershipPort membershipPort;

  private JwtCookieAuthenticationFilter filter;

  @BeforeEach
  void setUp() {
    filter =
        new JwtCookieAuthenticationFilter(
            COOKIE_NAME, tokenPort, tokenClaimsConverter, authenticationEntryPoint);
    SecurityContextHolder.clearContext();
  }

  @AfterEach
  void tearDown() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void validCookieSetsAuthenticationInSecurityContext() throws Exception {
    final var claims = Map.<String, Object>of("sub", "alice");
    final var camundaAuth = CamundaAuthentication.of(b -> b.user("alice"));
    when(tokenPort.validate(COOKIE_VALUE)).thenReturn(claims);
    when(tokenClaimsConverter.convert(claims)).thenReturn(camundaAuth);

    final var chain = new MockFilterChain();
    filter.doFilter(
        requestWithCookie(COOKIE_NAME, COOKIE_VALUE), new MockHttpServletResponse(), chain);

    assertThat(chain.getRequest()).isNotNull();
    final var auth = SecurityContextHolder.getContext().getAuthentication();
    assertThat(auth).isInstanceOf(PreAuthenticatedAuthenticationToken.class);
    assertThat(auth.getPrincipal()).isSameAs(camundaAuth);
    assertThat(auth.isAuthenticated()).isTrue();
  }

  @Test
  void missingCookieDelegatesToEntryPointWithoutContinuingChain() throws Exception {
    final var response = new MockHttpServletResponse();
    final var chain = new MockFilterChain();
    filter.doFilter(requestWithoutCookies(), response, chain);

    assertThat(chain.getRequest()).isNull();
    verify(authenticationEntryPoint)
        .commence(any(), eq(response), any(AuthenticationException.class));
    verifyNoInteractions(tokenPort);
    verifyNoInteractions(tokenClaimsConverter);
  }

  @Test
  void invalidTokenDelegatesToEntryPointWithoutContinuingChain() throws Exception {
    when(tokenPort.validate(COOKIE_VALUE)).thenThrow(new BadCredentialsException("expired token"));
    final var response = new MockHttpServletResponse();
    final var chain = new MockFilterChain();
    filter.doFilter(requestWithCookie(COOKIE_NAME, COOKIE_VALUE), response, chain);

    assertThat(chain.getRequest()).isNull();
    verify(authenticationEntryPoint)
        .commence(any(), eq(response), any(AuthenticationException.class));
  }

  @Test
  void conversionExceptionDelegatesToEntryPointWithoutContinuingChain() throws Exception {
    final var claims = Map.<String, Object>of("sub", "alice");
    when(tokenPort.validate(COOKIE_VALUE)).thenReturn(claims);
    when(tokenClaimsConverter.convert(claims))
        .thenThrow(
            new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN)));
    final var response = new MockHttpServletResponse();
    final var chain = new MockFilterChain();
    filter.doFilter(requestWithCookie(COOKIE_NAME, COOKIE_VALUE), response, chain);

    assertThat(chain.getRequest()).isNull();
    verify(authenticationEntryPoint)
        .commence(any(), eq(response), any(AuthenticationException.class));
  }

  @Test
  void alreadyAuthenticatedRequestSkipsFilterCompletely() throws Exception {
    final var existing =
        UsernamePasswordAuthenticationToken.authenticated("alice", null, List.of());
    SecurityContextHolder.getContext().setAuthentication(existing);

    final var chain = new MockFilterChain();
    filter.doFilter(
        requestWithCookie(COOKIE_NAME, COOKIE_VALUE), new MockHttpServletResponse(), chain);

    assertThat(chain.getRequest()).isNotNull();
    verifyNoInteractions(tokenPort);
    verifyNoInteractions(tokenClaimsConverter);
  }

  @Test
  void membershipPortIsCalledLazilyOnFirstFieldRead() throws Exception {
    final var realConverter =
        new LazyTokenClaimsConverter("sub", "azp", false, membershipPort, null);
    final var realFilter =
        new JwtCookieAuthenticationFilter(
            COOKIE_NAME, tokenPort, realConverter, authenticationEntryPoint);

    final var claims = Map.<String, Object>of("sub", "alice");
    when(tokenPort.validate(COOKIE_VALUE)).thenReturn(claims);
    when(membershipPort.groupIds(any())).thenReturn(List.of("g1"));

    final var chain = new MockFilterChain();
    realFilter.doFilter(
        requestWithCookie(COOKIE_NAME, COOKIE_VALUE), new MockHttpServletResponse(), chain);

    // MembershipPort must not be called just from setting authentication
    verify(membershipPort, never()).groupIds(any());
    verify(membershipPort, never()).roleIds(any());
    verify(membershipPort, never()).tenantIds(any());
    verify(membershipPort, never()).mappingRuleIds(any());

    // Reading the field triggers lazy resolution
    final var camundaAuth =
        (CamundaAuthentication)
            SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    assertThat(camundaAuth.authenticatedGroupIds()).containsExactly("g1");
    verify(membershipPort).groupIds(any());
  }

  private static MockHttpServletRequest requestWithCookie(final String name, final String value) {
    final var request = new MockHttpServletRequest();
    request.setCookies(new Cookie(name, value));
    return request;
  }

  private static MockHttpServletRequest requestWithoutCookies() {
    return new MockHttpServletRequest();
  }
}
