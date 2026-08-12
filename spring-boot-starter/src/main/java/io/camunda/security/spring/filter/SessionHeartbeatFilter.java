/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.filter;

import io.camunda.security.spring.security.CamundaSecurityFilterChainConstants;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Terminal filter for the session activity-heartbeat endpoint ({@code POST
 * {basePath}/session/heartbeat}, ADR-0042). Responds {@code 204 No Content} and does not continue
 * the filter chain — there is no further processing a heartbeat call needs.
 *
 * <p>This filter has no knowledge of {@code camunda.security.session.heartbeat.enabled}; its only
 * job is to give the endpoint a response instead of a 404. Whether hitting it actually has any
 * special effect on the session's activity is decided independently by {@code
 * WebSessionRepository}, which recognizes the same request via the exact same {@link
 * CamundaSecurityFilterChainConstants#isHeartbeatRequest} check this filter uses — so the two stay
 * in agreement on what counts as a heartbeat call without having to coordinate directly.
 *
 * <p>Installed on every webapp chain — the primary surface and every physical-tenant scope, both
 * OIDC and Basic-auth — immediately after {@code AuthorizationFilter}, so a heartbeat call reaching
 * this filter is already known-authenticated on both auth modes before it short-circuits with 204.
 * On the <b>OIDC</b> chains, that fell out of the chain's existing {@code
 * anyRequest().authenticated()} rule for free. On the <b>Basic-auth</b> chains it does not: those
 * chains otherwise configure {@code anyRequest().permitAll()} at the {@code authorizeHttpRequests}
 * layer and gate business paths downstream via {@code AdminUserCheckFilter}/{@code
 * WebAppAuthorizationCheckFilter} instead — filters this one is deliberately positioned ahead of,
 * and which the heartbeat path has no equivalent of. The Basic chain builders therefore carve out
 * an explicit {@code requestMatchers(heartbeatUrl).authenticated()} rule ahead of their {@code
 * permitAll()} catch-all, specifically for this path.
 */
public final class SessionHeartbeatFilter extends OncePerRequestFilter {

  @Override
  protected void doFilterInternal(
      final HttpServletRequest request,
      final HttpServletResponse response,
      final FilterChain filterChain)
      throws ServletException, IOException {
    if (CamundaSecurityFilterChainConstants.isHeartbeatRequest(request)) {
      response.setStatus(HttpServletResponse.SC_NO_CONTENT);
      return;
    }
    filterChain.doFilter(request, response);
  }
}
