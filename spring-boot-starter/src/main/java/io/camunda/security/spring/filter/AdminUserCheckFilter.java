/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.filter;

import io.camunda.security.core.port.out.AdminUserPresencePort;
import io.camunda.security.spring.spi.AdminUserMissingHandler;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Filter that ensures an admin user has been provisioned before letting requests reach the
 * application. The host plugs in:
 *
 * <ul>
 *   <li>{@link AdminUserPresencePort} — reports whether an admin user currently exists. The host's
 *       implementation may consult static configuration, live storage, or any combination.
 *   <li>{@link AdminUserMissingHandler} — invoked when no admin user exists. Hosts decide the
 *       response shape (redirect to a setup wizard, JSON 403, RequestDispatcher.forward, etc.).
 *   <li>The set of request-URI fragments that bypass the check entirely (typically the setup
 *       endpoint plus its static assets, sourced from {@link
 *       io.camunda.security.core.port.out.SecurityPathPort#adminFilterBypassPaths()}). The
 *       comparison is plain {@link String#contains(CharSequence)} so a single entry like {@code
 *       "/admin/setup"} matches both the exact URI and any sub-path the setup UI loads.
 * </ul>
 *
 * <p>If {@link AdminUserPresencePort#adminUserExists()} throws, the filter logs the error and
 * passes the request through. This is intentional — typically a transient secondary-storage outage
 * — and matches the behaviour of the source filter the lift is rewired from.
 */
public final class AdminUserCheckFilter extends OncePerRequestFilter {

  private static final Logger LOG = LoggerFactory.getLogger(AdminUserCheckFilter.class);

  private final AdminUserPresencePort presencePort;
  private final AdminUserMissingHandler missingHandler;
  private final Set<String> bypassPaths;

  public AdminUserCheckFilter(
      final AdminUserPresencePort presencePort,
      final AdminUserMissingHandler missingHandler,
      final Set<String> bypassPaths) {
    this.presencePort = presencePort;
    this.missingHandler = missingHandler;
    this.bypassPaths = Set.copyOf(bypassPaths);
  }

  @Override
  protected void doFilterInternal(
      final HttpServletRequest request,
      final HttpServletResponse response,
      final FilterChain filterChain)
      throws ServletException, IOException {

    if (isBypassed(request)) {
      filterChain.doFilter(request, response);
      return;
    }

    final boolean adminExists;
    try {
      adminExists = presencePort.adminUserExists();
    } catch (final RuntimeException ex) {
      LOG.error("Error while checking admin user presence. Letting the request pass through.", ex);
      filterChain.doFilter(request, response);
      return;
    }

    if (adminExists) {
      filterChain.doFilter(request, response);
      return;
    }

    LOG.debug(
        "No admin user provisioned; handing off to AdminUserMissingHandler for {}",
        request.getRequestURI());
    missingHandler.handle(request, response);
  }

  private boolean isBypassed(final HttpServletRequest request) {
    final String uri = request.getRequestURI();
    return bypassPaths.stream().anyMatch(uri::contains);
  }
}
