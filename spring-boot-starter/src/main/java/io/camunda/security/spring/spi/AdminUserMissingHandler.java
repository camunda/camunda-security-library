/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.spi;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Decides what to do when the admin-user setup filter detects that no admin user has been
 * provisioned. Hosts implement this SPI to redirect the browser to a setup wizard, render a JSON
 * payload, forward to a static page, or apply any other behaviour appropriate for the host.
 *
 * <p>This SPI lives in the starter (not {@code core}) because its signature speaks {@code
 * jakarta.servlet} types; {@code core} is servlet-free by design.
 */
@FunctionalInterface
public interface AdminUserMissingHandler {

  void handle(HttpServletRequest request, HttpServletResponse response)
      throws IOException, ServletException;
}
