/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.spi;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Optional;

/**
 * Resolves the web app a request belongs to. Hosts plug in the host-specific derivation — Hub
 * returns a constant, OC derives from the URL path, etc.
 *
 * <p>Returning {@link Optional#empty()} signals "this request doesn't belong to a web app" (e.g.
 * top-level navigation). Authorization filters that consume this SPI treat the empty case as a
 * pass-through.
 */
@FunctionalInterface
public interface WebAppProvider {

  Optional<String> webAppFor(HttpServletRequest request);
}
