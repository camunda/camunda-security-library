/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.spi;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Decides per request whether web app authorization is enabled. Hosts that serve several scopes
 * with their own {@code authorizations.enabled} value (OC: one per physical tenant) plug in the
 * lookup here. Without a host bean, the global {@code camunda.security.authorizations.enabled}
 * applies to every request.
 */
@FunctionalInterface
public interface WebAppAuthorizationEnabledPort {

  boolean isAuthorizationEnabled(HttpServletRequest request);
}
