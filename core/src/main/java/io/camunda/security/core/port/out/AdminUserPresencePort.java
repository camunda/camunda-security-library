/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.out;

/**
 * Outbound port the host application implements to report whether an admin user has been
 * provisioned. The library's admin-user setup filter consults this port to decide whether to allow
 * a request through or hand off to the host's {@code AdminUserMissingHandler}.
 *
 * <p>Hosts may answer from any combination of static configuration and live data lookups — the
 * library does not need to know how presence is determined.
 */
@FunctionalInterface
public interface AdminUserPresencePort {

  boolean adminUserExists();
}
