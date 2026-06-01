/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.session;

import java.util.Map;
import java.util.Objects;

/**
 * Framework-free boundary record passed across {@code SessionStorePort}. Carries the persisted
 * representation of a web session: its id, lifecycle timestamps (epoch millis), the maximum
 * inactive interval (seconds), and the serialized session attributes keyed by name.
 *
 * <p>Host adapters map this record to and from their own storage entities.
 */
public record PersistentSession(
    String id,
    Long creationTime,
    Long lastAccessedTime,
    Long maxInactiveIntervalInSeconds,
    Map<String, byte[]> attributes) {

  public PersistentSession {
    Objects.requireNonNull(id, "id");
    Objects.requireNonNull(creationTime, "creationTime");
    Objects.requireNonNull(lastAccessedTime, "lastAccessedTime");
    Objects.requireNonNull(maxInactiveIntervalInSeconds, "maxInactiveIntervalInSeconds");
    attributes = attributes == null ? Map.of() : Map.copyOf(attributes);
  }
  }
}
