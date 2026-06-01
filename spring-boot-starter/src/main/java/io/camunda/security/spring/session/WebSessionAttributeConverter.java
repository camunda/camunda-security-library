/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.session;

/**
 * Converts session attribute values to and from their serialized byte representation. Hosts may
 * provide their own implementation to control the (de)serialization strategy.
 *
 * <p>Implementations must not return {@code null} from either method. If a value cannot be
 * converted — e.g. an unsupported attribute type, schema evolution across deploys, or corrupt bytes
 * — the implementation should throw. {@code WebSessionMapper.fromPersistentSession} catches the
 * throwable, logs it, and deletes the unrestorable session deliberately; returning {@code null}
 * would reach that same path via a swallowed {@link NullPointerException} inside the mapper's
 * attribute-collection step, which is harder to diagnose.
 */
public interface WebSessionAttributeConverter {

  /**
   * Deserializes the given bytes back into an attribute value. Must not return {@code null} — throw
   * if the value cannot be restored.
   */
  Object deserialize(final byte[] value);

  /**
   * Serializes the given attribute value to bytes. Must not return {@code null} — throw if the
   * value cannot be serialized.
   */
  byte[] serialize(final Object value);
}
