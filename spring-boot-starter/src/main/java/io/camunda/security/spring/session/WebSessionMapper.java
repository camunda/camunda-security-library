/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.session;

import io.camunda.security.api.model.session.PersistentSession;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.convert.TypeDescriptor;
import org.springframework.core.convert.support.GenericConversionService;
import org.springframework.core.serializer.support.DeserializingConverter;
import org.springframework.core.serializer.support.SerializingConverter;

public final class WebSessionMapper {

  private static final Logger LOGGER = LoggerFactory.getLogger(WebSessionMapper.class);
  private final WebSessionAttributeConverter converter;

  public WebSessionMapper(final WebSessionAttributeConverter converter) {
    this.converter = converter;
  }

  public PersistentSession toPersistentSession(final WebSession webSession) {
    final var attributes = serializeSessionAttributes(webSession);
    return new PersistentSession(
        webSession.getId(),
        webSession.getCreationTime().toEpochMilli(),
        webSession.getLastAccessedTime().toEpochMilli(),
        webSession.getMaxInactiveInterval().getSeconds(),
        attributes);
  }

  public @Nullable WebSession fromPersistentSession(final PersistentSession persistentSession) {
    try {
      final var sessionId = persistentSession.id();
      final var creationTime = persistentSession.creationTime();
      final var lastAccessedTime = persistentSession.lastAccessedTime();
      final var maxInactiveIntervalInSeconds = persistentSession.maxInactiveIntervalInSeconds();
      final var attributes = deserializeSessionAttributes(persistentSession);

      final var webSession = new WebSession(sessionId);
      final var creationInstant = toInstant(creationTime);
      if (creationInstant != null) {
        webSession.setCreationTime(creationInstant);
      }
      final var lastAccessedInstant = toInstant(lastAccessedTime);
      if (lastAccessedInstant != null) {
        webSession.setLastAccessedTime(lastAccessedInstant);
      }
      final var maxInactiveInterval = toDuration(maxInactiveIntervalInSeconds);
      if (maxInactiveInterval != null) {
        webSession.setMaxInactiveInterval(maxInactiveInterval);
      }
      attributes.forEach(webSession::setAttribute);
      webSession.clearChangeFlag();
      return webSession;
    } catch (final Exception e) {
      LOGGER.error("The persistent session could not be restored.", e);
      return null;
    }
  }

  private Map<String, byte[]> serializeSessionAttributes(final WebSession webSession) {
    final var serializedAttributes = new HashMap<String, byte[]>();
    final var attributeNames = webSession.getAttributeNames();
    attributeNames.forEach(
        a -> serializedAttributes.put(a, converter.serialize(webSession.getAttribute(a))));
    return serializedAttributes;
  }

  private Map<String, Object> deserializeSessionAttributes(
      final PersistentSession persistentSession) {
    return Optional.ofNullable(persistentSession.attributes())
        .orElse(new HashMap<>())
        .entrySet()
        .stream()
        .collect(Collectors.toMap(Map.Entry::getKey, e -> converter.deserialize(e.getValue())));
  }

  private @Nullable Instant toInstant(final @Nullable Long value) {
    return Optional.ofNullable(value).map(Instant::ofEpochMilli).orElse(null);
  }

  private @Nullable Duration toDuration(final @Nullable Long value) {
    return Optional.ofNullable(value).map(Duration::ofSeconds).orElse(null);
  }

  public static final class SpringBasedWebSessionAttributeConverter
      implements WebSessionAttributeConverter {

    private final GenericConversionService conversionService;

    public SpringBasedWebSessionAttributeConverter(
        final GenericConversionService conversionService) {
      this.conversionService = conversionService;
      conversionService.addConverter(Object.class, byte[].class, new SerializingConverter());
      conversionService.addConverter(byte[].class, Object.class, new DeserializingConverter());
    }

    @Override
    public @Nullable Object deserialize(final byte[] value) {
      return conversionService.convert(
          value, TypeDescriptor.valueOf(byte[].class), TypeDescriptor.valueOf(Object.class));
    }

    @Override
    public byte @Nullable [] serialize(final @Nullable Object value) {
      return (byte[])
          conversionService.convert(
              value, TypeDescriptor.valueOf(Object.class), TypeDescriptor.valueOf(byte[].class));
    }
  }
}
