/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.session;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.model.session.PersistentSession;
import io.camunda.security.core.port.out.SessionStorePort;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.session.MapSessionRepository;

class WebSessionRepositoriesTest {

  @Test
  void returnsTheDurableRepositoryWhenPresent() {
    final var durable =
        new WebSessionRepository(
            new NoopSessionStore(),
            new WebSessionMapper(
                new WebSessionMapper.SpringBasedWebSessionAttributeConverter(
                    new org.springframework.core.convert.support.GenericConversionService())),
            new MockHttpServletRequest());

    assertThat(WebSessionRepositories.durableOrInMemory(durable)).isSameAs(durable);
  }

  @Test
  void fallsBackToInMemoryRepositoryWhenDurableIsAbsent() {
    assertThat(WebSessionRepositories.durableOrInMemory(null))
        .isInstanceOf(MapSessionRepository.class);
  }

  private static final class NoopSessionStore implements SessionStorePort {
    @Override
    public PersistentSession get(final String sessionId) {
      return null;
    }

    @Override
    public void upsert(final PersistentSession session) {}

    @Override
    public void delete(final String sessionId) {}

    @Override
    public List<PersistentSession> getAll() {
      return List.of();
    }
  }
}
