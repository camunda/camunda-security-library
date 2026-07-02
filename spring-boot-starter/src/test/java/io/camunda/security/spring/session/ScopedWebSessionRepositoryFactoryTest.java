/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.camunda.security.api.model.session.PersistentSession;
import io.camunda.security.core.port.out.ScopedSessionStorePortProvider;
import io.camunda.security.core.port.out.SessionStorePort;
import io.camunda.security.spring.session.WebSessionMapper.SpringBasedWebSessionAttributeConverter;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.core.convert.support.GenericConversionService;
import org.springframework.mock.web.MockHttpServletRequest;

class ScopedWebSessionRepositoryFactoryTest {

  private static WebSessionMapper mapper() {
    return new WebSessionMapper(
        new SpringBasedWebSessionAttributeConverter(new GenericConversionService()));
  }

  @Test
  void shouldReportUnavailableAndRejectBuildWhenNoProvider() {
    final var factory =
        new ScopedWebSessionRepositoryFactory(null, mapper(), new MockHttpServletRequest());

    assertThat(factory.isAvailable()).isFalse();
    assertThatThrownBy(() -> factory.forBasePath("/physical-tenants/a"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("/physical-tenants/a");
  }

  @Test
  void shouldBuildAScopeBoundRepositoryPerBasePathFromTheProvider() {
    final var requestedBasePaths = new ArrayList<String>();
    final ScopedSessionStorePortProvider provider =
        basePath -> {
          requestedBasePaths.add(basePath);
          return new NoopSessionStorePort();
        };
    final var factory =
        new ScopedWebSessionRepositoryFactory(provider, mapper(), new MockHttpServletRequest());

    assertThat(factory.isAvailable()).isTrue();

    final var repoA = factory.forBasePath("/physical-tenants/a");
    final var repoB = factory.forBasePath("/physical-tenants/b");

    // the provider is consulted per basePath, and each scope gets its own repository instance
    assertThat(requestedBasePaths).containsExactly("/physical-tenants/a", "/physical-tenants/b");
    assertThat(repoA).isNotNull();
    assertThat(repoB).isNotNull();
    assertThat(repoA).isNotSameAs(repoB);
  }

  private static final class NoopSessionStorePort implements SessionStorePort {
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
