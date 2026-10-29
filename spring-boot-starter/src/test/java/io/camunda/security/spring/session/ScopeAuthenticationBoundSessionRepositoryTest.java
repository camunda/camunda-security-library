/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.session;

import static io.camunda.security.spring.session.ScopeAuthenticationBoundSessionRepository.FINGERPRINT_ATTRIBUTE;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.springframework.session.MapSession;
import org.springframework.session.MapSessionRepository;

class ScopeAuthenticationBoundSessionRepositoryTest {

  private final MapSessionRepository store = new MapSessionRepository(new ConcurrentHashMap<>());
  private final AtomicReference<String> serving = new AtomicReference<>("first");
  private final ScopeAuthenticationBoundSessionRepository<MapSession> repository =
      new ScopeAuthenticationBoundSessionRepository<>(store, "basePath=/s", serving::get);

  @Test
  void shouldRecordTheServingConfigurationOnANewSession() {
    // when
    final var session = repository.createSession();

    // then
    assertThat((String) session.getAttribute(FINGERPRINT_ATTRIBUTE)).isEqualTo("first");
  }

  @Test
  void shouldKeepASessionOfTheServingConfiguration() {
    // given
    final var session = saved();

    // when / then
    assertThat(repository.findById(session.getId())).isNotNull();
  }

  @Test
  void shouldEndASessionCreatedUnderAnotherConfiguration() {
    // given
    final var session = saved();
    serving.set("second");

    // when
    final var found = repository.findById(session.getId());

    // then
    assertThat(found).isNull();
    assertThat(store.findById(session.getId())).isNull();
  }

  @Test
  void shouldAdoptASessionThatCarriesNoConfiguration() {
    // given
    final var session = store.createSession();
    store.save(session);

    // when
    final var found = repository.findById(session.getId());

    // then
    assertThat((String) found.getAttribute(FINGERPRINT_ATTRIBUTE)).isEqualTo("first");
  }

  @Test
  void shouldPassThroughWhenNoGenerationServesTheThread() {
    // given
    final var session = saved();
    serving.set(null);

    // when / then
    assertThat(repository.findById(session.getId())).isNotNull();
    assertThat(repository.createSession().<String>getAttribute(FINGERPRINT_ATTRIBUTE)).isNull();
  }

  private MapSession saved() {
    final var session = repository.createSession();
    repository.save(session);
    return session;
  }
}
