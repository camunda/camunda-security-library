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

import jakarta.servlet.http.HttpServletRequest;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.web.http.SessionRepositoryFilter;

/**
 * Verifies that {@link CamundaSessionRepositoryFilter} exposes the repository it was built with and
 * still hands that same repository to {@link SessionRepositoryFilter}, so exposing it costs no
 * behaviour change.
 */
class CamundaSessionRepositoryFilterTest {

  private final MapSessionRepository repository =
      new MapSessionRepository(new ConcurrentHashMap<>());

  @Test
  void exposesTheRepositoryItWasBuiltWith() {
    // given
    final var filter = new CamundaSessionRepositoryFilter<>(repository);

    // then
    assertThat(filter.sessionRepository())
        .as("the filter must expose the repository it was constructed with")
        .isSameAs(repository);
  }

  @Test
  void resolvesSessionsThroughTheSameRepository() throws Exception {
    // given — the superclass must have received the repository too, not just this subclass
    final var filter = new CamundaSessionRepositoryFilter<>(repository);
    final var request = new MockHttpServletRequest("GET", "/anything");
    final var response = new MockHttpServletResponse();

    // when — downstream creates a session, which the filter commits in its finally block
    final var sessionId = new String[1];
    filter.doFilter(
        request,
        response,
        (req, res) -> {
          final var session = ((HttpServletRequest) req).getSession(true);
          session.setAttribute("marker", "v");
          sessionId[0] = session.getId();
        });

    // then — the session landed in the repository this filter exposes
    final var saved = filter.sessionRepository().findById(sessionId[0]);
    assertThat(saved)
        .as("a session committed through the filter must be found in the exposed repository")
        .isNotNull();
    assertThat((String) saved.getAttribute("marker"))
        .as("the committed session must carry the attribute set downstream")
        .isEqualTo("v");
  }

  @Test
  void repositoryOfRejectsAFilterThatIsNotCamundaOwned() {
    // given — a raw Spring Session filter, i.e. production bypassed the CSL factories
    final var rawFilter = new SessionRepositoryFilter<>(repository);

    // then
    assertThatThrownBy(() -> WebSessionTestAccess.repositoryOf(rawFilter))
        .as("the test seam must fail loudly rather than silently skip the assertion")
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining("CamundaSessionRepositoryFilter");
  }
}
