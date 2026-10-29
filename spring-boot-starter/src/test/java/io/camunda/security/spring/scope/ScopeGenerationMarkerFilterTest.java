/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class ScopeGenerationMarkerFilterTest {

  @Test
  void shouldTellTheScopeWhichGenerationServesTheRequest() throws Exception {
    // given
    final var filter = new ScopeGenerationMarkerFilter("/s", 3, "fingerprint");
    final var seen = new AtomicReference<String>();
    final var request = new MockHttpServletRequest();

    // when
    filter.doFilter(
        request,
        new MockHttpServletResponse(),
        (req, res) -> seen.set(ScopeGenerationMarkerFilter.servingFingerprint("/s")));

    // then
    assertThat(seen).hasValue("fingerprint");
    assertThat(request.getAttribute(ScopeGenerationMarkerFilter.SERVING_ATTRIBUTE))
        .isEqualTo(new ScopeGenerationMarkerFilter.Serving("/s", 3, "fingerprint"));
    assertThat(ScopeGenerationMarkerFilter.servingFingerprint("/s")).isNull();
  }

  @Test
  void shouldNotTellAnotherScope() throws Exception {
    // given
    final var filter = new ScopeGenerationMarkerFilter("/s", 3, "fingerprint");
    final var seen = new AtomicReference<String>("unset");

    // when
    filter.doFilter(
        new MockHttpServletRequest(),
        new MockHttpServletResponse(),
        (req, res) -> seen.set(ScopeGenerationMarkerFilter.servingFingerprint("/other")));

    // then
    assertThat(seen.get()).isNull();
  }
}
