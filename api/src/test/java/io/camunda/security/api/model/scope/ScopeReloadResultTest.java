/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.scope;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class ScopeReloadResultTest {

  @ParameterizedTest
  @EnumSource(
      value = ScopeReloadOutcome.class,
      names = {"ADDED", "REPLACED", "CREDENTIALS_ROTATED", "CREDENTIALS_REFRESHED", "REMOVED"})
  void shouldReportAnAppliedChange(final ScopeReloadOutcome outcome) {
    // when
    final var result = result(outcome, null);

    // then
    assertThat(result.applied()).isTrue();
    assertThat(result.orThrow()).isSameAs(result);
  }

  @ParameterizedTest
  @EnumSource(
      value = ScopeReloadOutcome.class,
      names = {"UNCHANGED", "ABSENT", "KEPT_PREVIOUS", "FAILED"})
  void shouldReportAChangeThatWasNotApplied(final ScopeReloadOutcome outcome) {
    // when
    final var result = result(outcome, null);

    // then
    assertThat(result.applied()).isFalse();
  }

  @Test
  void shouldEndSessionsOnlyWhenTheAuthenticationChangedOrTheScopeWent() {
    // when / then
    assertThat(result(ScopeReloadOutcome.REPLACED, null).sessionsInvalidated()).isTrue();
    assertThat(result(ScopeReloadOutcome.REMOVED, null).sessionsInvalidated()).isTrue();
    assertThat(result(ScopeReloadOutcome.CREDENTIALS_ROTATED, null).sessionsInvalidated())
        .isFalse();
    assertThat(result(ScopeReloadOutcome.ADDED, null).sessionsInvalidated()).isFalse();
  }

  @Test
  void shouldThrowTheFailureOfAChangeThatWasNotApplied() {
    // given
    final var failure = new IllegalStateException("unreachable");
    final var result = result(ScopeReloadOutcome.KEPT_PREVIOUS, failure);

    // when / then
    assertThat(result.failureCause()).containsSame(failure);
    assertThatThrownBy(result::orThrow).isSameAs(failure);
  }

  @Test
  void shouldListOnlyTheFailuresOfAReport() {
    // given
    final var failed = result(ScopeReloadOutcome.FAILED, new IllegalStateException("boom"));
    final var added = result(ScopeReloadOutcome.ADDED, null);

    // when
    final var report = new ScopeReloadReport(List.of(added, failed));

    // then
    assertThat(report.failures()).containsExactly(failed);
    assertThat(report.result("/s")).containsSame(added);
    assertThat(report.result("/other")).isEmpty();
  }

  private static ScopeReloadResult result(
      final ScopeReloadOutcome outcome, final RuntimeException failure) {
    return new ScopeReloadResult("/s", outcome, 1, Duration.ZERO, failure);
  }
}
