/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
final class CompositeJWKSourceTest {

  @Mock private JWKSelector selector;
  @Mock private JWK jwk;
  @Mock private JWKSource<SecurityContext> sourceA;
  @Mock private JWKSource<SecurityContext> sourceB;
  @Mock private JWKSource<SecurityContext> sourceC;

  @Test
  void shouldReturnKeysFromFirstSourceWhenNonEmpty() throws KeySourceException {
    when(sourceA.get(any(), any())).thenReturn(List.of(jwk));

    final var composite = new CompositeJWKSource<>(List.of(sourceA, sourceB));

    assertThat(composite.get(selector, null)).containsExactly(jwk);
    verify(sourceB, never()).get(any(), any());
  }

  @Test
  void shouldFallToSecondSourceWhenFirstReturnsEmpty() throws KeySourceException {
    when(sourceA.get(any(), any())).thenReturn(List.of());
    when(sourceB.get(any(), any())).thenReturn(List.of(jwk));

    final var composite = new CompositeJWKSource<>(List.of(sourceA, sourceB));

    assertThat(composite.get(selector, null)).containsExactly(jwk);
  }

  @Test
  void shouldFallToSecondSourceWhenFirstThrowsKeySourceException() throws KeySourceException {
    when(sourceA.get(any(), any())).thenThrow(new KeySourceException("source A failed"));
    when(sourceB.get(any(), any())).thenReturn(List.of(jwk));

    final var composite = new CompositeJWKSource<>(List.of(sourceA, sourceB));

    assertThat(composite.get(selector, null)).containsExactly(jwk);
  }

  @Test
  void shouldRethrowLastExceptionWhenAllSourcesFail() throws KeySourceException {
    when(sourceA.get(any(), any())).thenThrow(new KeySourceException("source A failed"));
    when(sourceB.get(any(), any())).thenThrow(new KeySourceException("source B failed"));

    final var composite = new CompositeJWKSource<>(List.of(sourceA, sourceB));

    assertThatThrownBy(() -> composite.get(selector, null))
        .isInstanceOf(KeySourceException.class)
        .hasMessage("source B failed");
  }

  @Test
  void shouldReturnEmptyListWhenAllSourcesReturnEmpty() throws KeySourceException {
    when(sourceA.get(any(), any())).thenReturn(List.of());
    when(sourceB.get(any(), any())).thenReturn(List.of());

    final var composite = new CompositeJWKSource<>(List.of(sourceA, sourceB));

    assertThat(composite.get(selector, null)).isEmpty();
  }

  @Test
  void shouldWorkWithSingleSource() throws KeySourceException {
    when(sourceA.get(any(), any())).thenReturn(List.of(jwk));

    final var composite = new CompositeJWKSource<>(List.of(sourceA));

    assertThat(composite.get(selector, null)).containsExactly(jwk);
  }

  @Test
  void shouldHandleNullReturnFromSourceAsEmpty() throws KeySourceException {
    when(sourceA.get(any(), any())).thenReturn(null);
    when(sourceB.get(any(), any())).thenReturn(List.of(jwk));

    final var composite = new CompositeJWKSource<>(List.of(sourceA, sourceB));

    assertThat(composite.get(selector, null)).containsExactly(jwk);
  }

  @Test
  void shouldPreserveImmutabilityOfSourceList() throws KeySourceException {
    when(sourceA.get(any(), any())).thenReturn(List.of(jwk));

    final var mutableList = new ArrayList<JWKSource<SecurityContext>>();
    mutableList.add(sourceA);
    final var composite = new CompositeJWKSource<>(mutableList);
    mutableList.clear();

    assertThat(composite.get(selector, null)).containsExactly(jwk);
  }

  @Test
  @DisplayName("Empty sources list returns empty on get()")
  void shouldReturnEmptyWhenConstructedWithNoSources() throws KeySourceException {
    final var composite = new CompositeJWKSource<SecurityContext>(List.of());

    assertThat(composite.get(selector, null)).isEmpty();
  }

  @Test
  @DisplayName("Three sources: key found at third after first two return empty")
  void shouldFallThroughMultipleSourcesToFindKey() throws KeySourceException {
    when(sourceA.get(any(), any())).thenReturn(List.of());
    when(sourceB.get(any(), any())).thenReturn(List.of());
    when(sourceC.get(any(), any())).thenReturn(List.of(jwk));

    final var composite = new CompositeJWKSource<>(List.of(sourceA, sourceB, sourceC));

    assertThat(composite.get(selector, null)).containsExactly(jwk);
  }

  @Test
  @DisplayName("Three sources: first throws, second empty, third returns keys")
  void shouldHandleMixedFailureModesAcrossMultipleSources() throws KeySourceException {
    when(sourceA.get(any(), any())).thenThrow(new KeySourceException("source A network error"));
    when(sourceB.get(any(), any())).thenReturn(List.of());
    when(sourceC.get(any(), any())).thenReturn(List.of(jwk));

    final var composite = new CompositeJWKSource<>(List.of(sourceA, sourceB, sourceC));

    assertThat(composite.get(selector, null)).containsExactly(jwk);
  }

  @Test
  @DisplayName("RuntimeException from source propagates immediately without trying next sources")
  void shouldPropagateRuntimeExceptionWithoutCatching() throws KeySourceException {
    when(sourceA.get(any(), any())).thenThrow(new NullPointerException("unexpected NPE"));

    final var composite = new CompositeJWKSource<>(List.of(sourceA, sourceB));

    assertThatThrownBy(() -> composite.get(selector, null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("unexpected NPE");
    verify(sourceB, never()).get(any(), any());
  }

  @Test
  @DisplayName("Short-circuit: when first source has keys, remaining sources are never called")
  void shouldShortCircuitAndNotCallRemainingSourcesAfterMatch() throws KeySourceException {
    when(sourceA.get(any(), any())).thenReturn(List.of(jwk));

    final var composite = new CompositeJWKSource<>(List.of(sourceA, sourceB, sourceC));

    assertThat(composite.get(selector, null)).containsExactly(jwk);
    verify(sourceB, never()).get(any(), any());
    verify(sourceC, never()).get(any(), any());
  }
}
