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
import static org.mockito.Mockito.mock;
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

final class CompositeJWKSourceTest {

  private final JWKSelector selector = mock(JWKSelector.class);
  private final JWK jwk = mock(JWK.class);

  @Test
  void shouldReturnKeysFromFirstSourceWhenNonEmpty() throws KeySourceException {
    @SuppressWarnings("unchecked")
    final JWKSource<SecurityContext> sourceA = mock(JWKSource.class);
    @SuppressWarnings("unchecked")
    final JWKSource<SecurityContext> sourceB = mock(JWKSource.class);
    when(sourceA.get(any(), any())).thenReturn(List.of(jwk));

    final var composite = new CompositeJWKSource<>(List.of(sourceA, sourceB));

    assertThat(composite.get(selector, null)).containsExactly(jwk);
    verify(sourceB, never()).get(any(), any());
  }

  @Test
  void shouldFallToSecondSourceWhenFirstReturnsEmpty() throws KeySourceException {
    @SuppressWarnings("unchecked")
    final JWKSource<SecurityContext> sourceA = mock(JWKSource.class);
    @SuppressWarnings("unchecked")
    final JWKSource<SecurityContext> sourceB = mock(JWKSource.class);
    when(sourceA.get(any(), any())).thenReturn(List.of());
    when(sourceB.get(any(), any())).thenReturn(List.of(jwk));

    final var composite = new CompositeJWKSource<>(List.of(sourceA, sourceB));

    assertThat(composite.get(selector, null)).containsExactly(jwk);
  }

  @Test
  void shouldFallToSecondSourceWhenFirstThrowsKeySourceException() throws KeySourceException {
    @SuppressWarnings("unchecked")
    final JWKSource<SecurityContext> sourceA = mock(JWKSource.class);
    @SuppressWarnings("unchecked")
    final JWKSource<SecurityContext> sourceB = mock(JWKSource.class);
    when(sourceA.get(any(), any())).thenThrow(new KeySourceException("source A failed"));
    when(sourceB.get(any(), any())).thenReturn(List.of(jwk));

    final var composite = new CompositeJWKSource<>(List.of(sourceA, sourceB));

    assertThat(composite.get(selector, null)).containsExactly(jwk);
  }

  @Test
  void shouldRethrowLastExceptionWhenAllSourcesFail() throws KeySourceException {
    @SuppressWarnings("unchecked")
    final JWKSource<SecurityContext> sourceA = mock(JWKSource.class);
    @SuppressWarnings("unchecked")
    final JWKSource<SecurityContext> sourceB = mock(JWKSource.class);
    when(sourceA.get(any(), any())).thenThrow(new KeySourceException("source A failed"));
    when(sourceB.get(any(), any())).thenThrow(new KeySourceException("source B failed"));

    final var composite = new CompositeJWKSource<>(List.of(sourceA, sourceB));

    assertThatThrownBy(() -> composite.get(selector, null))
        .isInstanceOf(KeySourceException.class)
        .hasMessage("source B failed");
  }

  @Test
  void shouldReturnEmptyListWhenAllSourcesReturnEmpty() throws KeySourceException {
    @SuppressWarnings("unchecked")
    final JWKSource<SecurityContext> sourceA = mock(JWKSource.class);
    @SuppressWarnings("unchecked")
    final JWKSource<SecurityContext> sourceB = mock(JWKSource.class);
    when(sourceA.get(any(), any())).thenReturn(List.of());
    when(sourceB.get(any(), any())).thenReturn(List.of());

    final var composite = new CompositeJWKSource<>(List.of(sourceA, sourceB));

    assertThat(composite.get(selector, null)).isEmpty();
  }

  @Test
  void shouldWorkWithSingleSource() throws KeySourceException {
    @SuppressWarnings("unchecked")
    final JWKSource<SecurityContext> source = mock(JWKSource.class);
    when(source.get(any(), any())).thenReturn(List.of(jwk));

    final var composite = new CompositeJWKSource<>(List.of(source));

    assertThat(composite.get(selector, null)).containsExactly(jwk);
  }

  @Test
  void shouldHandleNullReturnFromSourceAsEmpty() throws KeySourceException {
    @SuppressWarnings("unchecked")
    final JWKSource<SecurityContext> sourceA = mock(JWKSource.class);
    @SuppressWarnings("unchecked")
    final JWKSource<SecurityContext> sourceB = mock(JWKSource.class);
    when(sourceA.get(any(), any())).thenReturn(null);
    when(sourceB.get(any(), any())).thenReturn(List.of(jwk));

    final var composite = new CompositeJWKSource<>(List.of(sourceA, sourceB));

    assertThat(composite.get(selector, null)).containsExactly(jwk);
  }

  @Test
  void shouldPreserveImmutabilityOfSourceList() throws KeySourceException {
    @SuppressWarnings("unchecked")
    final JWKSource<SecurityContext> source = mock(JWKSource.class);
    when(source.get(any(), any())).thenReturn(List.of(jwk));

    final var mutableList = new ArrayList<JWKSource<SecurityContext>>();
    mutableList.add(source);
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
    @SuppressWarnings("unchecked")
    final JWKSource<SecurityContext> sourceA = mock(JWKSource.class);
    @SuppressWarnings("unchecked")
    final JWKSource<SecurityContext> sourceB = mock(JWKSource.class);
    @SuppressWarnings("unchecked")
    final JWKSource<SecurityContext> sourceC = mock(JWKSource.class);
    when(sourceA.get(any(), any())).thenReturn(List.of());
    when(sourceB.get(any(), any())).thenReturn(List.of());
    when(sourceC.get(any(), any())).thenReturn(List.of(jwk));

    final var composite = new CompositeJWKSource<>(List.of(sourceA, sourceB, sourceC));

    assertThat(composite.get(selector, null)).containsExactly(jwk);
  }

  @Test
  @DisplayName("Three sources: first throws, second empty, third returns keys")
  void shouldHandleMixedFailureModesAcrossMultipleSources() throws KeySourceException {
    @SuppressWarnings("unchecked")
    final JWKSource<SecurityContext> sourceA = mock(JWKSource.class);
    @SuppressWarnings("unchecked")
    final JWKSource<SecurityContext> sourceB = mock(JWKSource.class);
    @SuppressWarnings("unchecked")
    final JWKSource<SecurityContext> sourceC = mock(JWKSource.class);
    when(sourceA.get(any(), any())).thenThrow(new KeySourceException("source A network error"));
    when(sourceB.get(any(), any())).thenReturn(List.of());
    when(sourceC.get(any(), any())).thenReturn(List.of(jwk));

    final var composite = new CompositeJWKSource<>(List.of(sourceA, sourceB, sourceC));

    assertThat(composite.get(selector, null)).containsExactly(jwk);
  }

  @Test
  @DisplayName("RuntimeException from source propagates immediately without trying next sources")
  void shouldPropagateRuntimeExceptionWithoutCatching() throws KeySourceException {
    @SuppressWarnings("unchecked")
    final JWKSource<SecurityContext> sourceA = mock(JWKSource.class);
    @SuppressWarnings("unchecked")
    final JWKSource<SecurityContext> sourceB = mock(JWKSource.class);
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
    @SuppressWarnings("unchecked")
    final JWKSource<SecurityContext> sourceA = mock(JWKSource.class);
    @SuppressWarnings("unchecked")
    final JWKSource<SecurityContext> sourceB = mock(JWKSource.class);
    @SuppressWarnings("unchecked")
    final JWKSource<SecurityContext> sourceC = mock(JWKSource.class);
    when(sourceA.get(any(), any())).thenReturn(List.of(jwk));

    final var composite = new CompositeJWKSource<>(List.of(sourceA, sourceB, sourceC));

    assertThat(composite.get(selector, null)).containsExactly(jwk);
    verify(sourceB, never()).get(any(), any());
    verify(sourceC, never()).get(any(), any());
  }
}
