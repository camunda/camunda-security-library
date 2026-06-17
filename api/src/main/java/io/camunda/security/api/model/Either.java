/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model;

import java.util.NoSuchElementException;

/**
 * A discriminated union of a left value (typically failure) and a right value (typically success).
 * Replaces {@code io.camunda.zeebe.util.Either} in the engine migration path.
 *
 * <p>Inc 1 minimal surface — {@code map}/{@code flatMap} are intentionally absent per YAGNI.
 *
 * @param <L> the left (typically rejection) type
 * @param <R> the right (typically success) type
 */
public sealed interface Either<L, R> permits Either.Left, Either.Right {

  static <L, R> Either<L, R> left(final L value) {
    return new Left<>(value);
  }

  static <L, R> Either<L, R> right(final R value) {
    return new Right<>(value);
  }

  boolean isLeft();

  boolean isRight();

  /**
   * Returns the left value, or throws {@link NoSuchElementException} if this is a {@link Right}.
   */
  L leftValue();

  /**
   * Returns the right value, or throws {@link NoSuchElementException} if this is a {@link Left}.
   */
  R rightValue();

  record Left<L, R>(L value) implements Either<L, R> {
    @Override
    public boolean isLeft() {
      return true;
    }

    @Override
    public boolean isRight() {
      return false;
    }

    @Override
    public L leftValue() {
      return value;
    }

    @Override
    public R rightValue() {
      throw new NoSuchElementException("Cannot get right value from a Left Either");
    }
  }

  record Right<L, R>(R value) implements Either<L, R> {
    @Override
    public boolean isLeft() {
      return false;
    }

    @Override
    public boolean isRight() {
      return true;
    }

    @Override
    public L leftValue() {
      throw new NoSuchElementException("Cannot get left value from a Right Either");
    }

    @Override
    public R rightValue() {
      return value;
    }
  }
}
