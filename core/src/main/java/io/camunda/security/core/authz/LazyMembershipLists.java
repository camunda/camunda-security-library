/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import io.camunda.security.api.context.MembershipResolutionContextPropagator;
import io.camunda.security.api.model.CamundaAuthentication;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * Builds lazy membership lists of any element type, such as conditional memberships, with the
 * context of the host bound. CSL's converters use it; it is not part of the host contract.
 */
public final class LazyMembershipLists {

  private LazyMembershipLists() {}

  /**
   * Returns a lazy list that runs {@code lookup} on its first read, with the context that {@code
   * propagator} captures now.
   *
   * <p>{@link MembershipResolutionContextPropagator#decorate} takes only string lists, so the
   * lookup runs inside a decorated string-list supplier and gives its result through a holder. The
   * lazy list runs that supplier at most once, so the holder needs no lock.
   */
  public static <T> List<T> decorated(
      final MembershipResolutionContextPropagator propagator, final Supplier<List<T>> lookup) {
    final var result = new AtomicReference<List<T>>();
    final Supplier<List<String>> decorated =
        propagator.decorate(
            () -> {
              result.set(lookup.get());
              return List.of();
            });
    return CamundaAuthentication.lazyList(
        () -> {
          decorated.get();
          return result.get();
        });
  }
}
