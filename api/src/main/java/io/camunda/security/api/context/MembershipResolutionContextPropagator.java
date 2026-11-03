/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.context;

import io.camunda.security.api.model.CamundaAuthentication;
import java.util.List;
import java.util.function.Supplier;

/**
 * Host-implemented SPI that decorates the deferred membership suppliers backing a {@link
 * CamundaAuthentication}, so a host can carry resolution context — captured while the
 * authentication is being built — onto the thread or scope that later materialises a lazy
 * membership list.
 *
 * <p>{@code CamundaAuthentication} membership lists are resolved lazily on first read, which may
 * happen long after, and on a different thread or scope than, the authentication was built — e.g.
 * during an asynchronous authorization read, or when an HTTP session is serialised after the
 * request scope has been torn down. A {@code MembershipPort} implementation that depends on
 * request-scoped state (such as a multi-tenant routing key) would fail at that point. This
 * decorator lets the host snapshot that state at construction time and rebind it around the
 * deferred call. Context-agnostic: CSL never interprets the meaning of the propagated context.
 *
 * <p>The default {@link #identity()} performs no decoration, preserving the plain lazy behaviour.
 */
@FunctionalInterface
public interface MembershipResolutionContextPropagator {

  /**
   * Returns a supplier that runs {@code supplier} with the host's resolution context bound. The
   * context is expected to be captured eagerly, when this method is invoked (i.e. while the
   * authentication is being built), and rebound lazily, when the returned supplier is called.
   *
   * <p>The returned supplier may be called re-entrantly (e.g. a lazy {@code roleIds} lookup reading
   * a not-yet-resolved {@code groupIds}). Implementations must restore the previous binding
   * afterwards rather than clearing it, so nested calls don't clobber the outer one.
   */
  Supplier<List<String>> decorate(Supplier<List<String>> supplier);

  /** A propagator that returns each supplier unchanged. */
  static MembershipResolutionContextPropagator identity() {
    return supplier -> supplier;
  }
}
