/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Every scope slot of the application context, by normalized base path. Slots are created, never
 * dropped: a removed scope's slot holds a tombstone, so the index is bounded by the number of
 * distinct base paths ever served, not by the number of changes.
 */
final class ScopeSlots {

  private final Map<String, ScopeSlot> byBasePath = new ConcurrentHashMap<>();

  /** The slot of a scope contributed at startup; the base path must not have one yet. */
  ScopeSlot registerStartupSlot(final String basePath) {
    final var slot = new ScopeSlot(basePath, true);
    if (byBasePath.putIfAbsent(basePath, slot) != null) {
      throw new IllegalStateException("A scope slot already exists for basePath=" + basePath);
    }
    return slot;
  }

  /** The slot for the base path, created as a runtime slot when it has none. */
  ScopeSlot slotFor(final String basePath) {
    return byBasePath.computeIfAbsent(basePath, path -> new ScopeSlot(path, false));
  }

  /** The slot for the base path, or {@code null}. */
  ScopeSlot find(final String basePath) {
    return byBasePath.get(basePath);
  }

  List<ScopeSlot> all() {
    return List.copyOf(byBasePath.values());
  }

  int runtimeScopeCount() {
    return (int) byBasePath.values().stream().filter(slot -> !slot.registeredAtStartup()).count();
  }

  /**
   * The runtime slot whose base path is the longest leading path prefix of the request, or {@code
   * null}. Startup slots are skipped: their own chain beans serve them.
   */
  ScopeSlot runtimeSlotFor(final HttpServletRequest request) {
    final var path = pathWithinApplication(request);
    for (int end = path.length(); end > 0; end = path.lastIndexOf('/', end - 1)) {
      final var slot = byBasePath.get(path.substring(0, end));
      if (slot != null) {
        return slot.registeredAtStartup() ? null : slot;
      }
    }
    return null;
  }

  private static String pathWithinApplication(final HttpServletRequest request) {
    final var uri = request.getRequestURI();
    if (uri == null) {
      return "";
    }
    final var contextPath = request.getContextPath();
    return contextPath != null && !contextPath.isEmpty() && uri.startsWith(contextPath)
        ? uri.substring(contextPath.length())
        : uri;
  }
}
