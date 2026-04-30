/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authorization;

import java.util.Objects;
import java.util.Set;

/**
 * Describes an authorization being checked: which permission against which resource type, scoped to
 * which resource ids (and optionally which resource properties).
 *
 * <p>Vocabulary is opaque strings — the library does not import permission or resource-type enums
 * from the host. Hosts encode their own permission/resource taxonomies and the {@link
 * io.camunda.security.core.port.in.AuthorizationPort} matches them as opaque values.
 *
 * <p>The generic parameter {@code T} is a phantom type — it lets callers express the resource type
 * statically (e.g. {@code Authorization<WebApp>}) without forcing the library to know what {@code
 * T} actually is.
 */
public record Authorization<T>(
    String permissionType,
    String resourceType,
    Set<String> resourceIds,
    Set<String> resourcePropertyNames) {

  /** Permission used by the web-app authorization filter. */
  public static final String WEB_APP_PERMISSION_TYPE = "ACCESS";

  /** Resource type used by the web-app authorization filter. */
  public static final String WEB_APP_RESOURCE_TYPE = "COMPONENT";

  public Authorization {
    Objects.requireNonNull(permissionType, "permissionType");
    Objects.requireNonNull(resourceType, "resourceType");
    resourceIds = resourceIds == null ? Set.of() : Set.copyOf(resourceIds);
    resourcePropertyNames =
        resourcePropertyNames == null ? Set.of() : Set.copyOf(resourcePropertyNames);
  }

  /**
   * Authorization shape used by the web-app check filter: principal asks for {@code ACCESS}
   * permission on a {@code COMPONENT} resource identified by name.
   */
  public static Authorization<WebApp> webAppAccess(final String webApp) {
    Objects.requireNonNull(webApp, "webApp");
    return new Authorization<>(
        WEB_APP_PERMISSION_TYPE, WEB_APP_RESOURCE_TYPE, Set.of(webApp), Set.of());
  }

  /** Marker type for {@link #webAppAccess(String)}. */
  public static final class WebApp {
    private WebApp() {}
  }
}
