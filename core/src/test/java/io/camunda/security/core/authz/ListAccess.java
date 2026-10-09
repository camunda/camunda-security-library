/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import io.camunda.security.api.model.authz.ResourceAttribute;
import java.util.Map;
import java.util.Set;

/** Evaluates the outcome of a list resolution for one resource, as a host's query would. */
final class ListAccess {

  private ListAccess() {}

  static boolean allows(
      final ResourceAccess access,
      final String resourceId,
      final Map<ResourceAttribute, Set<String>> attributes) {
    if (access.denied()) {
      return false;
    }
    if (access.wildcard()) {
      return true;
    }
    return access.filter().matches(resourceId, attributes);
  }
}
