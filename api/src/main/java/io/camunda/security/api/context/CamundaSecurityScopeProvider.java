/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.context;

import io.camunda.security.api.model.config.ScopedSecurityDescriptor;
import java.util.List;

/**
 * Host-implemented SPI contributing additional path-scoped API security chains. CSL builds one
 * chain per returned descriptor alongside its own. Scope-agnostic: CSL never interprets the meaning
 * of a scope.
 */
public interface CamundaSecurityScopeProvider {
  List<ScopedSecurityDescriptor> get();
}
