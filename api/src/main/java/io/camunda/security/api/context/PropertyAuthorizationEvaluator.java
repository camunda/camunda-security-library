/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.context;

import io.camunda.security.api.model.CamundaAuthentication;

/**
 * Extension point for property-based authorization. Evaluates whether a principal is authorized to
 * access a resource based on a named property value (e.g. {@code "assignee"}, {@code
 * "candidateUsers"}, {@code "candidateGroups"}).
 *
 * <p>Implementations are registered in a {@code PropertyAuthorizationEvaluatorRegistry} (core
 * module) and looked up by {@link #propertyName()} at evaluation time.
 *
 * @param <T> the resource type this evaluator operates on
 */
public interface PropertyAuthorizationEvaluator<T> {

  /** The property name this evaluator handles (e.g. {@code "assignee"}). */
  String propertyName();

  /** Returns {@code true} if {@code authentication} is authorized to access {@code resource}. */
  boolean isAuthorized(CamundaAuthentication authentication, T resource);
}
