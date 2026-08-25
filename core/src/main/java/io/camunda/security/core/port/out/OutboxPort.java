/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.out;

/**
 * Outbound port for recording and dispatching outbox events that carry policy changes from Hub to
 * Orchestration Clusters (see the proposed, not-yet-implemented
 * docs/vision/policy-version-change-sets.md and docs/vision/push-vs-pull-policy-propagation.md).
 */
public interface OutboxPort {}
