/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.adapter;

/**
 * Outbound adapter for recording and dispatching outbox events that carry
 * policy changes from Hub to Orchestration Clusters (see ADR-0001 and ADR-0003).
 */
public interface OutboxAdapter {}
