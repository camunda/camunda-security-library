/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.out;

import io.camunda.security.api.model.policy.PolicyChangeSet;

/**
 * Outbound port that projects a policy change set into the host's runtime, for example by pushing
 * it to the broker. Implemented by host adapters outside CSL. Throws on failure; the caller retries
 * the same version. Applying a {@code policyVersion} more than once must be idempotent.
 */
public interface PolicyProjectionPort {

  void apply(PolicyChangeSet changeSet);
}
