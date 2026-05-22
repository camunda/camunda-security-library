/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.auth;

import java.util.List;

/**
 * Per-field accessor for an authenticated principal's memberships. Returned by the host's {@code
 * MembershipPort} and wired by the library as {@code *Supplier} fields on {@code
 * CamundaAuthentication}; each method is invoked only when its corresponding field is first read.
 *
 * <p>Implementations may be eager (precompute all four lists at construction time and return them
 * unchanged on every call) or lazy (defer the underlying work to first call, typically with
 * memoisation). The contract from the library's perspective is just "answer this membership query
 * with a list of IDs".
 *
 * <p>Method names follow the {@code *Ids} convention used by {@code CamundaAuthentication}'s
 * accessors so calling code reads consistently regardless of whether the IDs come from the
 * authentication object directly or from a freshly created provider.
 */
public interface MembershipProvider {

  List<String> groupIds();

  List<String> roleIds();

  List<String> tenantIds();

  List<String> mappingRuleIds();
}
