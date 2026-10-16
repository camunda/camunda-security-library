/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.scim;

import java.util.List;

/**
 * One page of a User search result (RFC 7644 §3.4.2.4).
 *
 * @param totalResults number of matches across all pages
 * @param startIndex 1-based index of the first resource on this page
 * @param resources the resources on this page
 */
public record ScimUserPage(long totalResults, int startIndex, List<ScimUserResource> resources) {

  public ScimUserPage {
    resources = List.copyOf(resources);
  }
}
