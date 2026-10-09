/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import static io.camunda.security.api.model.authz.AuthorizationResourceType.PROCESS_APPLICATION;
import static io.camunda.security.api.model.authz.PermissionType.READ;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.camunda.security.core.auth.RequiredAuthorization;
import java.util.List;
import org.junit.jupiter.api.Test;

class ResourceIdResolverTest {

  private static RequiredAuthorization.Builder<Document> base(
      final RequiredAuthorization.Builder<Document> builder) {
    return builder.resourceType(PROCESS_APPLICATION).permissionType(READ);
  }

  @Test
  void resolvesTheIdFromTheSupplier() {
    final RequiredAuthorization<Document> authorization =
        RequiredAuthorization.of(b -> base(b).resourceIdSupplier(Document::id));

    assertThat(ResourceIdResolver.resolveResourceId(authorization, new Document("pa1")))
        .isEqualTo("pa1");
  }

  @Test
  void rejectsMissingSupplier() {
    final RequiredAuthorization<Document> authorization = RequiredAuthorization.of(b -> base(b));

    assertThatThrownBy(
            () -> ResourceIdResolver.resolveResourceId(authorization, new Document("pa1")))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("resourceIdSupplier");
  }

  @Test
  void rejectsExplicitResourceIdsEvenWithSupplier() {
    final RequiredAuthorization<Document> authorization =
        RequiredAuthorization.of(
            b -> base(b).resourceIdSupplier(Document::id).resourceIds(List.of("pa1")));

    assertThatThrownBy(
            () -> ResourceIdResolver.resolveResourceId(authorization, new Document("pa1")))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("explicit resource IDs");
  }

  @Test
  void rejectsSingleExplicitIdWithoutSupplier() {
    final RequiredAuthorization<Document> authorization =
        RequiredAuthorization.of(b -> base(b).resourceId("pa1"));

    assertThatThrownBy(
            () -> ResourceIdResolver.resolveResourceId(authorization, new Document("pa1")))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void rejectsSupplierReturningNullOrEmpty() {
    final RequiredAuthorization<Document> nullId =
        RequiredAuthorization.of(b -> base(b).resourceIdSupplier(Document::id));

    assertThatThrownBy(() -> ResourceIdResolver.resolveResourceId(nullId, new Document(null)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("returned no resource ID");
    assertThatThrownBy(() -> ResourceIdResolver.resolveResourceId(nullId, new Document("")))
        .isInstanceOf(IllegalArgumentException.class);
  }

  private record Document(String id) {}
}
