/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.policy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.camunda.security.api.model.authz.AuthorizationOwnerType;
import io.camunda.security.api.model.authz.AuthorizationResourceMatcher;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.EntityType;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.api.model.policy.PolicyAuthorization;
import io.camunda.security.api.model.policy.PolicyAuthorizationKey;
import io.camunda.security.api.model.policy.PolicyChangeSet;
import io.camunda.security.api.model.policy.PolicyChangeSetKind;
import io.camunda.security.api.model.policy.PolicyDeletions;
import io.camunda.security.api.model.policy.PolicyGroup;
import io.camunda.security.api.model.policy.PolicyMappingRule;
import io.camunda.security.api.model.policy.PolicyMembership;
import io.camunda.security.api.model.policy.PolicyMembershipTarget;
import io.camunda.security.api.model.policy.PolicyRole;
import io.camunda.security.api.model.policy.PolicyTenant;
import io.camunda.security.api.model.policy.PolicyUpserts;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Proves the policy model is a usable transport payload for a plain, annotation-free Jackson. */
class PolicyChangeSetJsonRoundTripTest {

  private final ObjectMapper mapper = new ObjectMapper();

  private static PolicyChangeSet fullChangeSet() {
    final var upserts =
        new PolicyUpserts(
            List.of(new PolicyTenant("t1", "Tenant", "d")),
            List.of(new PolicyRole("r1", "Role", "d")),
            List.of(new PolicyGroup("g1", "Group", "d")),
            List.of(new PolicyMappingRule("m1", "Rule", "groups", "admins")),
            List.of(new PolicyMembership(PolicyMembershipTarget.ROLE, "r1", EntityType.USER, "u1")),
            List.of(
                new PolicyAuthorization(
                    new PolicyAuthorizationKey(
                        AuthorizationOwnerType.ROLE,
                        "r1",
                        AuthorizationResourceType.RESOURCE,
                        AuthorizationResourceMatcher.ID,
                        "res-1",
                        null),
                    Set.of(PermissionType.READ)),
                new PolicyAuthorization(
                    new PolicyAuthorizationKey(
                        AuthorizationOwnerType.GROUP,
                        "g1",
                        AuthorizationResourceType.RESOURCE,
                        AuthorizationResourceMatcher.PROPERTY,
                        null,
                        "assignee"),
                    Set.of(PermissionType.READ, PermissionType.CREATE))));
    final var deletions =
        new PolicyDeletions(
            List.of("t2"),
            List.of("r2"),
            List.of("g2"),
            List.of("m2"),
            List.of(
                new PolicyMembership(PolicyMembershipTarget.TENANT, "t1", EntityType.ROLE, "r9")),
            List.of(
                new PolicyAuthorizationKey(
                    AuthorizationOwnerType.ROLE,
                    "r2",
                    AuthorizationResourceType.RESOURCE,
                    AuthorizationResourceMatcher.ANY,
                    "*",
                    null)));
    return new PolicyChangeSet(7, PolicyChangeSetKind.DELTA, upserts, deletions);
  }

  @Test
  void shouldRoundTripFullChangeSet() throws JsonProcessingException {
    final var original = fullChangeSet();

    final var json = mapper.writeValueAsString(original);

    assertThat(mapper.readValue(json, PolicyChangeSet.class)).isEqualTo(original);
  }

  @Test
  void shouldRoundTripInsideWrapperEvent() throws JsonProcessingException {
    final var event = new PolicyEvent("evt-1", fullChangeSet());

    final var json = mapper.writeValueAsString(event);

    assertThat(mapper.readValue(json, PolicyEvent.class)).isEqualTo(event);
  }

  @Test
  void shouldSerialiseOnlyRecordComponents() throws JsonProcessingException {
    final JsonNode tree = mapper.valueToTree(fullChangeSet());

    assertThat(fieldNames(tree))
        .containsExactlyInAnyOrder("policyVersion", "kind", "upserts", "deletions");
    assertThat(fieldNames(tree.get("upserts")))
        .containsExactlyInAnyOrder(
            "tenants", "roles", "groups", "mappingRules", "memberships", "authorizations");
    assertThat(fieldNames(tree.get("deletions")))
        .containsExactlyInAnyOrder(
            "tenantIds", "roleIds", "groupIds", "mappingRuleIds", "memberships", "authorizations");
    assertThat(fieldNames(tree.get("upserts").get("authorizations").get(0)))
        .containsExactlyInAnyOrder("key", "permissions");
    assertThat(fieldNames(tree.get("upserts").get("authorizations").get(0).get("key")))
        .containsExactlyInAnyOrder(
            "ownerType",
            "ownerId",
            "resourceType",
            "matcher",
            "resourceId",
            "resourcePropertyName");
    assertThat(fieldNames(tree.get("upserts").get("memberships").get(0)))
        .containsExactlyInAnyOrder("targetType", "targetId", "memberType", "memberId");
  }

  @Test
  void shouldDeserialiseOmittedSectionsToEmptyLists() throws JsonProcessingException {
    final var json =
        """
        {"policyVersion":3,"kind":"DELTA","deletions":{"roleIds":["r1"]}}
        """;

    final var changeSet = mapper.readValue(json, PolicyChangeSet.class);

    assertThat(changeSet.deletions().roleIds()).containsExactly("r1");
    assertThat(changeSet.deletions().tenantIds()).isEmpty();
    assertThat(changeSet.upserts().roles()).isEmpty();
    assertThat(changeSet.upserts().authorizations()).isEmpty();
  }

  @Test
  void shouldRejectSnapshotWithDeletionsOnRead() {
    final var json =
        """
        {"policyVersion":3,"kind":"SNAPSHOT","deletions":{"roleIds":["r1"]}}
        """;

    assertThatThrownBy(() -> mapper.readValue(json, PolicyChangeSet.class))
        .isInstanceOf(JsonMappingException.class)
        .hasRootCauseInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void shouldRejectReverseMembershipOnRead() {
    final var json =
        """
        {"policyVersion":3,"kind":"DELTA","upserts":{"memberships":[
          {"targetType":"GROUP","targetId":"g1","memberType":"ROLE","memberId":"r1"}]}}
        """;

    assertThatThrownBy(() -> mapper.readValue(json, PolicyChangeSet.class))
        .isInstanceOf(JsonMappingException.class)
        .hasRootCauseInstanceOf(IllegalArgumentException.class);
  }

  private static List<String> fieldNames(final JsonNode node) {
    final List<String> names = new ArrayList<>();
    node.fieldNames().forEachRemaining(names::add);
    return names;
  }

  private record PolicyEvent(String eventId, PolicyChangeSet payload) {}
}
