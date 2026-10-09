/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import static io.camunda.security.api.model.authz.AuthorizationResourceType.PROCESS_APPLICATION;
import static io.camunda.security.api.model.authz.AuthorizationResourceType.USER_TASK;
import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.authz.Condition;
import io.camunda.security.api.model.authz.Operand;
import io.camunda.security.api.model.authz.PrincipalAttribute;
import io.camunda.security.api.model.authz.ResourceAttribute;
import io.camunda.security.core.auth.RequiredAuthorization;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ResourceConditionsTest {

  private static final CamundaAuthentication ALICE =
      CamundaAuthentication.of(
          b -> b.user("alice").groupIds(List.of("g1", "g2")).tenants(List.of("t1")));

  @Test
  void resolvesLiteralValuesAsTheyAre() {
    assertThat(ResourceConditions.resolve(new Operand.Values(Set.of("a")), ALICE))
        .containsExactly("a");
  }

  @Test
  void resolvesPrincipalAttributesFromTheAuthentication() {
    assertThat(
            ResourceConditions.resolve(new Operand.Principal(PrincipalAttribute.USERNAME), ALICE))
        .containsExactly("alice");
    assertThat(
            ResourceConditions.resolve(new Operand.Principal(PrincipalAttribute.GROUP_IDS), ALICE))
        .containsExactlyInAnyOrder("g1", "g2");
    assertThat(
            ResourceConditions.resolve(new Operand.Principal(PrincipalAttribute.TENANT_IDS), ALICE))
        .containsExactly("t1");
  }

  @Test
  void resolvesTheClientIdOfAClientPrincipal() {
    final var client = CamundaAuthentication.of(b -> b.clientId("svc"));

    assertThat(
            ResourceConditions.resolve(new Operand.Principal(PrincipalAttribute.CLIENT_ID), client))
        .containsExactly("svc");
    assertThat(
            ResourceConditions.resolve(new Operand.Principal(PrincipalAttribute.USERNAME), client))
        .isEmpty();
  }

  @Test
  void absentAndEmptyPrincipalValuesResolveToNothing() {
    final var anonymous = CamundaAuthentication.anonymous();
    final var emptyUsername = CamundaAuthentication.of(b -> b.user("").groupIds(List.of("")));

    for (final var attribute : PrincipalAttribute.values()) {
      assertThat(ResourceConditions.resolve(new Operand.Principal(attribute), anonymous)).isEmpty();
    }
    assertThat(
            ResourceConditions.resolve(
                new Operand.Principal(PrincipalAttribute.USERNAME), emptyUsername))
        .isEmpty();
    assertThat(
            ResourceConditions.resolve(
                new Operand.Principal(PrincipalAttribute.GROUP_IDS), emptyUsername))
        .isEmpty();
  }

  @Test
  void conditionIsMetOnlyWhenTheValuesOverlap() {
    final var condition =
        new Condition(ResourceAttribute.WORKSPACE, new Operand.Values(Set.of("w1", "w2")));

    assertThat(
            ResourceConditions.isMet(
                condition, Map.of(ResourceAttribute.WORKSPACE, Set.of("w2")), ALICE))
        .isTrue();
    assertThat(
            ResourceConditions.isMet(
                condition, Map.of(ResourceAttribute.WORKSPACE, Set.of("w3")), ALICE))
        .isFalse();
    assertThat(ResourceConditions.isMet(condition, Map.of(), ALICE)).isFalse();
  }

  @Test
  void principalConditionIsMetAgainstTheResolvedPrincipalValues() {
    final var condition =
        new Condition(
            ResourceAttribute.CANDIDATE_GROUPS,
            new Operand.Principal(PrincipalAttribute.GROUP_IDS));

    assertThat(
            ResourceConditions.isMet(
                condition, Map.of(ResourceAttribute.CANDIDATE_GROUPS, Set.of("g2", "g9")), ALICE))
        .isTrue();
    assertThat(
            ResourceConditions.isMet(
                condition,
                Map.of(ResourceAttribute.CANDIDATE_GROUPS, Set.of("g2")),
                CamundaAuthentication.of(b -> b.user("alice"))))
        .isFalse();
  }

  @Test
  void allMetIsTrueWithoutConditions() {
    assertThat(ResourceConditions.allMet(List.of(), Map.of(), ALICE)).isTrue();
  }

  @Test
  void resolvedReplacesAPrincipalOperandByItsValues() {
    final var condition =
        new Condition(
            ResourceAttribute.ASSIGNEE, new Operand.Principal(PrincipalAttribute.USERNAME));

    assertThat(ResourceConditions.resolved(condition, ALICE))
        .isEqualTo(new Condition(ResourceAttribute.ASSIGNEE, new Operand.Values(Set.of("alice"))));
  }

  @Test
  void translatesThePropertyGrantsOfUserTasksIntoPrincipalConditions() {
    assertThat(ResourceConditions.propertyCondition(USER_TASK, RequiredAuthorization.PROP_ASSIGNEE))
        .contains(
            new Condition(
                ResourceAttribute.ASSIGNEE, new Operand.Principal(PrincipalAttribute.USERNAME)));
    assertThat(
            ResourceConditions.propertyCondition(
                USER_TASK, RequiredAuthorization.PROP_CANDIDATE_USERS))
        .contains(
            new Condition(
                ResourceAttribute.CANDIDATE_USERS,
                new Operand.Principal(PrincipalAttribute.USERNAME)));
    assertThat(
            ResourceConditions.propertyCondition(
                USER_TASK, RequiredAuthorization.PROP_CANDIDATE_GROUPS))
        .contains(
            new Condition(
                ResourceAttribute.CANDIDATE_GROUPS,
                new Operand.Principal(PrincipalAttribute.GROUP_IDS)));
  }

  @Test
  void unknownPropertiesAndTypesWithoutTheAttributeHaveNoCondition() {
    assertThat(ResourceConditions.propertyCondition(USER_TASK, "unknownProperty")).isEmpty();
    assertThat(
            ResourceConditions.propertyCondition(
                PROCESS_APPLICATION, RequiredAuthorization.PROP_ASSIGNEE))
        .isEmpty();
  }

  @Test
  void anAuthorizationIsPropertyOnlyWhenItNamesPropertiesAndNoResourceIds() {
    final RequiredAuthorization<Object> propertyOnly =
        RequiredAuthorization.of(b -> b.userTask().read().authorizedByAssignee());
    final RequiredAuthorization<Object> withSupplier =
        RequiredAuthorization.of(
            b -> b.userTask().read().authorizedByAssignee().resourceIdSupplier(r -> "t1"));
    final RequiredAuthorization<Object> withIds =
        RequiredAuthorization.of(b -> b.userTask().read().authorizedByAssignee().resourceId("t1"));
    final RequiredAuthorization<Object> withoutProperties =
        RequiredAuthorization.of(b -> b.userTask().read());

    assertThat(ResourceConditions.isPropertyOnly(propertyOnly)).isTrue();
    assertThat(ResourceConditions.isPropertyOnly(withSupplier)).isFalse();
    assertThat(ResourceConditions.isPropertyOnly(withIds)).isFalse();
    assertThat(ResourceConditions.isPropertyOnly(withoutProperties)).isFalse();
  }

  @Test
  void literalEmptyStringValuesAreNeverMet() {
    final var condition =
        new Condition(ResourceAttribute.WORKSPACE, new Operand.Values(Set.of("")));

    assertThat(ResourceConditions.resolve(condition.operand(), ALICE)).isEmpty();
    assertThat(
            ResourceConditions.isMet(
                condition, Map.of(ResourceAttribute.WORKSPACE, Set.of("")), ALICE))
        .isFalse();
  }
}
