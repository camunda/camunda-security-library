/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import static io.camunda.security.api.model.authz.AuthorizationResourceType.USER_TASK;
import static io.camunda.security.api.model.authz.PermissionType.READ;
import static io.camunda.security.core.auth.RequiredAuthorization.PROP_ASSIGNEE;
import static io.camunda.security.core.auth.RequiredAuthorization.PROP_CANDIDATE_GROUPS;
import static io.camunda.security.core.auth.RequiredAuthorization.PROP_CANDIDATE_USERS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.camunda.security.api.context.ResourceAttributeExtractor;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.authz.AuthorizationRejection;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.AuthorizationScope;
import io.camunda.security.api.model.authz.Condition;
import io.camunda.security.api.model.authz.EntityType;
import io.camunda.security.api.model.authz.Operand;
import io.camunda.security.api.model.authz.ResourceAttribute;
import io.camunda.security.api.model.authz.RoleMembership;
import io.camunda.security.core.auth.RequiredAuthorization;
import io.camunda.security.core.authz.ResourceAccessFilter.AnyOf;
import io.camunda.security.core.authz.ResourceAccessFilter.Term;
import io.camunda.security.core.port.out.AuthorizationCheckLatencyRecorder;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * Re-expresses the property cases of OC's {@code DefaultResourceAccessProviderTest} and the
 * semantics of its {@code UserTaskPropertyMatcher} with attribute conditions. Each case asserts
 * that the single check, the list filter and the per-resource access agree.
 */
class UserTaskPropertyAccessTest {

  private final InMemoryAuthorizationStore store = new InMemoryAuthorizationStore();

  private final ResourceAttributeExtractor<UserTask> userTaskExtractor =
      new ResourceAttributeExtractor<>() {
        @Override
        public AuthorizationResourceType resourceType() {
          return USER_TASK;
        }

        @Override
        public Class<UserTask> resourceClass() {
          return UserTask.class;
        }

        @Override
        public Set<ResourceAttribute> providedAttributes() {
          return USER_TASK.getSupportedAttributes();
        }

        @Override
        public Map<ResourceAttribute, Set<String>> attributesOf(final UserTask task) {
          final var attributes = new HashMap<ResourceAttribute, Set<String>>();
          if (task.assignee() != null) {
            attributes.put(ResourceAttribute.ASSIGNEE, Set.of(task.assignee()));
          }
          if (task.candidateUsers() != null) {
            attributes.put(ResourceAttribute.CANDIDATE_USERS, Set.copyOf(task.candidateUsers()));
          }
          if (task.candidateGroups() != null) {
            attributes.put(ResourceAttribute.CANDIDATE_GROUPS, Set.copyOf(task.candidateGroups()));
          }
          return attributes;
        }
      };

  private final ResourceAttributeExtractorRegistry registry =
      new ResourceAttributeExtractorRegistry(List.of(userTaskExtractor));

  private final AuthorizationService service =
      new AuthorizationService(
          new AuthorizationChecker(store),
          new PropertyAuthorizationEvaluatorRegistry(List.of()),
          new ResourceScopeExtractorRegistry(List.of()),
          registry,
          true,
          false,
          claims -> CamundaAuthentication.none(),
          AuthorizationCheckLatencyRecorder.noop());

  private final ConditionalResourceAccessProvider provider =
      new ConditionalResourceAccessProvider(new AuthorizationChecker(store), registry);

  private static RequiredAuthorization<UserTask> byProperties(final String... propertyNames) {
    return RequiredAuthorization.of(
        b ->
            b.resourceType(USER_TASK)
                .permissionType(READ)
                .resourcePropertyNames(Set.of(propertyNames)));
  }

  private static RequiredAuthorization<UserTask> byIdOrProperties(final String... propertyNames) {
    return RequiredAuthorization.of(
        b ->
            b.resourceType(USER_TASK)
                .permissionType(READ)
                .resourceIdSupplier(UserTask::id)
                .resourcePropertyNames(Set.of(propertyNames)));
  }

  private static CamundaAuthentication user(final String username, final String... groups) {
    return CamundaAuthentication.of(b -> b.user(username).groupIds(List.of(groups)));
  }

  private static UserTask task(final String assignee) {
    return new UserTask("t1", assignee, null, null);
  }

  private InMemoryAuthorizationStore grantProperties(final String username, final String... names) {
    for (final var name : names) {
      store.userGrant(username, USER_TASK, READ, AuthorizationScope.property(name));
    }
    return store;
  }

  private void assertAccess(
      final CamundaAuthentication auth,
      final RequiredAuthorization<UserTask> authorization,
      final UserTask task,
      final boolean expected) {
    final boolean single = service.check(auth, authorization, task).isRight();
    final boolean list =
        ListAccess.allows(
            provider.resolveResourceAccess(auth, authorization),
            task.id(),
            userTaskExtractor.attributesOf(task));
    final boolean perTask = provider.hasResourceAccess(auth, authorization, task).allowed();

    assertThat(single).as("single check").isEqualTo(expected);
    assertThat(list).as("list filter").isEqualTo(expected);
    assertThat(perTask).as("per-task access").isEqualTo(expected);
  }

  @Test
  void allowsWhenTheUserIsTheAssigneeAndTheAssigneePropertyIsGranted() {
    grantProperties("trevor", PROP_ASSIGNEE, PROP_CANDIDATE_USERS, PROP_CANDIDATE_GROUPS);

    assertAccess(
        user("trevor", "managers"),
        byProperties(PROP_ASSIGNEE, PROP_CANDIDATE_GROUPS),
        task("trevor"),
        true);
  }

  @Test
  void deniesWhenNoPropertyIsGranted() {
    assertAccess(user("jimmy"), byProperties(PROP_ASSIGNEE), task("jimmy"), false);
  }

  @Test
  void deniesWhenTheResourceDoesNotMatch() {
    grantProperties("franklin", PROP_ASSIGNEE);

    assertAccess(user("franklin"), byProperties(PROP_ASSIGNEE), task("michael"), false);
  }

  @Test
  void deniesForPropertiesWithoutAnAttributeCondition() {
    grantProperties("martin", "anotherValue");

    final var authorization = byProperties("anotherValue", "unknownProperty");

    assertAccess(user("martin"), authorization, task("martin"), false);
    assertThat(provider.resolveResourceAccess(user("martin"), authorization).denied()).isTrue();
  }

  @Test
  void resolvesATermForEveryGrantedRequestedProperty() {
    grantProperties("trevor", PROP_ASSIGNEE, PROP_CANDIDATE_USERS, PROP_CANDIDATE_GROUPS);

    final var access =
        provider.resolveResourceAccess(
            user("trevor", "managers", "ops"),
            byProperties(PROP_ASSIGNEE, PROP_CANDIDATE_USERS, PROP_CANDIDATE_GROUPS));

    assertThat(access.allowed()).isTrue();
    assertThat(access.wildcard()).isFalse();
    assertThat(((AnyOf) access.filter()).terms())
        .containsExactlyInAnyOrder(
            principalTerm(ResourceAttribute.ASSIGNEE, "trevor"),
            principalTerm(ResourceAttribute.CANDIDATE_USERS, "trevor"),
            principalTerm(ResourceAttribute.CANDIDATE_GROUPS, "managers", "ops"));
  }

  @Test
  void resolvesOnlyTheGrantedSubsetOfTheRequestedProperties() {
    grantProperties("trevor", PROP_CANDIDATE_USERS);

    final var access =
        provider.resolveResourceAccess(
            user("trevor"),
            byProperties(PROP_ASSIGNEE, PROP_CANDIDATE_USERS, PROP_CANDIDATE_GROUPS));

    assertThat(((AnyOf) access.filter()).terms())
        .containsExactly(principalTerm(ResourceAttribute.CANDIDATE_USERS, "trevor"));
    assertThat(access.authorization().resourcePropertyNames())
        .containsExactly(PROP_CANDIDATE_USERS);
  }

  @Test
  void resolvesNothingWhenNoRequestedPropertyIsGranted() {
    grantProperties("trevor", PROP_ASSIGNEE);

    final var access =
        provider.resolveResourceAccess(user("trevor"), byProperties(PROP_CANDIDATE_GROUPS));

    assertThat(access.denied()).isTrue();
  }

  @Test
  void assigneeMatchesOnlyTheExactUsername() {
    grantProperties("alice", PROP_ASSIGNEE);

    assertAccess(user("alice"), byProperties(PROP_ASSIGNEE), task("alice"), true);
    assertAccess(user("alice"), byProperties(PROP_ASSIGNEE), task("alice2"), false);
    assertAccess(user("alice"), byProperties(PROP_ASSIGNEE), task(null), false);
  }

  @Test
  void assigneeNeverMatchesAnEmptyUsernameOrAClientPrincipal() {
    grantProperties("", PROP_ASSIGNEE);
    store.grant(
        EntityType.CLIENT, "svc", USER_TASK, READ, AuthorizationScope.property(PROP_ASSIGNEE));

    assertAccess(user(""), byProperties(PROP_ASSIGNEE), task(""), false);
    assertAccess(
        CamundaAuthentication.of(b -> b.clientId("svc")),
        byProperties(PROP_ASSIGNEE),
        task("svc"),
        false);
  }

  @Test
  void candidateUsersMatchesWhenTheUsernameIsAmongThem() {
    grantProperties("alice", PROP_CANDIDATE_USERS);
    final var authorization = byProperties(PROP_CANDIDATE_USERS);

    assertAccess(
        user("alice"),
        authorization,
        new UserTask("t1", null, List.of("bob", "alice"), null),
        true);
    assertAccess(
        user("alice"), authorization, new UserTask("t1", null, List.of("bob"), null), false);
    assertAccess(user("alice"), authorization, new UserTask("t1", null, null, null), false);
    assertAccess(user("alice"), authorization, new UserTask("t1", null, List.of(), null), false);
  }

  @Test
  void candidateGroupsMatchesWhenAnyGroupOfTheUserIsAmongThem() {
    grantProperties("alice", PROP_CANDIDATE_GROUPS);
    final var authorization = byProperties(PROP_CANDIDATE_GROUPS);
    final var auth = user("alice", "g1", "g2");

    assertAccess(auth, authorization, new UserTask("t1", null, null, List.of("g3", "g2")), true);
    assertAccess(auth, authorization, new UserTask("t1", null, null, List.of("g3")), false);
    assertAccess(auth, authorization, new UserTask("t1", null, null, null), false);
    assertAccess(auth, authorization, new UserTask("t1", null, null, List.of()), false);
    assertAccess(
        user("alice"), authorization, new UserTask("t1", null, null, List.of("g1")), false);
  }

  @Test
  void anyOfTheGrantedPropertiesIsEnough() {
    grantProperties("alice", PROP_ASSIGNEE, PROP_CANDIDATE_GROUPS);
    final var authorization = byProperties(PROP_ASSIGNEE, PROP_CANDIDATE_GROUPS);

    assertAccess(
        user("alice", "g1"), authorization, new UserTask("t1", "bob", null, List.of("g1")), true);
    assertAccess(
        user("alice", "g1"), authorization, new UserTask("t1", "bob", null, List.of("g2")), false);
  }

  @Test
  void onlyTheGrantedPropertiesAreEvaluated() {
    grantProperties("alice", PROP_ASSIGNEE);

    assertAccess(
        user("alice", "g1"),
        byProperties(PROP_ASSIGNEE, PROP_CANDIDATE_GROUPS),
        new UserTask("t1", "bob", null, List.of("g1")),
        false);
  }

  @Test
  void propertyGrantsOfGroupsAndUnconditionalRolesApply() {
    store.grant(
        EntityType.GROUP, "managers", USER_TASK, READ, AuthorizationScope.property(PROP_ASSIGNEE));
    store.roleGrant("watcher", USER_TASK, READ, AuthorizationScope.property(PROP_CANDIDATE_USERS));
    final var auth =
        CamundaAuthentication.of(
            b -> b.user("alice").groupIds(List.of("managers")).roleIds(List.of("watcher")));

    assertAccess(auth, byProperties(PROP_ASSIGNEE), task("alice"), true);
    assertAccess(
        auth,
        byProperties(PROP_CANDIDATE_USERS),
        new UserTask("t1", null, List.of("alice"), null),
        true);
  }

  @Test
  void propertyGrantsOfAConditionalRoleApplyOnlyWhereTheMembershipConditionsAreMet() {
    store.roleGrant("ops-assignee", USER_TASK, READ, AuthorizationScope.property(PROP_ASSIGNEE));
    final var inOps =
        new Condition(ResourceAttribute.CANDIDATE_GROUPS, new Operand.Values(Set.of("ops")));
    final var auth =
        CamundaAuthentication.of(
            b ->
                b.user("alice")
                    .roleMemberships(List.of(new RoleMembership("ops-assignee", List.of(inOps)))));
    final var authorization = byProperties(PROP_ASSIGNEE);

    assertAccess(auth, authorization, new UserTask("t1", "alice", null, List.of("ops")), true);
    assertAccess(auth, authorization, new UserTask("t1", "alice", null, List.of("dev")), false);
    assertAccess(auth, authorization, new UserTask("t1", "bob", null, List.of("ops")), false);
    assertThat(((AnyOf) provider.resolveResourceAccess(auth, authorization).filter()).terms())
        .containsExactly(
            new Term(
                Set.of(),
                List.of(
                    inOps,
                    new Condition(
                        ResourceAttribute.ASSIGNEE, new Operand.Values(Set.of("alice"))))));
  }

  @Test
  void aGrantOnTheResourceIdAppliesNextToThePropertyGrants() {
    store.userGrant("alice", USER_TASK, READ, AuthorizationScope.id("t1"));
    grantProperties("alice", PROP_ASSIGNEE);
    final var authorization = byIdOrProperties(PROP_ASSIGNEE);

    assertAccess(user("alice"), authorization, new UserTask("t1", "bob", null, null), true);
    assertAccess(user("alice"), authorization, new UserTask("t2", "alice", null, null), true);
    assertAccess(user("alice"), authorization, new UserTask("t2", "bob", null, null), false);
  }

  @Test
  void aPropertyOnlyAuthorizationIgnoresGrantsOnResourceIds() {
    store.userGrant("alice", USER_TASK, READ, AuthorizationScope.id("t1"));
    store.userGrant("alice", USER_TASK, READ, AuthorizationScope.WILDCARD);

    assertAccess(
        user("alice"), byProperties(PROP_ASSIGNEE), new UserTask("t1", "bob", null, null), false);
  }

  @Test
  void rejectionNamesThePropertiesForAPropertyOnlyAuthorization() {
    final var result =
        service.check(
            user("alice"), byProperties(PROP_ASSIGNEE, PROP_CANDIDATE_USERS), task("alice"));

    assertThat(result.isLeft()).isTrue();
    assertThat(result.leftValue())
        .isEqualTo(
            new AuthorizationRejection.Property(
                USER_TASK, READ, new TreeSet<>(Set.of(PROP_ASSIGNEE, PROP_CANDIDATE_USERS))));
  }

  @Test
  void resourceIdsOnAPropertyAuthorizationAreRejected() {
    final RequiredAuthorization<UserTask> withIds =
        RequiredAuthorization.of(
            b ->
                b.resourceType(USER_TASK)
                    .permissionType(READ)
                    .resourceId("t1")
                    .resourcePropertyNames(Set.of(PROP_ASSIGNEE)));

    assertThatThrownBy(() -> service.check(user("alice"), withIds, task("alice")))
        .isInstanceOf(IllegalArgumentException.class);
  }

  private static Term principalTerm(final ResourceAttribute attribute, final String... values) {
    return new Term(
        Set.of(), List.of(new Condition(attribute, new Operand.Values(Set.of(values)))));
  }

  @Test
  void nullElementsOfAttributeValuesCountAsAbsent() {
    grantProperties("alice", PROP_CANDIDATE_USERS);
    final var withNull = new HashSet<String>();
    withNull.add(null);
    final var extractor =
        new ResourceAttributeExtractor<UserTask>() {
          @Override
          public AuthorizationResourceType resourceType() {
            return USER_TASK;
          }

          @Override
          public Class<UserTask> resourceClass() {
            return UserTask.class;
          }

          @Override
          public Set<ResourceAttribute> providedAttributes() {
            return Set.of(ResourceAttribute.CANDIDATE_USERS);
          }

          @Override
          public Map<ResourceAttribute, Set<String>> attributesOf(final UserTask task) {
            return Map.of(ResourceAttribute.CANDIDATE_USERS, withNull);
          }
        };
    final var nullRegistry = new ResourceAttributeExtractorRegistry(List.of(extractor));

    assertThat(nullRegistry.attributesOf(USER_TASK, task("alice"))).isEmpty();
  }

  private record UserTask(
      String id, String assignee, List<String> candidateUsers, List<String> candidateGroups) {}
}
