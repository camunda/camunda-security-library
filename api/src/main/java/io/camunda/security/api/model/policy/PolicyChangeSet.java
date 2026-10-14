/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.policy;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;

/**
 * A versioned set of policy changes, the payload handed to {@code PolicyProjectionPort}. It is
 * plain data and round-trips through a Jackson {@code ObjectMapper} without annotations; invalid
 * payloads fail in the canonical constructor.
 *
 * <p>A {@link PolicyChangeSetKind#SNAPSHOT} is the authoritative full state, but only over entities
 * the projection created earlier. Bootstrap entities (default roles, users, clients) are never
 * removed by a snapshot. A snapshot has no deletions. A {@link PolicyChangeSetKind#DELTA} applies
 * exactly the listed upserts and deletions; the caller guarantees contiguous versions and fetches a
 * snapshot when it detects a gap.
 *
 * <p>Apply order: upsert tenants, roles, groups and mapping rules; upsert memberships; upsert
 * authorizations; delete authorizations; delete memberships; delete mapping rules, groups, roles
 * and tenants. Applying the same {@code policyVersion} again must be harmless.
 *
 * <p>Deletes cascade only partly. Deleting a role or group removes the memberships where it is the
 * target (its own members) and its owned authorizations, but not the memberships where it is itself
 * the member (group to role, group to tenant, role to tenant). The sender must list those as
 * membership deletions, otherwise they survive and keep resolving. Deleting a mapping rule removes
 * its memberships in tenants, roles and groups plus its owned authorizations; deleting a tenant
 * removes its members.
 *
 * <p>An ID or key may not appear in both upserts and deletions, and no list may contain the same
 * ID, membership or authorization key twice. {@code policyVersion} starts at 1.
 */
public record PolicyChangeSet(
    long policyVersion,
    PolicyChangeSetKind kind,
    PolicyUpserts upserts,
    PolicyDeletions deletions) {

  private static final PolicyUpserts NO_UPSERTS =
      new PolicyUpserts(null, null, null, null, null, null);
  private static final PolicyDeletions NO_DELETIONS =
      new PolicyDeletions(null, null, null, null, null, null);

  public PolicyChangeSet {
    if (policyVersion < 1) {
      throw new IllegalArgumentException("policyVersion must be at least 1: " + policyVersion);
    }
    Objects.requireNonNull(kind, "kind must not be null");
    upserts = upserts == null ? NO_UPSERTS : upserts;
    deletions = deletions == null ? NO_DELETIONS : deletions;
    if (kind == PolicyChangeSetKind.SNAPSHOT && !isEmpty(deletions)) {
      throw new IllegalArgumentException("A SNAPSHOT must not carry deletions");
    }
    requireNoDuplicates(upserts, deletions);
    requireNoOverlap(upserts, deletions);
  }

  private static boolean isEmpty(final PolicyDeletions deletions) {
    return deletions.tenantIds().isEmpty()
        && deletions.roleIds().isEmpty()
        && deletions.groupIds().isEmpty()
        && deletions.mappingRuleIds().isEmpty()
        && deletions.memberships().isEmpty()
        && deletions.authorizations().isEmpty();
  }

  private static void requireNoDuplicates(final PolicyUpserts up, final PolicyDeletions del) {
    requireUnique("upserted tenant", ids(up.tenants(), PolicyTenant::tenantId));
    requireUnique("upserted role", ids(up.roles(), PolicyRole::roleId));
    requireUnique("upserted group", ids(up.groups(), PolicyGroup::groupId));
    requireUnique(
        "upserted mapping rule", ids(up.mappingRules(), PolicyMappingRule::mappingRuleId));
    requireUnique("upserted membership", up.memberships());
    requireUnique("upserted authorization", ids(up.authorizations(), PolicyAuthorization::key));
    requireUnique("deleted tenant", del.tenantIds());
    requireUnique("deleted role", del.roleIds());
    requireUnique("deleted group", del.groupIds());
    requireUnique("deleted mapping rule", del.mappingRuleIds());
    requireUnique("deleted membership", del.memberships());
    requireUnique("deleted authorization", del.authorizations());
  }

  private static void requireUnique(final String what, final Collection<?> keys) {
    final Set<Object> seen = new HashSet<>();
    for (final Object key : keys) {
      if (!seen.add(key)) {
        throw new IllegalArgumentException("Duplicate " + what + ": " + key);
      }
    }
  }

  private static void requireNoOverlap(final PolicyUpserts up, final PolicyDeletions del) {
    requireDisjoint("tenant", ids(up.tenants(), PolicyTenant::tenantId), del.tenantIds());
    requireDisjoint("role", ids(up.roles(), PolicyRole::roleId), del.roleIds());
    requireDisjoint("group", ids(up.groups(), PolicyGroup::groupId), del.groupIds());
    requireDisjoint(
        "mapping rule",
        ids(up.mappingRules(), PolicyMappingRule::mappingRuleId),
        del.mappingRuleIds());
    requireDisjoint("membership", up.memberships(), del.memberships());
    requireDisjoint(
        "authorization", ids(up.authorizations(), PolicyAuthorization::key), del.authorizations());
  }

  private static <E, K> List<K> ids(final List<E> entities, final Function<E, K> idOf) {
    return entities.stream().map(idOf).toList();
  }

  private static <K> void requireDisjoint(
      final String what, final Collection<K> upserted, final Collection<K> deleted) {
    final Set<K> upsertedSet = new HashSet<>(upserted);
    for (final K key : deleted) {
      if (upsertedSet.contains(key)) {
        throw new IllegalArgumentException(
            "The " + what + " " + key + " is both upserted and deleted");
      }
    }
  }
}
