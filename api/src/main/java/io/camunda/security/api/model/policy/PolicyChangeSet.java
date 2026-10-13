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
 * and tenants. Applying the same {@code policyVersion} again must be harmless. Deleting a tenant,
 * role, group or mapping rule cascades to its memberships and owned authorizations, so listing
 * those is optional.
 *
 * <p>An ID or key may not appear in both upserts and deletions, and the upserts hold at most one
 * authorization per {@link PolicyAuthorizationKey}.
 */
public record PolicyChangeSet(
    long policyVersion,
    PolicyChangeSetKind kind,
    PolicyUpserts upserts,
    PolicyDeletions deletions) {

  public PolicyChangeSet {
    if (policyVersion < 0) {
      throw new IllegalArgumentException("policyVersion must not be negative: " + policyVersion);
    }
    Objects.requireNonNull(kind, "kind must not be null");
    upserts = upserts == null ? new PolicyUpserts(null, null, null, null, null, null) : upserts;
    deletions =
        deletions == null ? new PolicyDeletions(null, null, null, null, null, null) : deletions;
    if (kind == PolicyChangeSetKind.SNAPSHOT && !isEmpty(deletions)) {
      throw new IllegalArgumentException("A SNAPSHOT must not carry deletions");
    }
    requireNoDuplicateAuthorizationKeys(upserts);
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

  private static void requireNoDuplicateAuthorizationKeys(final PolicyUpserts upserts) {
    final Set<PolicyAuthorizationKey> seen = new HashSet<>();
    for (final PolicyAuthorization authorization : upserts.authorizations()) {
      if (!seen.add(authorization.key())) {
        throw new IllegalArgumentException(
            "Duplicate authorization key in upserts: " + authorization.key());
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
