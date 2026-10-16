/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.scim;

import io.camunda.security.core.port.in.ScimUserPort;
import io.camunda.security.core.port.out.ScimUserRepositoryPort;
import io.camunda.security.core.scim.filter.ScimFilter;
import io.camunda.security.core.scim.filter.ScimFilterEvaluator;
import io.camunda.security.core.scim.filter.ScimFilterParser;
import io.camunda.security.core.scim.patch.ScimPatchEngine;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default {@link ScimUserPort}: validation, {@code userName} uniqueness, PATCH, filtering and
 * paging on top of a {@link ScimUserRepositoryPort}. Mutations are serialized so the
 * check-then-write uniqueness test is atomic within one instance; a host with several instances
 * must additionally enforce uniqueness in its store.
 *
 * <p>Logs carry resource ids and operation names only: SCIM payloads are PII.
 */
public final class ScimUserService implements ScimUserPort {

  private static final Logger LOG = LoggerFactory.getLogger(ScimUserService.class);

  /** Upper bound for {@code count}, advertised as {@code filter.maxResults}. */
  public static final int MAX_PAGE_SIZE = 200;

  private final ScimUserRepositoryPort repository;
  private final ScimUserValidator validator;
  private final ScimPatchEngine patchEngine;
  private final Clock clock;

  public ScimUserService(
      final ScimUserRepositoryPort repository,
      final ScimUserValidator validator,
      final ScimPatchEngine patchEngine,
      final Clock clock) {
    this.repository = repository;
    this.validator = validator;
    this.patchEngine = patchEngine;
    this.clock = clock;
  }

  @Override
  public synchronized ScimUserResource create(final Map<String, Object> body) {
    LOG.debug("SCIM create user: validating");
    final Map<String, Object> attributes = validator.validateBody(body);
    requireUniqueUserName(attributes, null);
    final Instant now = clock.instant();
    final ScimUserResource user =
        new ScimUserResource(UUID.randomUUID().toString(), attributes, now, now, 1);
    final ScimUserResource saved = repository.save(user);
    LOG.info("SCIM user created: id={}", saved.id());
    return saved;
  }

  @Override
  public ScimUserResource get(final String id) {
    LOG.debug("SCIM get user: id={}", id);
    return load(id);
  }

  @Override
  public synchronized ScimUserResource replace(final String id, final Map<String, Object> body) {
    LOG.debug("SCIM replace user: id={}", id);
    final ScimUserResource existing = load(id);
    final Map<String, Object> attributes = validator.validateBody(body);
    requireUniqueUserName(attributes, id);
    final ScimUserResource saved =
        repository.save(existing.withAttributes(attributes, clock.instant()));
    LOG.info("SCIM user replaced: id={} version={}", saved.id(), saved.version());
    return saved;
  }

  @Override
  public synchronized ScimUserResource patch(
      final String id, final Map<String, Object> patchRequest) {
    LOG.debug("SCIM patch user: id={}", id);
    final ScimUserResource existing = load(id);
    final Map<String, Object> attributes = patchEngine.apply(existing.attributes(), patchRequest);
    requireUniqueUserName(attributes, id);
    final ScimUserResource saved =
        repository.save(existing.withAttributes(attributes, clock.instant()));
    LOG.info("SCIM user patched: id={} version={}", saved.id(), saved.version());
    return saved;
  }

  @Override
  public synchronized void delete(final String id) {
    LOG.debug("SCIM delete user: id={}", id);
    if (!repository.deleteById(id)) {
      throw ScimException.notFound("User '" + id + "' not found");
    }
    LOG.info("SCIM user deleted: id={}", id);
  }

  @Override
  public ScimUserPage search(final String filter, final int startIndex, final int count) {
    final int start = Math.max(startIndex, 1);
    final int size = Math.min(Math.max(count, 0), MAX_PAGE_SIZE);
    final ScimFilter parsed = filter == null || filter.isBlank() ? null : parse(filter);
    final List<ScimUserResource> matches =
        repository.findAll().stream()
            .filter(u -> parsed == null || matchesFilter(parsed, u))
            .toList();
    final int from = Math.min(start - 1, matches.size());
    final int to = Math.min(from + size, matches.size());
    LOG.debug(
        "SCIM search users: filter={} matches={} startIndex={} count={}",
        filter,
        matches.size(),
        start,
        size);
    return new ScimUserPage(matches.size(), start, matches.subList(from, to));
  }

  private ScimFilter parse(final String filter) {
    final ScimFilter parsed = ScimFilterParser.parse(filter);
    ScimFilterEvaluator.validate(parsed);
    return parsed;
  }

  private boolean matchesFilter(final ScimFilter filter, final ScimUserResource user) {
    return ScimFilterEvaluator.matches(filter, ScimUserRepresentation.toDocument(user, null));
  }

  private ScimUserResource load(final String id) {
    return repository
        .findById(id)
        .orElseThrow(() -> ScimException.notFound("User '" + id + "' not found"));
  }

  private void requireUniqueUserName(final Map<String, Object> attributes, final String selfId) {
    final String userName = (String) attributes.get("userName");
    repository
        .findByUserName(userName)
        .filter(other -> !other.id().equals(selfId))
        .ifPresent(
            other -> {
              LOG.debug("SCIM userName conflict with existing user id={}", other.id());
              throw ScimException.uniqueness("userName is already in use");
            });
  }
}
