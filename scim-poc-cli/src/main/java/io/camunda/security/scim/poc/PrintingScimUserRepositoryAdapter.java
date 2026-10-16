/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.scim.poc;

import io.camunda.security.core.port.out.ScimUserRepositoryPort;
import io.camunda.security.core.scim.ScimUserRepresentation;
import io.camunda.security.core.scim.ScimUserResource;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import tools.jackson.databind.ObjectMapper;

/**
 * In-memory {@link ScimUserRepositoryPort} that prints every stored or deleted entity to stdout.
 */
final class PrintingScimUserRepositoryAdapter implements ScimUserRepositoryPort {

  private final Map<String, ScimUserResource> users = new ConcurrentHashMap<>();
  private final ObjectMapper mapper;

  PrintingScimUserRepositoryAdapter(final ObjectMapper mapper) {
    this.mapper = mapper;
  }

  @Override
  public ScimUserResource save(final ScimUserResource user) {
    final boolean update = users.put(user.id(), user) != null;
    print(update ? "UPDATED" : "CREATED", user);
    return user;
  }

  @Override
  public Optional<ScimUserResource> findById(final String id) {
    return Optional.ofNullable(users.get(id));
  }

  @Override
  public Optional<ScimUserResource> findByUserName(final String userName) {
    final String wanted = userName.toLowerCase(Locale.ROOT);
    return users.values().stream()
        .filter(u -> u.userName().toLowerCase(Locale.ROOT).equals(wanted))
        .findFirst();
  }

  @Override
  public List<ScimUserResource> findAll() {
    return new ArrayList<>(users.values());
  }

  @Override
  public boolean deleteById(final String id) {
    final ScimUserResource removed = users.remove(id);
    if (removed != null) {
      print("DELETED", removed);
    }
    return removed != null;
  }

  private void print(final String action, final ScimUserResource user) {
    System.out.println(
        "\n======== USER " + action + " (stored users: " + users.size() + ") ========");
    System.out.println(mapper.writeValueAsString(ScimUserRepresentation.toDocument(user, null)));
    System.out.println("=====================================================");
  }
}
