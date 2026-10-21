/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

/** A host repository whose registrations change order, as a dynamic repository can. */
final class ReorderableRegistrationRepository
    implements ClientRegistrationRepository, Iterable<ClientRegistration> {

  private final List<ClientRegistration> registrations;

  ReorderableRegistrationRepository(final ClientRegistration... registrations) {
    this.registrations = new ArrayList<>(List.of(registrations));
  }

  void reverse() {
    Collections.reverse(registrations);
  }

  @Override
  public ClientRegistration findByRegistrationId(final String registrationId) {
    return registrations.stream()
        .filter(r -> r.getRegistrationId().equals(registrationId))
        .findFirst()
        .orElse(null);
  }

  @Override
  public Iterator<ClientRegistration> iterator() {
    return List.copyOf(registrations).iterator();
  }
}
