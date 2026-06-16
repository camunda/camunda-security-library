/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;

/**
 * Factory for creating a per-scope {@link OAuth2AuthorizedClientManager} from its collaborating
 * repositories. Keeping it a factory avoids holding a global manager and lets tests stub the
 * creation.
 */
@FunctionalInterface
public interface OAuth2AuthorizedClientManagerFactory {

  OAuth2AuthorizedClientManager create(
      ClientRegistrationRepository clientRegistrationRepository,
      OAuth2AuthorizedClientRepository authorizedClientRepository);
}
