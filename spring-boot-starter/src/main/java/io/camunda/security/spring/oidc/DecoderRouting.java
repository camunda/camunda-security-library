/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import java.util.List;
import java.util.function.Supplier;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

/**
 * How the library's default decoder ({@code OidcWebappClientBeansConfiguration#jwtDecoder}) routes
 * tokens, so the claim converters route them the same way. Exactly one component is set.
 *
 * @param lazyRepository the library's repository, whose providers the decoder routes by
 * @param registrations the registrations of a host repository, read once and shared by the decoder
 *     and the claim converters. A dynamic repository can change between two reads, and both must
 *     decide the owner of an issuer from the same registrations.
 */
record DecoderRouting(
    LazyClientRegistrationRepository lazyRepository,
    Supplier<List<ClientRegistration>> registrations) {

  static DecoderRouting byProviders(final LazyClientRegistrationRepository repository) {
    return new DecoderRouting(repository, null);
  }

  static DecoderRouting byRegistrations(final Supplier<List<ClientRegistration>> registrations) {
    return new DecoderRouting(null, registrations);
  }
}
