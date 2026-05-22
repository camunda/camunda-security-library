/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.api.model.config.oidc.OidcProvidersConfiguration;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class OidcAuthenticationConfigurationRepositoryTest {

  private CamundaSecurityLibraryProperties properties;

  @BeforeEach
  void setUp() {
    properties = new CamundaSecurityLibraryProperties();
  }

  @Test
  void shouldReturnEmptyMapWhenNeitherFlatNorProvidersConfigured() {
    final var repo = new OidcAuthenticationConfigurationRepository(properties);
    assertThat(repo.getOidcAuthenticationConfigurations()).isEmpty();
  }

  @Test
  void shouldIncludeFlatBlockUnderDefaultRegistrationIdWhenClientIdSet() {
    final var oidc = new OidcConfiguration();
    oidc.setClientId("client1");
    oidc.setIssuerUri("https://issuer1.example.com");
    properties.getAuthentication().setOidc(oidc);

    final var repo = new OidcAuthenticationConfigurationRepository(properties);

    assertThat(repo.getOidcAuthenticationConfigurations()).containsOnlyKeys("oidc");
    assertThat(repo.getOidcAuthenticationConfigurations().get("oidc").getClientId())
        .isEqualTo("client1");
  }

  @Test
  void shouldNotIncludeFlatBlockWhenClientIdBlank() {
    final var oidc = new OidcConfiguration();
    oidc.setClientId("");
    properties.getAuthentication().setOidc(oidc);

    final var repo = new OidcAuthenticationConfigurationRepository(properties);
    assertThat(repo.getOidcAuthenticationConfigurations()).isEmpty();
  }

  @Test
  void shouldIncludeProvidersMapEntries() {
    final var providerOidc = new OidcConfiguration();
    providerOidc.setClientId("providerClient");
    providerOidc.setIssuerUri("https://provider.example.com");
    final var providers = new OidcProvidersConfiguration();
    providers.getOidc().put("myProvider", providerOidc);
    properties.getAuthentication().setProviders(providers);

    final var repo = new OidcAuthenticationConfigurationRepository(properties);

    assertThat(repo.getOidcAuthenticationConfigurations()).containsOnlyKeys("myProvider");
    assertThat(repo.getOidcAuthenticationConfigurations().get("myProvider").getClientId())
        .isEqualTo("providerClient");
  }

  @Test
  void shouldMergeFlatAndProvidersWithProviderOverwritingOnCollision() {
    final var flat = new OidcConfiguration();
    flat.setClientId("flatClient");
    flat.setIssuerUri("https://flat.example.com");
    // default registrationId is "oidc"
    properties.getAuthentication().setOidc(flat);

    final var override = new OidcConfiguration();
    override.setClientId("overrideClient");
    override.setIssuerUri("https://override.example.com");
    final var providers = new OidcProvidersConfiguration();
    providers.getOidc().put("oidc", override); // same key — provider overwrites flat
    properties.getAuthentication().setProviders(providers);

    final var repo = new OidcAuthenticationConfigurationRepository(properties);

    assertThat(repo.getOidcAuthenticationConfigurations()).containsOnlyKeys("oidc");
    assertThat(repo.getOidcAuthenticationConfigurations().get("oidc").getClientId())
        .isEqualTo("overrideClient");
  }

  @Test
  void shouldReturnConfigByRegistrationId() {
    final var oidc = new OidcConfiguration();
    oidc.setClientId("client1");
    oidc.setIssuerUri("https://issuer.example.com");
    properties.getAuthentication().setOidc(oidc);

    final var repo = new OidcAuthenticationConfigurationRepository(properties);

    assertThat(repo.getOidcAuthenticationConfigurationById("oidc")).isNotNull();
    assertThat(repo.getOidcAuthenticationConfigurationById("unknown")).isNull();
  }

  @Test
  void shouldUseFlatRegistrationIdPropertyWhenCustomized() {
    final var oidc = new OidcConfiguration();
    oidc.setClientId("client1");
    oidc.setRegistrationId("myCustomId");
    oidc.setIssuerUri("https://issuer.example.com");
    properties.getAuthentication().setOidc(oidc);

    final var repo = new OidcAuthenticationConfigurationRepository(properties);

    assertThat(repo.getOidcAuthenticationConfigurations()).containsOnlyKeys("myCustomId");
  }
}
