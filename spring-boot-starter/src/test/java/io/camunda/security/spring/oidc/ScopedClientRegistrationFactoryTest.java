/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link ScopedClientRegistrationFactory}. All providers use explicit endpoint URIs
 * (no {@code issuer-uri}) to avoid any network calls during testing.
 */
class ScopedClientRegistrationFactoryTest {

  private ScopedClientRegistrationFactory factory;
  private OidcTestServer oidcServer;

  @BeforeEach
  void setUp() {
    factory = new ScopedClientRegistrationFactory();
  }

  @AfterEach
  void tearDown() {
    if (oidcServer != null) {
      oidcServer.close();
      oidcServer = null;
    }
  }

  // ---------------------------------------------------------------------------
  // createFromProviderMap
  // ---------------------------------------------------------------------------

  @Test
  void shouldBuildOneRegistrationFromSingleProviderMapEntry() {
    final var oidc = explicitEndpoints("my-client", "https://idp.example.com");
    final var registrations = factory.createFromProviderMap(Map.of("myid", oidc));

    assertThat(registrations).hasSize(1);
    final var reg = registrations.get(0);
    assertThat(reg.getRegistrationId()).isEqualTo("myid");
    assertThat(reg.getClientId()).isEqualTo("my-client");
    assertThat(reg.getProviderDetails().getAuthorizationUri())
        .isEqualTo("https://idp.example.com/auth");
    assertThat(reg.getProviderDetails().getTokenUri()).isEqualTo("https://idp.example.com/token");
    assertThat(reg.getProviderDetails().getJwkSetUri()).isEqualTo("https://idp.example.com/jwks");
  }

  @Test
  void shouldBuildOneRegistrationPerEntryInProviderMap() {
    final Map<String, OidcConfiguration> providers = new LinkedHashMap<>();
    providers.put("idp1", explicitEndpoints("client1", "https://idp1.example.com"));
    providers.put("idp2", explicitEndpoints("client2", "https://idp2.example.com"));

    final var registrations = factory.createFromProviderMap(providers);

    assertThat(registrations).hasSize(2);
    assertThat(registrations.get(0).getRegistrationId()).isEqualTo("idp1");
    assertThat(registrations.get(0).getClientId()).isEqualTo("client1");
    assertThat(registrations.get(1).getRegistrationId()).isEqualTo("idp2");
    assertThat(registrations.get(1).getClientId()).isEqualTo("client2");
  }

  @Test
  void shouldFailWithActionableErrorWhenProviderMapKeyIsBlank() {
    final var oidc = explicitEndpoints("my-client", "https://idp.example.com");
    assertThatThrownBy(() -> factory.createFromProviderMap(Map.of("", oidc)))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("registrationId")
        .hasMessageContaining("registration-id");
  }

  @Test
  void shouldFailWithActionableErrorWhenNoIssuerAndMissingExplicitEndpoints() {
    final var oidc = OidcConfiguration.builder().clientId("my-client").build();
    assertThatThrownBy(() -> factory.createFromProviderMap(Map.of("myid", oidc)))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("'myid'")
        .hasMessageContaining("issuer-uri")
        .hasMessageContaining("jwk-set-uri");
  }

  @Test
  void shouldFailFastWhenProviderMapIsNull() {
    assertThatThrownBy(() -> factory.createFromProviderMap(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessageContaining("providers");
  }

  @Test
  void shouldPrefixRedirectUriWhenScopedPathGiven() {
    // given
    final var oidc = explicitEndpoints("my-client", "https://idp.example.com");

    // when
    final var registrations =
        factory.createFromProviderMap(Map.of("myid", oidc), "/physical-tenants/t1/sso-callback");

    // then
    assertThat(registrations).hasSize(1);
    assertThat(registrations.get(0).getRedirectUri())
        .isEqualTo("{baseUrl}/physical-tenants/t1/sso-callback");
  }

  @Test
  void shouldRejectScopedRedirectUriPathWithoutLeadingSlash() {
    // given
    final var oidc = explicitEndpoints("my-client", "https://idp.example.com");

    // when / then
    assertThatThrownBy(
            () ->
                factory.createFromProviderMap(
                    Map.of("myid", oidc), "physical-tenants/t1/sso-callback"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void shouldUseConfiguredRedirectUriWhenNoScopedPath() {
    // given
    final var oidc = explicitEndpoints("my-client", "https://idp.example.com");

    // when
    final var registrations = factory.createFromProviderMap(Map.of("myid", oidc));

    // then
    assertThat(registrations).hasSize(1);
    assertThat(registrations.get(0).getRedirectUri())
        .isEqualTo("{baseUrl}/login/oauth2/code/{registrationId}");
  }

  @Test
  void shouldCarryAudiencesInProviderConfigurationMetadata() {
    // given
    final var oidc =
        OidcConfiguration.builder()
            .clientId("my-client")
            .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
            .authorizationUri("https://idp.example.com/auth")
            .tokenUri("https://idp.example.com/token")
            .jwkSetUri("https://idp.example.com/jwks")
            .audiences(Set.of("scoped-aud"))
            .build();

    // when
    final var registrations = factory.createFromProviderMap(Map.of("myid", oidc));

    // then
    assertThat(registrations).hasSize(1);
    final var metadata = registrations.get(0).getProviderDetails().getConfigurationMetadata();
    assertThat(metadata.get(TokenValidatorFactory.AUDIENCES_METADATA_KEY))
        .asInstanceOf(InstanceOfAssertFactories.collection(String.class))
        .containsExactly("scoped-aud");
  }

  @Test
  void shouldCarryBothEndSessionAndAudiencesInMetadata() {
    // given
    final var oidc =
        OidcConfiguration.builder()
            .clientId("my-client")
            .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
            .authorizationUri("https://idp.example.com/auth")
            .tokenUri("https://idp.example.com/token")
            .jwkSetUri("https://idp.example.com/jwks")
            .endSessionEndpointUri("https://idp.example.com/logout")
            .audiences(Set.of("scoped-aud"))
            .build();

    // when
    final var registrations = factory.createFromProviderMap(Map.of("myid", oidc));

    // then
    final var metadata = registrations.get(0).getProviderDetails().getConfigurationMetadata();
    assertThat(metadata).containsKey("end_session_endpoint");
    assertThat(metadata).containsKey(TokenValidatorFactory.AUDIENCES_METADATA_KEY);
    assertThat(metadata.get("end_session_endpoint")).isEqualTo("https://idp.example.com/logout");
  }

  @Test
  void shouldPreserveDiscoveredEndSessionEndpointWhenStashingAudiences() throws Exception {
    // given a discovery document that advertises an end_session_endpoint (as real IdPs do) but no
    // explicitly-configured end-session URI on the OidcConfiguration
    oidcServer =
        OidcTestServer.startDiscovery(
            """
            {
              "issuer": "%1$s",
              "authorization_endpoint": "%1$s/auth",
              "token_endpoint": "%1$s/token",
              "jwks_uri": "%1$s/jwks",
              "end_session_endpoint": "%1$s/logout",
              "response_types_supported": ["code"],
              "subject_types_supported": ["public"],
              "id_token_signing_alg_values_supported": ["RS256"]
            }
            """);
    final var oidc =
        OidcConfiguration.builder()
            .clientId("my-client")
            .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
            .issuerUri(oidcServer.issuerUri())
            .audiences(Set.of("scoped-aud"))
            .build();

    // when discovery populates the registration's metadata, then we merge our additions on top
    final var registrations = factory.createFromProviderMap(Map.of("myid", oidc));

    // then the discovered end_session_endpoint survives alongside the stashed audiences
    final var metadata = registrations.get(0).getProviderDetails().getConfigurationMetadata();
    assertThat(metadata.get("end_session_endpoint")).isEqualTo(oidcServer.issuerUri() + "/logout");
    assertThat(metadata.get(TokenValidatorFactory.AUDIENCES_METADATA_KEY))
        .asInstanceOf(InstanceOfAssertFactories.collection(String.class))
        .containsExactly("scoped-aud");
  }

  @Test
  void shouldOverrideDiscoveredEndSessionEndpointWithExplicitConfig() throws Exception {
    // given a discovery document advertising one end_session_endpoint
    oidcServer =
        OidcTestServer.startDiscovery(
            """
            {
              "issuer": "%1$s",
              "authorization_endpoint": "%1$s/auth",
              "token_endpoint": "%1$s/token",
              "jwks_uri": "%1$s/jwks",
              "end_session_endpoint": "%1$s/discovered-logout",
              "response_types_supported": ["code"],
              "subject_types_supported": ["public"],
              "id_token_signing_alg_values_supported": ["RS256"]
            }
            """);
    // and an explicitly-configured end-session URI
    final var oidc =
        OidcConfiguration.builder()
            .clientId("my-client")
            .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
            .issuerUri(oidcServer.issuerUri())
            .endSessionEndpointUri("https://explicit.example.com/logout")
            .build();

    // when
    final var registrations = factory.createFromProviderMap(Map.of("myid", oidc));

    // then explicit config wins over the discovered value
    final var metadata = registrations.get(0).getProviderDetails().getConfigurationMetadata();
    assertThat(metadata.get("end_session_endpoint"))
        .isEqualTo("https://explicit.example.com/logout");
  }

  @Test
  void shouldStashEmptyAudiencesEntryWhenAudiencesUnset() {
    // given a scoped provider with no audiences configured
    final var oidc = explicitEndpoints("my-client", "https://idp.example.com");

    // when
    final var registrations = factory.createFromProviderMap(Map.of("myid", oidc));

    // then the audiences key is still present (authoritative by presence) but empty
    final var metadata = registrations.get(0).getProviderDetails().getConfigurationMetadata();
    assertThat(metadata).containsKey(TokenValidatorFactory.AUDIENCES_METADATA_KEY);
    assertThat(metadata.get(TokenValidatorFactory.AUDIENCES_METADATA_KEY))
        .asInstanceOf(InstanceOfAssertFactories.collection(String.class))
        .isEmpty();
  }

  // ---------------------------------------------------------------------------
  // create(AuthenticationConfiguration)
  // ---------------------------------------------------------------------------

  @Test
  void shouldBuildOneRegistrationFromFlatAuthenticationConfiguration() {
    final var auth = new AuthenticationConfiguration();
    final var flat = explicitEndpoints("flat-client", "https://flat.example.com");
    flat.setRegistrationId("oidc");
    auth.setOidc(flat);

    final var registrations = factory.create(auth);

    assertThat(registrations).hasSize(1);
    assertThat(registrations.get(0).getRegistrationId()).isEqualTo("oidc");
    assertThat(registrations.get(0).getClientId()).isEqualTo("flat-client");
  }

  @Test
  void shouldBuildTwoRegistrationsFromFlatPlusOneProvider() {
    final var auth = new AuthenticationConfiguration();
    final var flat = explicitEndpoints("flat-client", "https://flat.example.com");
    flat.setRegistrationId("oidc");
    auth.setOidc(flat);
    auth.getProviders()
        .getOidc()
        .put("foo", explicitEndpoints("foo-client", "https://foo.example.com"));

    final var registrations = factory.create(auth);

    assertThat(registrations).hasSize(2);
    assertThat(registrations.stream().map(r -> r.getRegistrationId()))
        .containsExactly("oidc", "foo");
    assertThat(registrations.stream().map(r -> r.getClientId()))
        .containsExactly("flat-client", "foo-client");
  }

  @Test
  void shouldLetProviderOverwriteFlatWhenRegistrationIdCollides() {
    final var auth = new AuthenticationConfiguration();
    final var flat = explicitEndpoints("flat-client", "https://flat.example.com");
    flat.setRegistrationId("oidc");
    auth.setOidc(flat);
    // provider key "oidc" collides with the flat registrationId
    auth.getProviders()
        .getOidc()
        .put("oidc", explicitEndpoints("provider-client", "https://provider.example.com"));

    final var registrations = factory.create(auth);

    assertThat(registrations).hasSize(1);
    assertThat(registrations.get(0).getRegistrationId()).isEqualTo("oidc");
    assertThat(registrations.get(0).getClientId()).isEqualTo("provider-client");
  }

  @Test
  void shouldSkipFlatBlockWhenClientIdIsAbsent() {
    final var auth = new AuthenticationConfiguration();
    // flat has no clientId → should be ignored
    auth.getProviders()
        .getOidc()
        .put("bar", explicitEndpoints("bar-client", "https://bar.example.com"));

    final var registrations = factory.create(auth);

    assertThat(registrations).hasSize(1);
    assertThat(registrations.get(0).getRegistrationId()).isEqualTo("bar");
  }

  // ---------------------------------------------------------------------------
  // flatten(AuthenticationConfiguration)
  // ---------------------------------------------------------------------------

  @Test
  void shouldReturnSingleFlattenedEntryForFlatWithClientId() {
    final var auth = new AuthenticationConfiguration();
    final var flat = explicitEndpoints("flat-client", "https://flat.example.com");
    flat.setRegistrationId("oidc");
    auth.setOidc(flat);

    final var map = factory.flatten(auth);

    assertThat(map).containsOnlyKeys("oidc");
    assertThat(map.get("oidc").getClientId()).isEqualTo("flat-client");
  }

  @Test
  void shouldLetProviderOverwriteFlatInFlattenedMapOnCollision() {
    final var auth = new AuthenticationConfiguration();
    final var flat = explicitEndpoints("flat-client", "https://flat.example.com");
    flat.setRegistrationId("oidc");
    auth.setOidc(flat);
    auth.getProviders()
        .getOidc()
        .put("oidc", explicitEndpoints("provider-client", "https://provider.example.com"));

    final var map = factory.flatten(auth);

    assertThat(map).containsOnlyKeys("oidc");
    assertThat(map.get("oidc").getClientId()).isEqualTo("provider-client");
  }

  @Test
  void shouldFailFastWhenAuthenticationIsNull() {
    assertThatThrownBy(() -> factory.flatten(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessageContaining("authentication");
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  /** Creates an {@link OidcConfiguration} with explicit endpoints — no issuer-uri discovery. */
  private static OidcConfiguration explicitEndpoints(final String clientId, final String base) {
    return OidcConfiguration.builder()
        .clientId(clientId)
        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
        .authorizationUri(base + "/auth")
        .tokenUri(base + "/token")
        .jwkSetUri(base + "/jwks")
        .build();
  }
}
