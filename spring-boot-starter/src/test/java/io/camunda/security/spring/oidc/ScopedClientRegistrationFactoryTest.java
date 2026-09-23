/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.REDIRECT_URI;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import jakarta.servlet.http.HttpServletRequest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.UnaryOperator;
import java.util.stream.Stream;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.web.firewall.RequestRejectedException;
import org.springframework.security.web.firewall.StrictHttpFirewall;

/**
 * Unit tests for {@link ScopedClientRegistrationFactory}: provider-map handling, redirect-uri
 * resolution and metadata merging. Every provider here uses explicit endpoint URIs, so no test in
 * this class touches the network. The per-issuer discovery cache is covered by {@link
 * ScopedClientRegistrationFactoryDiscoveryCacheTest}.
 */
class ScopedClientRegistrationFactoryTest {

  private ScopedClientRegistrationFactory factory;

  @BeforeEach
  void setUp() {
    factory = new ScopedClientRegistrationFactory();
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
  void shouldRejectConfiguredRedirectUriWithoutBaseUrlOrSchemePrefix() {
    // given a bare-path redirect-uri (no {baseUrl} template, no scheme://host)
    final var oidc =
        OidcConfiguration.builder()
            .clientId("my-client")
            .authorizationUri("https://idp.example.com/auth")
            .tokenUri("https://idp.example.com/token")
            .jwkSetUri("https://idp.example.com/jwks")
            .redirectUri("/api/authentication/callback")
            .build();

    // when / then: the redirect_uri sent to the IdP would be non-absolute and break login
    assertThatThrownBy(() -> factory.createFromProviderMap(Map.of("myid", oidc)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("myid")
        .hasMessageContaining("providers.oidc.myid.redirect-uri")
        .hasMessageContaining("{baseUrl}")
        .hasMessageContaining("/api/authentication/callback");
  }

  @Test
  void shouldDefaultRedirectUriToSsoCallbackWhenUnsetAndNoScopedPath() {
    // given a provider that configures no redirect-uri
    final var oidc =
        OidcConfiguration.builder()
            .clientId("my-client")
            .authorizationUri("https://idp.example.com/auth")
            .tokenUri("https://idp.example.com/token")
            .jwkSetUri("https://idp.example.com/jwks")
            .build();

    // when
    final var registrations = factory.createFromProviderMap(Map.of("myid", oidc));

    // then it falls back to the cluster redirection endpoint rather than a null redirect-uri
    assertThat(registrations).hasSize(1);
    assertThat(registrations.get(0).getRedirectUri()).isEqualTo("{baseUrl}" + REDIRECT_URI);
  }

  @Test
  void shouldPreferScopedPathOverDefaultWhenRedirectUriUnset() {
    // given a provider that configures no redirect-uri, built for a scoped chain
    final var oidc =
        OidcConfiguration.builder()
            .clientId("my-client")
            .authorizationUri("https://idp.example.com/auth")
            .tokenUri("https://idp.example.com/token")
            .jwkSetUri("https://idp.example.com/jwks")
            .build();

    // when
    final var registrations =
        factory.createFromProviderMap(Map.of("myid", oidc), "/physical-tenants/t1/sso-callback");

    // then the scoped path wins over the default
    assertThat(registrations).hasSize(1);
    assertThat(registrations.get(0).getRedirectUri())
        .isEqualTo("{baseUrl}/physical-tenants/t1/sso-callback");
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

  @Test
  void metadataCarriesUserInfoRequiredFlagWhenSet() {
    final var oidc = explicitEndpointsWith(b -> b.userInfoRequired(true));

    final var registrations = factory.createFromProviderMap(Map.of("myid", oidc));

    final var metadata = registrations.get(0).getProviderDetails().getConfigurationMetadata();
    assertThat(metadata)
        .containsEntry(FailSoftOidcUserService.USER_INFO_REQUIRED_METADATA_KEY, true);
  }

  @Test
  void metadataCarriesUserInfoRequiredFlagFalseByDefault() {
    final var oidc = explicitEndpoints("my-client", "https://idp.example.com");

    final var registrations = factory.createFromProviderMap(Map.of("myid", oidc));

    final var metadata = registrations.get(0).getProviderDetails().getConfigurationMetadata();
    assertThat(metadata)
        .containsEntry(FailSoftOidcUserService.USER_INFO_REQUIRED_METADATA_KEY, false);
  }

  @Test
  void rejectsUserInfoRequiredWithoutUserInfoEnabled() {
    final var oidc = explicitEndpointsWith(b -> b.userInfoRequired(true).userInfoEnabled(false));

    assertThatThrownBy(() -> factory.createFromProviderMap(Map.of("myid", oidc)))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("user-info-required")
        .hasMessageContaining("user-info-enabled");
  }

  // ---------------------------------------------------------------------------
  // userInfoUri / userNameAttributeName
  // ---------------------------------------------------------------------------

  @Test
  void shouldSetUserNameAttributeNameToSubWhenUserInfoUriConfiguredWithoutIssuer() {
    // given a manual-endpoint provider that also configures a UserInfo endpoint
    final var oidc =
        OidcConfiguration.builder()
            .clientId("my-client")
            .authorizationUri("https://idp.example.com/auth")
            .tokenUri("https://idp.example.com/token")
            .jwkSetUri("https://idp.example.com/jwks")
            .userInfoUri("https://idp.example.com/userinfo")
            .build();

    // when
    final var registrations = factory.createFromProviderMap(Map.of("myid", oidc));

    // then DefaultOAuth2UserService needs this set, or every login fails with
    // missing_user_name_attribute as soon as a UserInfo endpoint is configured
    final var userInfoEndpoint = registrations.get(0).getProviderDetails().getUserInfoEndpoint();
    assertThat(userInfoEndpoint.getUri()).isEqualTo("https://idp.example.com/userinfo");
    assertThat(userInfoEndpoint.getUserNameAttributeName()).isEqualTo("sub");
  }

  @Test
  void shouldLeaveUserNameAttributeNameUnsetWhenUserInfoUriNotConfigured() {
    // given a manual-endpoint provider with no UserInfo endpoint at all
    final var oidc = explicitEndpoints("my-client", "https://idp.example.com");

    // when
    final var registrations = factory.createFromProviderMap(Map.of("myid", oidc));

    // then
    final var userInfoEndpoint = registrations.get(0).getProviderDetails().getUserInfoEndpoint();
    assertThat(userInfoEndpoint.getUri()).isNull();
    assertThat(userInfoEndpoint.getUserNameAttributeName()).isNull();
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

  @Test
  void shouldValidateAnIssuerBasedProviderWithoutContactingIt() {
    // given a provider whose issuer is not listening at all
    final var oidc =
        OidcConfiguration.builder()
            .clientId("my-client")
            .redirectUri("{baseUrl}/sso-callback")
            .issuerUri("http://127.0.0.1:1/realms/camunda")
            .build();

    // when / then the configuration is accepted without any discovery call
    assertThatNoException()
        .isThrownBy(() -> factory.validateWithoutNetwork(Map.of("oidc", oidc), null));
  }

  @Test
  void shouldRejectABlankRegistrationIdWithoutNetwork() {
    final var oidc = explicitEndpoints("my-client", "https://idp.example.com");

    assertThatThrownBy(() -> factory.validateWithoutNetwork(Map.of(" ", oidc), null))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("registrationId");
  }

  @Test
  void shouldRejectABlankClientIdWithoutNetwork() {
    // given a provider whose client-id is missing — ClientRegistration.Builder#build rejects it
    final var oidc =
        OidcConfiguration.builder()
            .redirectUri("{baseUrl}/sso-callback")
            .issuerUri("https://idp.example.com/realms/camunda")
            .build();

    // when / then the message names the properties to set, which the builder's own error does not
    assertThatThrownBy(() -> factory.validateWithoutNetwork(Map.of("oidc", oidc), null))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("client-id")
        .hasMessageContaining("providers.oidc.oidc.client-id");
  }

  @Test
  void shouldRejectMissingExplicitEndpointsWithoutNetwork() {
    final var oidc = OidcConfiguration.builder().clientId("my-client").build();

    assertThatThrownBy(() -> factory.validateWithoutNetwork(Map.of("oidc", oidc), null))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("issuer-uri");
  }

  @Test
  void shouldNameTheMalformedEndpointUrlOfAnIncompleteBlockWithoutNetwork() {
    // given a block whose one configured endpoint is malformed, leaving it incomplete as well
    final var oidc =
        OidcConfiguration.builder().clientId("my-client").authorizationUri("not a URL").build();

    // when / then the typo is named rather than hidden behind the completeness error, as on the
    // build path
    assertThatThrownBy(() -> factory.validateWithoutNetwork(Map.of("oidc", oidc), null))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("authorization-uri")
        .hasMessageContaining("not a URL");
  }

  @Test
  void shouldRejectAScopedRedirectUriPathWithoutLeadingSlashWithoutNetwork() {
    final var oidc = explicitEndpoints("my-client", "https://idp.example.com");

    assertThatThrownBy(
            () -> factory.validateWithoutNetwork(Map.of("oidc", oidc), "physical-tenants/t1"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void shouldRejectAConfiguredRedirectUriWithoutBaseUrlOrSchemeWithoutNetwork() {
    final var oidc = explicitEndpoints("my-client", "https://idp.example.com");
    oidc.setRedirectUri("sso-callback");

    assertThatThrownBy(() -> factory.validateWithoutNetwork(Map.of("oidc", oidc), null))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void shouldRejectAMalformedProviderBeforeContactingAnEarlierProvidersIssuer() {
    // given a first provider whose issuer is not listening at all, and a second one whose
    // redirect-uri could never be served
    final var providers = new LinkedHashMap<String, OidcConfiguration>();
    providers.put(
        "reachable-last",
        OidcConfiguration.builder()
            .clientId("my-client")
            .redirectUri("{baseUrl}/sso-callback")
            .issuerUri("http://127.0.0.1:1/realms/camunda")
            .build());
    providers.put("broken", explicitEndpointsWith(b -> b.redirectUri("{baseUrl}api/callback")));

    // when / then the deterministic error is reported rather than the discovery attempt the first
    // provider would make on the way to it
    assertThatThrownBy(() -> factory.createFromProviderMap(providers))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("broken")
        .hasMessageContaining("{baseUrl}api/callback");
  }

  @Test
  void shouldRejectABlankClientIdWhenBuildingARegistration() {
    // given the same missing client-id, now on the building path
    final var oidc =
        OidcConfiguration.builder()
            .redirectUri("{baseUrl}/sso-callback")
            .authorizationUri("https://idp.example.com/auth")
            .tokenUri("https://idp.example.com/token")
            .jwkSetUri("https://idp.example.com/jwks")
            .build();

    // when / then it fails with the actionable message rather than the builder's assertion
    assertThatThrownBy(() -> factory.createFromProviderMap(Map.of("oidc", oidc)))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("client-id");
  }

  @Test
  void shouldRejectAMalformedIssuerUriWithoutNetwork() {
    // given an issuer-uri that cannot be parsed as a URI at all
    final var oidc =
        OidcConfiguration.builder()
            .clientId("my-client")
            .redirectUri("{baseUrl}/sso-callback")
            .issuerUri("not a URI")
            .build();

    // when / then discovery could never be performed against it, and seeing that needs no network
    assertThatThrownBy(() -> factory.validateWithoutNetwork(Map.of("oidc", oidc), null))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("issuer-uri must be an absolute http(s) URL")
        .hasMessageContaining("not a URI");
  }

  @Test
  void shouldRejectAnIssuerUriWithoutASchemeWithoutNetwork() {
    final var oidc =
        OidcConfiguration.builder()
            .clientId("my-client")
            .redirectUri("{baseUrl}/sso-callback")
            .issuerUri("idp.example.com/realms/camunda")
            .build();

    assertThatThrownBy(() -> factory.validateWithoutNetwork(Map.of("oidc", oidc), null))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("issuer-uri must be an absolute http(s) URL");
  }

  @Test
  void shouldRejectANonHttpIssuerUriWithoutNetwork() {
    final var oidc =
        OidcConfiguration.builder()
            .clientId("my-client")
            .redirectUri("{baseUrl}/sso-callback")
            .issuerUri("ftp://idp.example.com/realms/camunda")
            .build();

    assertThatThrownBy(() -> factory.validateWithoutNetwork(Map.of("oidc", oidc), null))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("issuer-uri must be an absolute http(s) URL");
  }

  @Test
  void shouldRejectAMalformedIssuerUriWhenBuildingARegistration() {
    // given the same malformed issuer-uri, now on the building path
    final var oidc =
        OidcConfiguration.builder()
            .clientId("my-client")
            .redirectUri("{baseUrl}/sso-callback")
            .issuerUri("not a URI")
            .build();

    // when / then it fails before any discovery attempt
    assertThatThrownBy(() -> factory.createFromProviderMap(Map.of("oidc", oidc)))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("issuer-uri must be an absolute http(s) URL");
  }

  @Test
  void shouldAcceptAnIssuerUriWhoseSchemeIsUppercaseWithoutNetwork() {
    // given an issuer-uri whose scheme is spelled in uppercase, which URI syntax allows
    final var oidc =
        OidcConfiguration.builder()
            .clientId("my-client")
            .redirectUri("{baseUrl}/sso-callback")
            .issuerUri("HTTPS://idp.example.com/realms/camunda")
            .build();

    // when / then
    assertThatNoException()
        .isThrownBy(() -> factory.validateWithoutNetwork(Map.of("oidc", oidc), null));
  }

  @ParameterizedTest(name = "{0}")
  @ValueSource(strings = {"0", "65536", "99999"})
  void shouldRejectAnEndpointUrlNamingAPortOutsideTheTcpRangeWithoutNetwork(final String port) {
    // given a port no TCP connection can be opened to, which URI syntax still accepts
    final var oidc =
        explicitEndpointsWith(b -> b.jwkSetUri("https://idp.example.com:" + port + "/keys"));

    // when / then the typo fails at startup rather than on the first token validation
    assertThatThrownBy(() -> factory.validateWithoutNetwork(Map.of("oidc", oidc), null))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("jwk-set-uri must be an absolute http(s) URL")
        .hasMessageContaining("1-65535");
  }

  @Test
  void shouldAcceptAnEndpointUrlNamingTheHighestPortInTheTcpRangeWithoutNetwork() {
    // given the boundary value, which is usable
    final var oidc = explicitEndpointsWith(b -> b.jwkSetUri("https://idp.example.com:65535/keys"));

    // when / then
    assertThatNoException()
        .isThrownBy(() -> factory.validateWithoutNetwork(Map.of("oidc", oidc), null));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("providersWithOneMalformedEndpointUrl")
  void shouldRejectAMalformedEndpointUrlWithoutNetwork(
      final String property, final OidcConfiguration oidc) {
    // when / then every endpoint the application sends requests to is named in its own error
    assertThatThrownBy(() -> factory.validateWithoutNetwork(Map.of("oidc", oidc), null))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining(property + " must be an absolute http(s) URL")
        .hasMessageContaining("not a URL");
  }

  @Test
  void shouldBuildWithoutLoginRoutesGivenACallbackThisApplicationCouldNotServe() {
    // given a redirect-uri naming no callback path
    final var providers =
        Map.of("oidc", explicitEndpointsWith(b -> b.redirectUri("https://example.com")));

    // when a caller derives no redirection endpoint from it
    // then it is no reason to refuse to start, while a login path still rejects it
    assertThatNoException().isThrownBy(() -> factory.createWithoutLoginRoutes(providers));
    assertThatThrownBy(() -> factory.createFromProviderMap(providers))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("redirect-uri");
  }

  @Test
  void shouldBuildWithoutLoginRoutesGivenAnIdOnlyTheLoginRouteCouldNotAddress() {
    // given an id usable as a registration key but not as a path segment
    final var providers = Map.of("foo/bar", explicitEndpointsWith(b -> b));

    // when a caller never resolves /oauth2/authorization/<id>
    // then the id it can use is no reason to refuse to start, while a login path still rejects it
    assertThatNoException().isThrownBy(() -> factory.createWithoutLoginRoutes(providers));
    assertThatThrownBy(() -> factory.createFromProviderMap(providers))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("single path segment")
        // the id can come from either shape, so the message names both properties that set it
        .hasMessageContaining("camunda.security.authentication.oidc.registration-id")
        .hasMessageContaining("camunda.security.authentication.providers.oidc.<id>");
  }

  @Test
  void shouldRejectABlankIdEvenWithoutLoginRoutes() {
    // given no registration key at all, which every caller needs
    final var providers = Map.of(" ", explicitEndpointsWith(b -> b));

    // when / then
    assertThatThrownBy(() -> factory.createWithoutLoginRoutes(providers))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("registrationId must be non-blank");
  }

  @Test
  void shouldRejectAMalformedEndpointUrlWhenBuildingWithoutLoginRoutes() {
    // given a value token validation itself uses
    final var providers = Map.of("oidc", explicitEndpointsWith(b -> b.jwkSetUri("not a URL")));

    // when / then
    assertThatThrownBy(() -> factory.createWithoutLoginRoutes(providers))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("jwk-set-uri");
  }

  @Test
  void shouldBuildWithoutLoginRoutesGivenAnEndSessionEndpointOnlyLogoutWouldDereference() {
    // given a malformed end-session endpoint, whose only consumer is the webapp logout handler
    final var providers =
        Map.of("oidc", explicitEndpointsWith(b -> b.endSessionEndpointUri("not a URL")));

    // when a caller mounts no login chain, and therefore no logout handler
    // then the value it never dereferences is no reason to refuse to start, while a login path
    // still rejects it
    assertThatNoException().isThrownBy(() -> factory.createWithoutLoginRoutes(providers));
    assertThatThrownBy(() -> factory.createFromProviderMap(providers))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("end-session-endpoint-uri");
  }

  @Test
  void shouldIgnoreAMalformedUserInfoUriOfAProviderThatDisabledUserInfo() {
    // given a stale user-info-uri on a provider whose UserInfo lookup is switched off
    final var oidc = explicitEndpointsWith(b -> b.userInfoUri("not a URL").userInfoEnabled(false));

    // when / then the value the build path discards does not fail a deployment that works today
    assertThatNoException()
        .isThrownBy(() -> factory.validateWithoutNetwork(Map.of("oidc", oidc), null));
  }

  private static Stream<Arguments> providersWithOneMalformedEndpointUrl() {
    return Stream.of(
        arguments("authorization-uri", explicitEndpointsWith(b -> b.authorizationUri("not a URL"))),
        arguments("token-uri", explicitEndpointsWith(b -> b.tokenUri("not a URL"))),
        arguments("jwk-set-uri", explicitEndpointsWith(b -> b.jwkSetUri("not a URL"))),
        arguments("user-info-uri", explicitEndpointsWith(b -> b.userInfoUri("not a URL"))),
        arguments(
            "end-session-endpoint-uri",
            explicitEndpointsWith(b -> b.endSessionEndpointUri("not a URL"))),
        arguments(
            "additional-jwk-set-uris",
            explicitEndpointsWith(b -> b.additionalJwkSetUris(List.of("not a URL")))));
  }

  @ParameterizedTest(name = "{0}")
  @ValueSource(
      strings = {
        "/physical-tenants/t%2fa/sso-callback",
        "/physical-tenants/t;a/sso-callback",
        "/physical-tenants//sso-callback",
        "/physical-tenants/./sso-callback",
        "/physical-tenants/../sso-callback",
        "/physical-tenants/t%zz/sso-callback"
      })
  void shouldRejectAScopedRedirectPathTheDeploymentCannotServe(final String scopedPath) {
    // given a scope whose base path is valid per BasePathSyntax but yields a callback no chain is
    // asked about: a form the default firewall blocks, a non-normalized segment, or no URL at all
    final var oidc = explicitEndpoints("my-client", "https://idp.example.com");

    // when / then the scoped chain would send the IdP a callback no chain is ever asked about
    assertThatThrownBy(() -> factory.validateWithoutNetwork(Map.of("oidc", oidc), scopedPath))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining(scopedPath);
  }

  @Test
  void shouldRejectAScopedRedirectPathWhoseEncodingTheEndpointAndTheCallbackDisagreeOn() {
    // given a scope whose base path carries an encoded space — one the default firewall allows
    final var scopedPath = "/physical-tenants/t%20a/sso-callback";
    final var firewall = new StrictHttpFirewall();
    final var request = new MockHttpServletRequest("GET", scopedPath);
    assertThatNoException().isThrownBy(() -> firewall.getFirewalledRequest(request));

    // when / then it is still unusable, for the other reason: the endpoint pattern keeps the escape
    // while the expanded callback path decodes it, so the two never match and the IdP would send
    // the browser to a callback the scoped chain's redirection endpoint does not serve
    final var oidc = explicitEndpoints("my-client", "https://idp.example.com");
    assertThatThrownBy(() -> factory.validateWithoutNetwork(Map.of("oidc", oidc), scopedPath))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining(scopedPath);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {"foo?bar", "foo#bar", "foo/bar", "foo bar", "foo%2fbar", "foo;bar", ".", ".."})
  void shouldRejectARegistrationIdThatDoesNotAddressItsOwnLoginRoute(final String registrationId) {
    // given a provider under an id that does not survive /oauth2/authorization/<id> as one segment
    final var oidc = explicitEndpointsWith(b -> b);

    // when / then it is rejected rather than naming a provider no browser can reach
    assertThatThrownBy(() -> factory.validateWithoutNetwork(Map.of(registrationId, oidc), null))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining(registrationId);
  }

  @ParameterizedTest
  @ValueSource(strings = {"keycloak", "my-idp", "idp_2", "foo.bar", "foo~bar", "foo!bar"})
  void shouldAcceptARegistrationIdThatAddressesItsOwnLoginRoute(final String registrationId) {
    // given a provider under an id that is a single path segment
    final var oidc = explicitEndpointsWith(b -> b);

    // when / then the id is accepted
    assertThatNoException()
        .isThrownBy(() -> factory.validateWithoutNetwork(Map.of(registrationId, oidc), null));
  }

  @Test
  void shouldAcceptARedirectUriTemplatingAServableRegistrationId() {
    // given the same template under an ordinary id
    final var oidc =
        explicitEndpointsWith(b -> b.redirectUri("{baseUrl}/sso-callback/{registrationId}"));

    // when / then the id expands to a callback the deployment can serve
    assertThatNoException()
        .isThrownBy(() -> factory.validateWithoutNetwork(Map.of("keycloak", oidc), null));
  }

  @Test
  void shouldRejectAScopeThatIsASpaceSeparatedListWithoutNetwork() {
    // given the scopes written as one space-separated entry instead of one entry each
    final var oidc = explicitEndpointsWith(b -> b.scope(List.of("openid profile email")));

    // when / then the authorization request Spring would refuse to build fails at startup
    assertThatThrownBy(() -> factory.validateWithoutNetwork(Map.of("provider-b", oidc), null))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("provider-b")
        .hasMessageContaining("openid profile email")
        .hasMessageContaining("providers.oidc.provider-b.scope");
  }

  @Test
  void shouldStartAndBuildAProviderThatConfiguresNoScope() {
    // given a provider whose scope list was unset rather than filled
    final var providers = Map.of("oidc", explicitEndpointsWith(b -> b.scope(null)));

    // when / then ClientRegistration.Builder#scope ignores a null list, so the registration builds
    // with no scope and startup has nothing to reject
    assertThatNoException().isThrownBy(() -> factory.validateWithoutNetwork(providers, null));
    assertThat(factory.createFromProviderMap(providers).getFirst().getScopes()).isEmpty();
  }

  @Test
  void shouldRejectABlankClientAuthenticationMethodWithoutNetwork() {
    // given a provider whose client-authentication-method was blanked out
    final var oidc = explicitEndpointsWith(b -> b.clientAuthenticationMethod(""));

    // when / then the value the registration builder would reject is named at startup instead
    assertThatThrownBy(() -> factory.validateWithoutNetwork(Map.of("provider-b", oidc), null))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("provider-b")
        .hasMessageContaining("client-authentication-method");
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("io.camunda.security.spring.oidc.RedirectUriSamples#unusable")
  void shouldRejectARedirectUriThatIsNotAUsableCallbackUrlWithoutNetwork(final String redirectUri) {
    final var oidc = explicitEndpointsWith(b -> b.redirectUri(redirectUri));

    // when / then the IdP would receive a redirect_uri it cannot redirect to, and the provider
    // whose value that is has to be named where several are configured
    assertThatThrownBy(() -> factory.validateWithoutNetwork(Map.of("provider-b", oidc), null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("provider-b")
        .hasMessageContaining("providers.oidc.provider-b.redirect-uri")
        .hasMessageContaining(UrlRedaction.redact(redirectUri));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("io.camunda.security.spring.oidc.RedirectUriSamples#unusable")
  void shouldRejectAFlatRedirectUriTheWebappChainCannotMount(final String redirectUri) {
    // given a flat redirect-uri that contributes no registration of its own — no client-id beside
    // it — but still decides where the unscoped chain mounts its redirection endpoint

    // when / then it is held to the same contract, instead of the chain quietly mounting the
    // default callback while the IdP redirects elsewhere
    assertThatThrownBy(() -> factory.validateRedirectionEndpointSource(redirectUri, "oidc"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("camunda.security.authentication.oidc.redirect-uri")
        .hasMessageContaining(UrlRedaction.redact(redirectUri));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("io.camunda.security.spring.oidc.RedirectUriSamples#usable")
  void shouldAcceptAFlatRedirectUriTheWebappChainCanMount(final String redirectUri) {
    // when / then the value the chain mounts its endpoint from names a callback it can serve
    assertThatNoException()
        .isThrownBy(() -> factory.validateRedirectionEndpointSource(redirectUri, "oidc"));
  }

  @Test
  void shouldValidateAFlatRedirectUriWhoseBlockHasNoRegistrationIdOfItsOwn() {
    // given a redirect-only flat block: it moves the mounted endpoint but contributes no
    // registration, so it carries no registration id

    // when / then the template is judged under the default registration id rather than failing on
    // the absent one
    assertThatNoException()
        .isThrownBy(
            () ->
                factory.validateRedirectionEndpointSource(
                    "{baseUrl}/login/oauth2/code/{registrationId}", null));
    assertThatThrownBy(() -> factory.validateRedirectionEndpointSource("https://example.com", null))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void shouldAcceptAnUnsetFlatRedirectUri() {
    // when / then the default callback stays in place, which the chain mounts by default too
    assertThatNoException()
        .isThrownBy(
            () -> {
              factory.validateRedirectionEndpointSource(null, "oidc");
              factory.validateRedirectionEndpointSource("  ", "oidc");
            });
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("io.camunda.security.spring.oidc.RedirectUriSamples#usable")
  void shouldAcceptAnAbsoluteOrTemplatedRedirectUriWithoutNetwork(final String redirectUri) {
    final var oidc = explicitEndpointsWith(b -> b.redirectUri(redirectUri));

    // when / then a placeholder is only expanded per request, so it cannot be checked here
    assertThatNoException()
        .isThrownBy(() -> factory.validateWithoutNetwork(Map.of("oidc", oidc), null));
  }

  @ParameterizedTest(name = "{0}")
  @ValueSource(
      strings = {
        "/sso//callback",
        "/sso;callback",
        "/sso%3bcallback",
        "/sso%2fcallback",
        "/sso\\callback",
        "/sso%5ccallback",
        "/sso%25callback",
        "/sso%2ecallback",
        "/sso%00callback",
        "/sso%0acallback",
        "/sso%0dcallback",
        "/sso/./callback",
        "/sso/../callback"
      })
  void shouldPinThatTheDefaultFirewallRejectsTheCallbackPathsValidationRejects(
      final String callbackPath) {
    // given Spring Security's default firewall, the one a chain is wrapped in
    final var firewall = new StrictHttpFirewall();
    final var request = new MockHttpServletRequest("GET", callbackPath);

    // when / then the callback never reaches a chain, so rejecting the redirect-uri that produces
    // it at startup is not a rule of ours to keep current
    assertThatThrownBy(() -> firewall.getFirewalledRequest(request))
        .isInstanceOf(RequestRejectedException.class);
  }

  @ParameterizedTest(name = "{0}")
  @ValueSource(
      strings = {"/sso-callback", "/login/oauth2/code/oidc", "/orchestration/sso-callback"})
  void shouldPinThatTheDefaultFirewallPassesTheCallbackPathsValidationAccepts(
      final String callbackPath) {
    // given the same firewall and a callback an accepted redirect-uri expands to
    final var firewall = new StrictHttpFirewall();
    final var request = new MockHttpServletRequest("GET", callbackPath);

    // when / then accepting the value does not promise a shape the firewall blocks
    assertThatNoException().isThrownBy(() -> firewall.getFirewalledRequest(request));
  }

  @Test
  void shouldRejectARedirectUriThatIsTheDeploymentContextPathWithoutNetwork() {
    // given a deployment under a context path, and a redirect-uri pointing at its root
    final var contextPathFactory = new ScopedClientRegistrationFactory("/orchestration");
    final var oidc = explicitEndpointsWith(b -> b.redirectUri("https://example.com/orchestration"));

    // when / then the redirection endpoint would strip the whole path away and listen at the
    // default callback instead, while the IdP redirects the browser to the context root
    assertThatThrownBy(() -> contextPathFactory.validateWithoutNetwork(Map.of("oidc", oidc), null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("https://example.com/orchestration");
  }

  @Test
  void shouldNormalizeATrailingSlashOnTheDeploymentContextPath() {
    // given a context path configured with a trailing slash, as the servlet never reports it
    final var contextPathFactory = new ScopedClientRegistrationFactory("/orchestration/");
    final var usable = explicitEndpointsWith(b -> b.redirectUri("{baseUrl}/sso-callback"));
    final var contextRoot =
        explicitEndpointsWith(b -> b.redirectUri("https://example.com/orchestration"));

    // when / then the slash does not make a usable template expand to an empty path segment, and
    // the context root is still rejected
    assertThatNoException()
        .isThrownBy(() -> contextPathFactory.validateWithoutNetwork(Map.of("oidc", usable), null));
    assertThatThrownBy(
            () -> contextPathFactory.validateWithoutNetwork(Map.of("oidc", contextRoot), null))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void shouldAcceptARedirectUriRepeatingTheContextPathBehindAPlaceholder() {
    // given a deployment under a context path and a {baseUrl} template whose own path repeats that
    // segment, so the IdP is handed /orchestration/orchestration/sso-callback — {baseUrl} expands
    // from request.getContextPath(), so the repeated segment is part of the callback
    final var contextPathFactory = new ScopedClientRegistrationFactory("/orchestration");
    final var oidc =
        explicitEndpointsWith(b -> b.redirectUri("{baseUrl}/orchestration/sso-callback"));

    // when / then the endpoint derived from the value matches that callback, so the value is not
    // refused for a context path the placeholder had already accounted for
    assertThatNoException()
        .isThrownBy(() -> contextPathFactory.validateWithoutNetwork(Map.of("oidc", oidc), null));
  }

  @Test
  void shouldAcceptARedirectUriUnderTheDeploymentContextPathWithoutNetwork() {
    // given a deployment under a context path, and a callback below it
    final var contextPathFactory = new ScopedClientRegistrationFactory("/orchestration");
    final var oidc =
        explicitEndpointsWith(b -> b.redirectUri("https://example.com/orchestration/sso-callback"));

    // when / then
    assertThatNoException()
        .isThrownBy(() -> contextPathFactory.validateWithoutNetwork(Map.of("oidc", oidc), null));
  }

  /**
   * Pins what the factory's sample request shapes stand in for against Spring's own resolver: a
   * renamed variable, a changed expansion or {@code basePort}/{@code basePath} losing their own
   * {@code :} and {@code /} fails here, instead of turning a working redirect-uri into a startup
   * failure or letting a broken one through.
   */
  @Test
  void shouldExpandRedirectUriPlaceholdersTheWaySpringsResolverDoes() {
    // given a request on a non-default port under a context path, and one without either
    final var contextPathRequest = authorizationRequestTo("https", "host", 8443, "/context");
    final var rootRequest = authorizationRequestTo("https", "host", 443, "");

    // when Spring expands templates naming every variable the factory supplies values for
    final var placeholders =
        "{baseScheme}://{baseHost}{basePort}{basePath}/{action}/{registrationId}";

    // then
    assertThat(expandWithSpring(placeholders, contextPathRequest))
        .isEqualTo("https://host:8443/context/login/registration");
    assertThat(expandWithSpring("{baseUrl}/sso-callback", contextPathRequest))
        .isEqualTo("https://host:8443/context/sso-callback");
    assertThat(expandWithSpring(placeholders, rootRequest))
        .isEqualTo("https://host/login/registration");
    assertThat(expandWithSpring("{baseUrl}/sso-callback", rootRequest))
        .isEqualTo("https://host/sso-callback");
  }

  @Test
  void shouldFailSpringsResolverOnAPlaceholderItDoesNotExpand() {
    // given
    final var request = authorizationRequestTo("https", "host", 443, "");

    // when / then rejecting an unknown placeholder at startup matches what the resolver would do
    // with it on the first login request
    assertThatThrownBy(() -> expandWithSpring("{typo}/sso-callback", request))
        .isInstanceOf(IllegalArgumentException.class);
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  private static MockHttpServletRequest authorizationRequestTo(
      final String scheme, final String host, final int port, final String contextPath) {
    final var request =
        new MockHttpServletRequest("GET", contextPath + "/oauth2/authorization/registration");
    request.setScheme(scheme);
    request.setServerName(host);
    request.setServerPort(port);
    request.setContextPath(contextPath);
    return request;
  }

  /** Expands a redirect-uri template the way a login request would, using Spring's own resolver. */
  private static String expandWithSpring(
      final String redirectUri, final HttpServletRequest request) {
    final var registration =
        ClientRegistration.withRegistrationId("registration")
            .clientId("my-client")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationUri("https://idp.example.com/auth")
            .tokenUri("https://idp.example.com/token")
            .redirectUri(redirectUri)
            .build();
    final var resolver =
        new DefaultOAuth2AuthorizationRequestResolver(
            new InMemoryClientRegistrationRepository(registration), "/oauth2/authorization");
    return resolver.resolve(request).getRedirectUri();
  }

  /**
   * Creates an {@link OidcConfiguration} with explicit endpoints, letting the caller replace one of
   * them.
   */
  // post-logout-redirect-uri (ADR-0026)
  //
  // Validated here, with every other OIDC provider-block check, rather than where the value is
  // consumed. ScopedWebappSecurityChainBuilder only composes an already-valid value against its
  // chain.

  private void validatePostLogoutRedirectUri(final String configured) {
    factory.validateWithoutNetwork(
        Map.of("oidc", explicitEndpointsWith(b -> b.postLogoutRedirectUri(configured))), null);
  }

  private org.assertj.core.api.AbstractThrowableAssert<?, ? extends Throwable>
      assertPostLogoutRedirectUriRejected(final String configured) {
    return assertThatThrownBy(() -> validatePostLogoutRedirectUri(configured))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("post-logout-redirect-uri");
  }

  @Test
  void shouldAcceptAnUnsetPostLogoutRedirectUri() {
    assertThatNoException().isThrownBy(() -> validatePostLogoutRedirectUri(null));
  }

  /**
   * {@code {basePort}} carries its own {@code ':'}, so {@code {baseHost}{basePort}} is the
   * canonical way to write a host with an optional port — rejecting it would fail a working
   * deployment at startup, which is worse than the false accepts this validation exists to stop.
   */
  @ValueSource(
      strings = {
        "/goodbye",
        "{baseUrl}/post-logout",
        "https://accounts.example.com/logged-out",
        "{baseScheme}://{baseHost}/logged-out",
        "{baseScheme}://accounts.example.com/logged-out",
        "https://{baseHost}{basePort}/logged-out",
        "https://{baseHost}:8080/logged-out",
        "https://accounts.example.com:8443/logged-out",
        "{baseUrl}",
        // {basePath} brings its own '/' and {basePort} its own ':', so both may trail the host
        // without ending the authority — rejecting these would fail a context-path deployment.
        "https://{baseHost}{basePort}{basePath}/logged-out",
        "https://accounts.example.com{basePath}/logged-out",
        "{baseScheme}://{baseHost}{basePort}{basePath}/logged-out"
      })
  @ParameterizedTest
  void shouldAcceptAUsablePostLogoutRedirectUri(final String configured) {
    assertThatNoException().isThrownBy(() -> validatePostLogoutRedirectUri(configured));
  }

  /**
   * A {@code "://"} anywhere in the string is not a scheme. {@code
   * {basePath}https://accounts.example.com/logout} contains one, uses only supported placeholders,
   * and expands to {@code /prefix...https://...} — still relative.
   */
  @Test
  void shouldRejectAPostLogoutRedirectUriWhoseSchemeIsNotAtTheStart() {
    assertPostLogoutRedirectUriRejected("{basePath}https://accounts.example.com/logout")
        .hasMessageContaining("must be an absolute URL");
  }

  /** A placeholder in the port position expands to something no socket can use. */
  @Test
  void shouldRejectAPostLogoutRedirectUriWithAPlaceholderInThePortPosition() {
    assertPostLogoutRedirectUriRejected("https://accounts.example.com:{registrationId}/logout")
        .hasMessageContaining("must be an absolute URL");
  }

  /** A literal port still has to be a port, matching what the other endpoint URLs enforce. */
  @Test
  void shouldRejectAPostLogoutRedirectUriWithAPortOutsideTheTcpRange() {
    assertPostLogoutRedirectUriRejected("https://accounts.example.com:99999/logout")
        .hasMessageContaining("port");
  }

  /**
   * A templated host does not excuse the port beside it. The structural check can only see that the
   * port is digits; expanding the value is what shows the number is out of range.
   */
  @Test
  void shouldRejectAPostLogoutRedirectUriWithATemplatedHostAndAnOutOfRangePort() {
    assertPostLogoutRedirectUriRejected("https://{baseHost}:99999/logout")
        .hasMessageContaining("must expand to an absolute http(s) URL");
  }

  /**
   * {@code basePort} brings its own {@code ':'}, so a literal one before it doubles up — {@code
   * https://accounts.example.com::8443/…} on a non-default port.
   *
   * <p>Caught by the authority rule rather than by expansion: peeling a trailing {@code {basePort}}
   * is what lets it legitimately follow a host, and the colon left behind is the giveaway that the
   * value supplied one too.
   */
  @Test
  void shouldRejectAPostLogoutRedirectUriWithALiteralColonBeforeBasePort() {
    assertPostLogoutRedirectUriRejected("https://accounts.example.com:{basePort}/logged-out")
        .hasMessageContaining("must be an absolute URL");
  }

  /**
   * {@code {baseUrl}} already carries scheme, host, port and context path, so anything but a path
   * after it duplicates a component — {@code https://host:8443:8080/logout} on a non-default port.
   * Expansion alone cannot catch this: on a default-port request the result still parses.
   */
  @Test
  void shouldRejectAPostLogoutRedirectUriThatAddsAPortAfterBaseUrl() {
    assertPostLogoutRedirectUriRejected("{baseUrl}:8080/logout")
        .hasMessageContaining("must continue with a path after {baseUrl}");
  }

  /**
   * The path form faces the same expansion check as the rest. It returns early from the
   * absolute-URL rules, which do not apply to it, and used to return from the method with it — so a
   * malformed escape reached Spring, prefixed with {@code {baseUrl}}, and failed at logout.
   */
  @ValueSource(strings = {"/goodbye/%zz", "/goodbye/{basePath}%zz"})
  @ParameterizedTest
  void shouldRejectAPostLogoutRedirectPathThatCannotExpand(final String configured) {
    assertPostLogoutRedirectUriRejected(configured)
        .hasMessageContaining("must expand to an absolute http(s) URL");
  }

  /**
   * Surrounding whitespace is trimmed before anything else looks at the value, and the trimmed
   * value is what both this check and the chain composition use — so an edge newline from a YAML
   * block scalar is hygiene, not a rejected control character. One in the middle is a different
   * matter.
   */
  @Test
  void shouldTrimSurroundingWhitespaceRatherThanRejectIt() {
    assertThatNoException()
        .isThrownBy(() -> validatePostLogoutRedirectUri("\n  https://accounts.example.com/x  \n"));
  }

  /**
   * A literal path is checked even when a placeholder sits further along it. Parsing only the
   * authority in that case would let a malformed escape through to logout.
   */
  @Test
  void shouldRejectAPostLogoutRedirectUriWithAMalformedEscapeInALiteralPath() {
    assertPostLogoutRedirectUriRejected("https://accounts.example.com/%zz/{basePath}")
        .hasMessageContaining("must expand to an absolute http(s) URL");
  }

  /**
   * A placeholder in the path must not excuse a malformed literal host. Skipping the parse for any
   * templated value was too coarse: the host here is literal, and wrong.
   */
  @ValueSource(
      strings = {"https://ex ample.com/{basePath}", "{baseScheme}://ex ample.com/logged-out"})
  @ParameterizedTest
  void shouldRejectAPostLogoutRedirectUriWithALiteralHostThatCannotParse(final String configured) {
    assertPostLogoutRedirectUriRejected(configured).hasMessageContaining("is not a valid URI");
  }

  /**
   * A relative value, whatever placeholders it uses. RP-Initiated Logout requires {@code
   * post_logout_redirect_uri} to be absolute, so the OP rejects the logout rather than the
   * deployment failing to start.
   *
   * <p>{@code https://{basePath}/goodbye} is the one worth spelling out: it carries a scheme and
   * every placeholder in it is supported, so only the host-position rule catches it — Spring
   * expands it to {@code https:///goodbye}.
   */
  @ValueSource(
      strings = {
        "goodbye",
        "{basePath}/goodbye",
        "{baseHost}/logged-out",
        "{registrationId}/goodbye",
        "https://{basePath}/goodbye",
        "https://{registrationId}/goodbye",
        "https://",
        "file:///logged-out"
      })
  @ParameterizedTest
  void shouldRejectAPostLogoutRedirectUriThatIsNotAbsolute(final String configured) {
    assertPostLogoutRedirectUriRejected(configured).hasMessageContaining("must be an absolute URL");
  }

  /**
   * Spring expands the template with a fixed variable map, so an unsupported name throws from
   * inside {@code buildAndExpand} on the logout request itself — a 500 on the one request a user
   * cannot usefully retry.
   */
  /**
   * Every property routed through {@code requireAbsoluteHttpUrl} quotes the value it rejects, so a
   * scheme-less one must be redacted there too — not only for post-logout.
   */
  @Test
  void shouldRedactCredentialsFromASchemelessEndpointUrl() {
    assertThatThrownBy(
            () ->
                factory.validateWithoutNetwork(
                    Map.of(
                        "oidc",
                        OidcConfiguration.builder()
                            .clientId("my-client")
                            .redirectUri("{baseUrl}/sso-callback")
                            .issuerUri("user:secret@idp.example.com/realm")
                            .build()),
                    null))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageNotContaining("secret")
        .hasMessageContaining("idp.example.com");
  }

  @Test
  void shouldRejectAPostLogoutRedirectUriWithAnUnsupportedTemplateVariable() {
    assertPostLogoutRedirectUriRejected("{baseUrl}/{tenantId}")
        .hasMessageContaining("unsupported template variable {tenantId}");
  }

  /**
   * The variable name reaches the message before the value is redacted, so a name that is not a
   * plausible identifier is reported generically rather than echoed — otherwise anything can be
   * written between the braces to get it into the log verbatim.
   */
  @Test
  void shouldNotEchoAnUnsupportedTemplateVariableThatCarriesCredentials() {
    assertPostLogoutRedirectUriRejected("{baseUrl}/{https://user:secret@host}")
        .hasMessageNotContaining("secret")
        .hasMessageContaining("an unsupported template variable")
        .hasMessageContaining("supported variables are");
  }

  /**
   * An unclosed brace is invisible to a closed-pair check, and {@code UriComponentsBuilder} does
   * not reject it either — it expands to a literal and ships to the IdP as-is.
   */
  @ValueSource(strings = {"{baseUrl}{tenantId", "{baseUrl"})
  @ParameterizedTest
  void shouldRejectAPostLogoutRedirectUriWithAnUnclosedBrace(final String configured) {
    assertPostLogoutRedirectUriRejected(configured).hasMessageContaining("unclosed '{'");
  }

  @Test
  void shouldRejectAPostLogoutRedirectUriWithAnUnmatchedClosingBrace() {
    assertPostLogoutRedirectUriRejected("https://accounts.example.com/a}")
        .hasMessageContaining("unmatched '}'");
  }

  /** A literal host reaches the URI parse, which is what catches a host that cannot be parsed. */
  @Test
  void shouldRejectAPostLogoutRedirectUriWithAnUnparseableHost() {
    assertPostLogoutRedirectUriRejected("https://ex ample.com/logout")
        .hasMessageContaining("is not a valid URI");
  }

  /** RP-Initiated Logout 1.0 §2 gives the parameter no fragment, for any of the accepted forms. */
  @ValueSource(strings = {"https://accounts.example.com/logged-out#section", "/goodbye#section"})
  @ParameterizedTest
  void shouldRejectAPostLogoutRedirectUriWithAFragment(final String configured) {
    assertPostLogoutRedirectUriRejected(configured).hasMessageContaining("must not contain");
  }

  /**
   * CR and LF would forge a line in the log this very message lands in; the other control
   * characters are simply unusable. Both are rejected by the same check.
   */
  @ValueSource(strings = {"https://accounts.example.com/x\r\nSet-Cookie: a=b", "/good\tbye"})
  @ParameterizedTest
  void shouldRejectAPostLogoutRedirectUriWithControlCharacters(final String configured) {
    assertPostLogoutRedirectUriRejected(configured)
        .hasMessageContaining("must not contain control characters");
  }

  /** And the message that reports one must not carry the control characters either. */
  @Test
  void shouldEscapeControlCharactersInTheRejectionMessage() {
    assertPostLogoutRedirectUriRejected("https://accounts.example.com/x\r\nINFO forged")
        .hasMessageNotContaining("\r")
        .hasMessageNotContaining("\n");
  }

  /**
   * The value is validated even when the redirect is switched off, so a typo surfaces at startup
   * rather than lying dormant until someone flips the flag back on.
   */
  @Test
  void shouldRejectAnUnusablePostLogoutRedirectUriEvenWhenTheRedirectIsDisabled() {
    assertThatThrownBy(
            () ->
                factory.validateWithoutNetwork(
                    Map.of(
                        "oidc",
                        explicitEndpointsWith(
                            b ->
                                b.postLogoutRedirectUri("{tenantId}/goodbye")
                                    .postLogoutRedirectEnabled(false))),
                    null))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("unsupported template variable {tenantId}");
  }

  /**
   * A rejected value reaches a startup exception that lands in application logs, so its credentials
   * and query must not travel with it. The host and path survive, which is what locates the typo.
   */
  @Test
  void shouldRedactCredentialsAndQueryFromARejectedPostLogoutRedirectUri() {
    assertPostLogoutRedirectUriRejected("https://user:secret@accounts.example.com/{tenantId}?t=abc")
        .hasMessageNotContaining("secret")
        .hasMessageNotContaining("t=abc")
        .hasMessageContaining("accounts.example.com");
  }

  private static OidcConfiguration explicitEndpointsWith(
      final UnaryOperator<OidcConfiguration.Builder> override) {
    return override
        .apply(
            OidcConfiguration.builder()
                .clientId("my-client")
                .redirectUri("{baseUrl}/sso-callback")
                .authorizationUri("https://idp.example.com/auth")
                .tokenUri("https://idp.example.com/token")
                .jwkSetUri("https://idp.example.com/jwks"))
        .build();
  }

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
