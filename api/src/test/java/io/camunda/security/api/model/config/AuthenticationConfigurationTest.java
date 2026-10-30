/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class AuthenticationConfigurationTest {

  private static final String KEYCLOAK = "https://keycloak.example.com/realms/camunda";
  private static final String PARTNER = "https://partner.example.com";

  @Test
  void shouldEnableCamundaGroupsAndUsersInBasicAuth() {
    // given:
    final var config = new AuthenticationConfiguration();
    config.setMethod(AuthenticationMethod.BASIC);

    // expect:
    assertThat(config.isCamundaUsersEnabled()).isTrue();
    assertThat(config.isCamundaGroupsEnabled()).isTrue();
    assertThat(config.isExternalGroupsEnabled()).isFalse();
  }

  @Test
  void shouldEnableOnlyCamundaGroupsInOIDCAuth() {
    // given:
    final var config = new AuthenticationConfiguration();
    config.setMethod(AuthenticationMethod.OIDC);

    // expect:
    assertThat(config.isCamundaUsersEnabled()).isFalse();
    assertThat(config.isCamundaGroupsEnabled()).isTrue();
  }

  @Test
  void shouldDisableCamundaGroupsAndUsersInOIDCAuthWithGroupsClaim() {
    // given:
    final var config = new AuthenticationConfiguration();
    config.setMethod(AuthenticationMethod.OIDC);
    config.getOidc().setGroupsClaim("groups");

    // expect:
    assertThat(config.isCamundaUsersEnabled()).isFalse();
    assertThat(config.isCamundaGroupsEnabled()).isFalse();
    assertThat(config.isExternalGroupsEnabled()).isTrue();
  }

  @Test
  void shouldEnableCamundaGroupsWhenOidcGroupsClaimIsNotConfigured() {
    // given:
    final var config = new AuthenticationConfiguration();
    config.setMethod(AuthenticationMethod.OIDC);
    config.setOidc(null);

    // expect: setOidc(null) is normalised to a fresh OidcConfiguration; with no groups claim
    // configured, Camunda-managed groups remain enabled.
    assertThat(config.getOidc()).isNotNull();
    assertThat(config.isCamundaUsersEnabled()).isFalse();
    assertThat(config.isCamundaGroupsEnabled()).isTrue();
  }

  @Test
  void shouldReadTheGroupsOfANamedProviderFromItsGroupsClaim() {
    // given - only a named provider, which has a groups claim
    final var config = oidc();
    config.getProviders().getOidc().put("keycloak", provider(KEYCLOAK, "groups"));

    // expect
    assertThat(config.isCamundaGroupsEnabled()).isFalse();
    assertThat(config.isExternalGroupsEnabled()).isTrue();
    assertThat(config.getGroupsClaim(KEYCLOAK)).isEqualTo("groups");
  }

  @Test
  void shouldUseBothKindsOfGroupsWhenOnlySomeProvidersHaveAGroupsClaim() {
    // given - one provider with a groups claim and one without
    final var config = oidc();
    config.getProviders().getOidc().put("keycloak", provider(KEYCLOAK, "groups"));
    config.getProviders().getOidc().put("partner", provider(PARTNER, null));

    // expect
    assertThat(config.isCamundaGroupsEnabled()).isTrue();
    assertThat(config.isExternalGroupsEnabled()).isTrue();
    assertThat(config.getGroupsClaim(KEYCLOAK)).isEqualTo("groups");
    assertThat(config.getGroupsClaim(PARTNER)).isNull();
  }

  @Test
  void shouldCountTheOidcBlockAsAProviderWhenItHasAClientId() {
    // given - the oidc block is a provider without a groups claim, beside one with a groups claim
    final var config = oidc();
    config.getOidc().setClientId("partner-client");
    config.getOidc().setIssuerUri(PARTNER);
    config.getProviders().getOidc().put("keycloak", provider(KEYCLOAK, "groups"));

    // expect
    assertThat(config.isCamundaGroupsEnabled()).isTrue();
    assertThat(config.isExternalGroupsEnabled()).isTrue();
    assertThat(config.getGroupsClaim(PARTNER)).isNull();
  }

  @Test
  void shouldUseTheGroupsClaimOfTheOidcBlockForAProviderWithoutOne() {
    // given - the oidc block sets the groups claim for every provider
    final var config = oidc();
    config.getOidc().setGroupsClaim("roles");
    config.getProviders().getOidc().put("keycloak", provider(KEYCLOAK, "groups"));
    config.getProviders().getOidc().put("partner", provider(PARTNER, null));

    // expect
    assertThat(config.isCamundaGroupsEnabled()).isFalse();
    assertThat(config.isExternalGroupsEnabled()).isTrue();
    assertThat(config.getGroupsClaim(KEYCLOAK)).isEqualTo("groups");
    assertThat(config.getGroupsClaim(PARTNER)).isEqualTo("roles");
  }

  @Test
  void shouldReadTheGroupsClaimOfTheFirstProviderOfAnIssuer() {
    // given - two providers declare the same issuer
    final var config = oidc();
    config.getProviders().getOidc().put("first", provider(KEYCLOAK, "groups"));
    config.getProviders().getOidc().put("second", provider(KEYCLOAK, "roles"));

    // expect
    assertThat(config.getGroupsClaim(KEYCLOAK)).isEqualTo("groups");
  }

  @ParameterizedTest
  @ValueSource(strings = {KEYCLOAK, KEYCLOAK + "/"})
  void shouldReadTheGroupsClaimOfAProviderWhoseIssuerUriDiffersByATrailingSlash(
      final String tokenIssuer) {
    // given - the provider's issuer-uri has a trailing slash, its tokens may not (#61896)
    final var config = oidc();
    config.getProviders().getOidc().put("keycloak", provider(KEYCLOAK + "/", "groups"));

    // expect
    assertThat(config.getGroupsClaim(tokenIssuer)).isEqualTo("groups");
  }

  @Test
  void shouldGiveBothFormsOfAnIssuerToTheSlashFormDeclaredFirst() {
    // given - both forms of one issuer, each with its own groups claim
    final var config = oidc();
    config.getProviders().getOidc().put("slash", provider(KEYCLOAK + "/", "groups"));
    config.getProviders().getOidc().put("plain", provider(KEYCLOAK, "roles"));

    // expect - one issuer, owned by the provider declared first, which verifies its tokens
    assertThat(config.getGroupsClaim(KEYCLOAK)).isEqualTo("groups");
    assertThat(config.getGroupsClaim(KEYCLOAK + "/")).isEqualTo("groups");
  }

  @Test
  void shouldGiveBothFormsOfAnIssuerToThePlainFormDeclaredFirst() {
    // given
    final var config = oidc();
    config.getProviders().getOidc().put("plain", provider(KEYCLOAK, "roles"));
    config.getProviders().getOidc().put("slash", provider(KEYCLOAK + "/", "groups"));

    // expect
    assertThat(config.getGroupsClaim(KEYCLOAK)).isEqualTo("roles");
    assertThat(config.getGroupsClaim(KEYCLOAK + "/")).isEqualTo("roles");
  }

  @ParameterizedTest
  @CsvSource({
    KEYCLOAK + "," + KEYCLOAK,
    KEYCLOAK + "/," + KEYCLOAK,
    KEYCLOAK + "," + KEYCLOAK + "/"
  })
  void shouldCountEveryRegistrationOfAnIssuerForTheGroupsModes(
      final String ownerIssuerUri, final String secondIssuerUri) {
    // given - two registrations of one issuer; only the second has a groups claim
    final var config = oidc();
    config.getProviders().getOidc().put("owner", provider(ownerIssuerUri, null));
    config.getProviders().getOidc().put("second", provider(secondIssuerUri, "groups"));

    // expect - a user can log in through either registration in the browser, so both modes apply
    assertThat(config.isCamundaGroupsEnabled()).isTrue();
    assertThat(config.isExternalGroupsEnabled()).isTrue();
    // a bearer token of the issuer is verified by the owner
    assertThat(config.getGroupsClaim(KEYCLOAK)).isNull();
    // a browser login uses the claim of the registration the user picked
    assertThat(config.getGroupsClaimOfRegistration("owner")).isNull();
    assertThat(config.getGroupsClaimOfRegistration("second")).isEqualTo("groups");
  }

  @Test
  void shouldReadTheGroupsClaimOfTheRegistrationOfABrowserLogin() {
    // given
    final var config = oidc();
    config.getProviders().getOidc().put("keycloak", provider(KEYCLOAK, "groups"));
    config.getProviders().getOidc().put("partner", provider(PARTNER, null));

    // expect
    assertThat(config.getGroupsClaimOfRegistration("keycloak")).isEqualTo("groups");
    assertThat(config.getGroupsClaimOfRegistration("partner")).isNull();
  }

  @Test
  void shouldUseTheGroupsClaimOfTheOidcBlockForARegistrationWithoutOne() {
    // given
    final var config = oidc();
    config.getOidc().setGroupsClaim("roles");
    config.getProviders().getOidc().put("keycloak", provider(KEYCLOAK, null));

    // expect - also for a registration the configuration does not know
    assertThat(config.getGroupsClaimOfRegistration("keycloak")).isEqualTo("roles");
    assertThat(config.getGroupsClaimOfRegistration("unknown")).isEqualTo("roles");
    assertThat(config.getGroupsClaimOfRegistration(null)).isEqualTo("roles");
  }

  @Test
  void shouldReadTheGroupsClaimOfTheOidcBlockRegistration() {
    // given - the oidc block is a registration of its own
    final var config = oidc();
    config.getOidc().setClientId("flat-client");
    config.getOidc().setIssuerUri(KEYCLOAK);
    config.getOidc().setGroupsClaim("groups");
    config.getProviders().getOidc().put("partner", provider(PARTNER, null));

    // expect
    assertThat(config.getGroupsClaimOfRegistration(OidcConfiguration.DEFAULT_REGISTRATION_ID))
        .isEqualTo("groups");
  }

  @Test
  void shouldLetANamedProviderReplaceTheOidcBlockWithTheSameRegistrationId() {
    // given - the oidc block, without a groups claim, and a named provider with its registration
    // ID, which replaces it
    final var config = oidc();
    config.getOidc().setClientId("flat-client");
    config.getOidc().setIssuerUri(KEYCLOAK);
    config
        .getProviders()
        .getOidc()
        .put(OidcConfiguration.DEFAULT_REGISTRATION_ID, provider(KEYCLOAK, "groups"));

    // expect - only the named provider is active
    assertThat(config.isCamundaGroupsEnabled()).isFalse();
    assertThat(config.isExternalGroupsEnabled()).isTrue();
    assertThat(config.getGroupsClaim(KEYCLOAK)).isEqualTo("groups");
  }

  @Test
  void shouldLeaveOutTheOidcBlockWhenItsRegistrationIdIsBlank() {
    // given - the oidc block, without a groups claim, has a blank registration ID, which the token
    // decoders leave out, and a named provider of the same issuer has a groups claim
    final var config = oidc();
    config.getOidc().setClientId("flat-client");
    config.getOidc().setIssuerUri(KEYCLOAK);
    config.getOidc().setRegistrationId("");
    config.getProviders().getOidc().put("keycloak", provider(KEYCLOAK, "groups"));

    // expect - only the named provider is active
    assertThat(config.isCamundaGroupsEnabled()).isFalse();
    assertThat(config.isExternalGroupsEnabled()).isTrue();
    assertThat(config.getGroupsClaim(KEYCLOAK)).isEqualTo("groups");
  }

  @Test
  void shouldLeaveOutANamedProviderWithABlankRegistrationId() {
    // given - a named provider without a groups claim under a blank registration ID
    final var config = oidc();
    config.getProviders().getOidc().put(" ", provider(PARTNER, null));
    config.getProviders().getOidc().put("keycloak", provider(KEYCLOAK, "groups"));

    // expect
    assertThat(config.isCamundaGroupsEnabled()).isFalse();
    assertThat(config.isExternalGroupsEnabled()).isTrue();
  }

  @Test
  void shouldUseTheGroupsClaimOfTheOidcBlockForATokenOfNoKnownIssuer() {
    // given - several providers, so a token is matched to one by its issuer
    final var config = oidc();
    config.getOidc().setGroupsClaim("roles");
    config.getProviders().getOidc().put("keycloak", provider(KEYCLOAK, "groups"));
    config.getProviders().getOidc().put("partner", provider(PARTNER, "groups"));

    // expect
    assertThat(config.getGroupsClaim("https://unknown.example.com")).isEqualTo("roles");
    assertThat(config.getGroupsClaim(null)).isEqualTo("roles");
  }

  @Test
  void shouldReadTheGroupsClaimOfTheOnlyProviderForATokenOfAnyIssuer() {
    // given - a single provider without an issuer-uri; it verifies every token
    final var config = oidc();
    config.getProviders().getOidc().put("keycloak", provider(null, "groups"));

    // expect - the modes and the claim agree, so the external groups are read
    assertThat(config.isExternalGroupsEnabled()).isTrue();
    assertThat(config.getGroupsClaim(KEYCLOAK)).isEqualTo("groups");
    assertThat(config.getGroupsClaim(null)).isEqualTo("groups");
  }

  @Test
  void shouldReadTheGroupsClaimOfTheOnlyProviderForATokenOfAnotherIssuer() {
    // given - a single provider whose issuer-uri differs from the token's iss
    final var config = oidc();
    config.getProviders().getOidc().put("keycloak", provider(KEYCLOAK, "groups"));

    // expect
    assertThat(config.getGroupsClaim(PARTNER)).isEqualTo("groups");
  }

  @Test
  void shouldNotReadGroupsFromAClaimWithoutOidc() {
    // given - a groups claim is configured, but the method is basic
    final var config = new AuthenticationConfiguration();
    config.setMethod(AuthenticationMethod.BASIC);
    config.getOidc().setGroupsClaim("groups");

    // expect
    assertThat(config.isCamundaGroupsEnabled()).isTrue();
    assertThat(config.isExternalGroupsEnabled()).isFalse();
    assertThat(config.getGroupsClaim(null)).isNull();
    assertThat(config.getGroupsClaimOfRegistration(OidcConfiguration.DEFAULT_REGISTRATION_ID))
        .isNull();
  }

  private static AuthenticationConfiguration oidc() {
    final var config = new AuthenticationConfiguration();
    config.setMethod(AuthenticationMethod.OIDC);
    return config;
  }

  private static OidcConfiguration provider(final String issuerUri, final String groupsClaim) {
    final var provider = new OidcConfiguration();
    provider.setClientId("client");
    provider.setIssuerUri(issuerUri);
    if (groupsClaim != null) {
      provider.setGroupsClaim(groupsClaim);
    }
    return provider;
  }
}
