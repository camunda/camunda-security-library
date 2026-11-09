/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.hostdecoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;

import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.core.port.in.OidcProviderConfigurationPort;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.oidc.JWSKeySelectorFactory;
import io.camunda.security.spring.oidc.LazyClientRegistrationRepository;
import io.camunda.security.spring.oidc.OidcAccessTokenDecoderFactory;
import io.camunda.security.spring.oidc.OidcTestServer;
import io.camunda.security.spring.oidc.OidcWebappClientBeansConfiguration;
import io.camunda.security.spring.oidc.ScopedClientRegistrationFactory;
import io.camunda.security.spring.oidc.ScopedJwtDecoderFactory;
import io.camunda.security.spring.oidc.TokenValidatorFactory;
import io.camunda.security.spring.oidc.VerifiedJwt;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.JwtDecoder;

/**
 * A host can replace {@link OidcAccessTokenDecoderFactory} with a subclass, from its own package,
 * that wraps the decoder the public selection gives. The library's decoders must keep calling that
 * selection, so the host's wrapper still runs, and their tokens are still tagged with the claims of
 * the provider that verified them.
 */
@ExtendWith(MockitoExtension.class)
class HostDecoderFactoryOverrideTest {

  private static OidcTestServer server;

  @Mock private OidcProviderConfigurationPort oidcProviderConfigurationPort;

  private OidcConfiguration provider;
  private WrappingDecoderFactory factory;

  @BeforeAll
  static void startServer() throws Exception {
    server = OidcTestServer.startRsa("host-key");
  }

  @AfterAll
  static void stopServer() {
    server.stop();
  }

  @BeforeEach
  void setUp() {
    provider = server.oidcConfiguration("host-client");
    provider.setUsernameClaim("upn");
    factory =
        new WrappingDecoderFactory(
            new TokenValidatorFactory(
                Map.of("kc", provider), OidcConfiguration.DEFAULT_CLOCK_SKEW, List.of()));
    lenient()
        .when(oidcProviderConfigurationPort.getOidcAuthenticationConfigurations())
        .thenReturn(Map.of("kc", provider));
  }

  @Test
  void shouldKeepTheHostSelectionForTheLibrarysLazyRepository() throws Exception {
    // given
    final var repository =
        new LazyClientRegistrationRepository(
            new ScopedClientRegistrationFactory(), Map.of("kc", provider));
    final var decoder =
        new OidcWebappClientBeansConfiguration()
            .jwtDecoder(
                repository,
                oidcProviderConfigurationPort,
                factory,
                new CamundaSecurityLibraryProperties());

    // when / then
    assertDecodesThroughTheHostSelection(decoder);
  }

  @Test
  void shouldKeepTheHostSelectionForARepositoryOfTheHost() throws Exception {
    // given
    final var repository = new InMemoryClientRegistrationRepository(registration());
    final var decoder =
        new OidcWebappClientBeansConfiguration()
            .jwtDecoder(
                repository,
                oidcProviderConfigurationPort,
                factory,
                new CamundaSecurityLibraryProperties());

    // when / then
    assertDecodesThroughTheHostSelection(decoder);
  }

  @Test
  void shouldKeepTheHostSelectionForAScopedDecoder() throws Exception {
    // given
    final var scope = new AuthenticationConfiguration();
    scope.getProviders().getOidc().put("kc", provider);
    final var decoder =
        new ScopedJwtDecoderFactory(new ScopedClientRegistrationFactory(), factory)
            .buildIssuerAwareDecoder(scope);

    // when / then
    assertDecodesThroughTheHostSelection(decoder);
  }

  private void assertDecodesThroughTheHostSelection(final JwtDecoder decoder) throws Exception {
    final var jwt = decoder.decode(server.sign(server.issuerUri()));

    assertThat(factory.decodes).as("decodes through the host's wrapper").hasPositiveValue();
    assertThat(jwt)
        .isInstanceOfSatisfying(
            VerifiedJwt.class,
            verified ->
                assertThat(verified.principalClaims())
                    .hasValueSatisfying(
                        claims -> assertThat(claims.usernameClaim()).isEqualTo("upn")));
  }

  private static ClientRegistration registration() {
    return ClientRegistration.withRegistrationId("kc")
        .clientId("host-client")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/cb")
        .authorizationUri(server.issuerUri() + "/auth")
        .tokenUri(server.issuerUri() + "/token")
        .jwkSetUri(server.jwksUri())
        .issuerUri(server.issuerUri())
        .build();
  }

  /** A factory of the host that wraps every decoder the public selection gives. */
  private static final class WrappingDecoderFactory extends OidcAccessTokenDecoderFactory {

    private final AtomicInteger decodes = new AtomicInteger();

    WrappingDecoderFactory(final TokenValidatorFactory tokenValidatorFactory) {
      super(new JWSKeySelectorFactory(), tokenValidatorFactory);
    }

    @Override
    public JwtDecoder selectAccessTokenDecoder(
        final Map<String, OidcConfiguration> providersById,
        final Function<String, ClientRegistration> resolveByRegistrationId) {
      return counting(super.selectAccessTokenDecoder(providersById, resolveByRegistrationId));
    }

    @Override
    public JwtDecoder selectAccessTokenDecoder(
        final Map<String, OidcConfiguration> providersById,
        final Function<String, ClientRegistration> resolveByRegistrationId,
        final TokenValidatorFactory validatorFactory) {
      return counting(
          super.selectAccessTokenDecoder(providersById, resolveByRegistrationId, validatorFactory));
    }

    @Override
    public JwtDecoder selectAccessTokenDecoder(
        final List<ClientRegistration> registrations,
        final Map<String, OidcConfiguration> providersById) {
      return counting(super.selectAccessTokenDecoder(registrations, providersById));
    }

    private JwtDecoder counting(final JwtDecoder delegate) {
      return token -> {
        decodes.incrementAndGet();
        return delegate.decode(token);
      };
    }
  }
}
