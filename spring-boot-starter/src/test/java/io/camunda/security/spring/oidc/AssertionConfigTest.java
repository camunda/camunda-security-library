/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.model.config.AssertionConfiguration.KidCase;
import io.camunda.security.api.model.config.AssertionConfiguration.KidDigestAlgorithm;
import io.camunda.security.api.model.config.AssertionConfiguration.KidEncoding;
import io.camunda.security.api.model.config.AssertionConfiguration.KidSource;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@SuppressWarnings("SpringBootApplicationProperties")
@EnableAutoConfiguration
@SpringBootTest(
    classes = AssertionConfigTest.TestConfig.class,
    properties = {
      "camunda.security.authentication.oidc.assertion.keystore.path=/opt/keys/thekeystore.p12",
      "camunda.security.authentication.oidc.assertion.keystore.password=password",
      "camunda.security.authentication.oidc.assertion.keystore.keyAlias=thekey",
      "camunda.security.authentication.oidc.assertion.keystore.keyPassword=keypass",
      "camunda.security.authentication.oidc.assertion.kidSource=certificate",
      "camunda.security.authentication.oidc.assertion.kidDigestAlgorithm=sha256",
      "camunda.security.authentication.oidc.assertion.kidEncoding=hex",
      "camunda.security.authentication.oidc.assertion.kidCase=lower"
    })
class AssertionConfigTest {

  @Autowired private CamundaSecurityLibraryProperties properties;

  @Test
  void shouldLoadAssertionConfiguration() {
    final var assertionConfig = properties.getAuthentication().getOidc().getAssertion();
    final var keystoreConfig = assertionConfig.getKeystore();
    assertThat(keystoreConfig.getPath()).isEqualTo("/opt/keys/thekeystore.p12");
    assertThat(keystoreConfig.getPassword()).isEqualTo("password");
    assertThat(keystoreConfig.getKeyAlias()).isEqualTo("thekey");
    assertThat(keystoreConfig.getKeyPassword()).isEqualTo("keypass");
    assertThat(assertionConfig.getKidSource()).isEqualTo(KidSource.CERTIFICATE);
    assertThat(assertionConfig.getKidDigestAlgorithm()).isEqualTo(KidDigestAlgorithm.SHA256);
    assertThat(assertionConfig.getKidEncoding()).isEqualTo(KidEncoding.HEX);
    assertThat(assertionConfig.getKidCase()).isEqualTo(KidCase.LOWER);
  }

  @Configuration
  static class TestConfig {
    @Bean
    @ConfigurationProperties("camunda.security")
    public CamundaSecurityLibraryProperties properties() {
      return new CamundaSecurityLibraryProperties();
    }
  }
}
