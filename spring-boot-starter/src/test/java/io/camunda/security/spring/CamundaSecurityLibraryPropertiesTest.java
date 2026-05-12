/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class CamundaSecurityLibraryPropertiesTest {

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withConfiguration(AutoConfigurations.of(CamundaSecurityConfiguration.class));

  @Test
  void shouldValidateNestedOidcAssertionConfigurationAfterBinding() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.assertion.kid-encoding=BASE64URL",
            "camunda.security.authentication.oidc.assertion.kid-case=LOWER")
        .run(
            context -> {
              assertThat(context).hasFailed();
              assertThat(context.getStartupFailure())
                  .hasRootCauseInstanceOf(IllegalStateException.class)
                  .hasRootCauseMessage("kidCase can only be set when kidEncoding is HEX");
            });
  }
}
