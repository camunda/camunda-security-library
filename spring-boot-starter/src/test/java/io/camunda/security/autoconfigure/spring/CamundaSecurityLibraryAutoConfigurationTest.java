/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.autoconfigure.spring;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationPropertiesBindException;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class CamundaSecurityLibraryAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    ConfigurationPropertiesAutoConfiguration.class,
                    CamundaSecurityLibraryAutoConfiguration.class));

    @Test
    void binds_oc_standalone() {
        runner.withPropertyValues("camunda.security.strategy=oc-standalone")
                .run(ctx -> assertThat(ctx)
                        .getBean(CamundaSecurityLibraryProperties.class)
                        .extracting(CamundaSecurityLibraryProperties::getStrategy)
                        .isEqualTo(Strategy.OC_STANDALONE));
    }

    @Test
    void binds_oc_managed() {
        runner.withPropertyValues("camunda.security.strategy=oc-managed")
                .run(ctx -> assertThat(ctx)
                        .getBean(CamundaSecurityLibraryProperties.class)
                        .extracting(CamundaSecurityLibraryProperties::getStrategy)
                        .isEqualTo(Strategy.OC_MANAGED));
    }

    @Test
    void binds_hub() {
        runner.withPropertyValues("camunda.security.strategy=hub")
                .run(ctx -> assertThat(ctx)
                        .getBean(CamundaSecurityLibraryProperties.class)
                        .extracting(CamundaSecurityLibraryProperties::getStrategy)
                        .isEqualTo(Strategy.HUB));
    }

    @Test
    void missing_strategy_fails_startup() {
        runner.run(ctx -> assertThat(ctx)
                .hasFailed()
                .getFailure()
                .isInstanceOf(ConfigurationPropertiesBindException.class)
                .hasStackTraceContaining("camunda.security.strategy"));
    }

    @Test
    void invalid_strategy_fails_startup() {
        runner.withPropertyValues("camunda.security.strategy=bogus")
                .run(ctx -> assertThat(ctx)
                        .hasFailed()
                        .getFailure()
                        .isInstanceOf(ConfigurationPropertiesBindException.class)
                        .hasStackTraceContaining("camunda.security.strategy")
                        .hasStackTraceContaining("bogus"));
    }
}
