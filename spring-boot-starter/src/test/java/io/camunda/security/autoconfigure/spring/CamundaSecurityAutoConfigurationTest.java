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
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationPropertiesBindException;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

class CamundaSecurityAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(CamundaSecurityAutoConfiguration.class))
            .withUserConfiguration(OcStandaloneDemoConfiguration.class);

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
                .rootCause()
                .hasMessageContainingAll(
                        "must not be null",
                        "field 'strategy'",
                        "camunda.security"));
    }

    @Test
    void invalid_strategy_fails_startup() {
        runner.withPropertyValues("camunda.security.strategy=bogus")
                .run(ctx -> assertThat(ctx)
                        .hasFailed()
                        .getFailure()
                        .isInstanceOf(ConfigurationPropertiesBindException.class)
                        .rootCause()
                        .hasMessage("No enum constant io.camunda.security.autoconfigure.spring.Strategy.bogus"));
    }

    @Test
    void marker_bean_is_registered_under_oc_standalone() {
        runner.withPropertyValues("camunda.security.strategy=oc-standalone")
                .run(ctx -> assertThat(ctx).hasSingleBean(OcStandaloneMarker.class));
    }

    @Test
    void marker_bean_is_absent_under_oc_managed() {
        runner.withPropertyValues("camunda.security.strategy=oc-managed")
                .run(ctx -> assertThat(ctx).doesNotHaveBean(OcStandaloneMarker.class));
    }

    @Test
    void marker_bean_is_absent_under_hub() {
        runner.withPropertyValues("camunda.security.strategy=hub")
                .run(ctx -> assertThat(ctx).doesNotHaveBean(OcStandaloneMarker.class));
    }

    /**
     * Test-only configuration that exercises the strategy-scoped wiring
     * convention. Production auto-configuration uses the same
     * {@code @ConditionalOnProperty} pattern when it registers real
     * strategy-specific beans in later vertical-slice PRs.
     */
    @Configuration
    static class OcStandaloneDemoConfiguration {

        @Bean
        @ConditionalOnProperty(name = "camunda.security.strategy", havingValue = "oc-standalone")
        OcStandaloneMarker ocStandaloneMarker() {
            return new OcStandaloneMarker();
        }
    }
}
