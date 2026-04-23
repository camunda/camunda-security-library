/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.autoconfigure.spring;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Root auto-configuration for the Camunda Security Library. Enables
 * {@link CamundaSecurityLibraryProperties} binding so the deployment
 * strategy is validated at application startup, and wires
 * strategy-scoped beans via {@code @ConditionalOnProperty}.
 */
@AutoConfiguration
@EnableConfigurationProperties(CamundaSecurityLibraryProperties.class)
public class CamundaSecurityLibraryAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(name = "camunda.security.strategy", havingValue = "oc-standalone")
    OcStandaloneMarker ocStandaloneMarker() {
        return new OcStandaloneMarker();
    }
}
