/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.autoconfigure.spring;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/**
 * Root auto-configuration for the Camunda Security Library. Enables {@link
 * CamundaSecurityLibraryProperties} binding at application startup.
 */
@AutoConfiguration
@EnableConfigurationProperties(CamundaSecurityLibraryProperties.class)
public class CamundaSecurityAutoConfiguration {}
