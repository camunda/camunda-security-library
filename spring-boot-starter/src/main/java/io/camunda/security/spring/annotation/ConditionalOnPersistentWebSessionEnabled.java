/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

/**
 * Matches when persistent web sessions are enabled via {@code
 * camunda.security.session.persistent.enabled=true}.
 *
 * <p>Hosts that still use legacy enable-properties are expected to bridge them onto this canonical
 * property (for example via an {@code EnvironmentPostProcessor}).
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
@Documented
@ConditionalOnProperty(
    name = io.camunda.security.api.model.config.SessionConfiguration.PERSISTENT_ENABLED_PROPERTY,
    havingValue = "true")
public @interface ConditionalOnPersistentWebSessionEnabled {}
