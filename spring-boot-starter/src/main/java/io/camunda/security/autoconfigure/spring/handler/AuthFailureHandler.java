/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.autoconfigure.spring.handler;

import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

/**
 * Unified handler for authentication and authorization failures.
 *
 * <p>Combines the three Spring Security failure-handling SPIs the central filter chains route
 * through ({@link AuthenticationFailureHandler}, {@link AccessDeniedHandler}, {@link
 * AuthenticationEntryPoint}) so hosts only need to register a single bean.
 *
 * <p>Hosts can either register {@link JsonProblemDetailAuthFailureHandler} (the library's RFC 7807
 * default) or implement this interface themselves to emit a host-specific problem-detail schema.
 * When a host registers its own implementation, the library configurations pick it up by type.
 */
public interface AuthFailureHandler
    extends AuthenticationFailureHandler, AccessDeniedHandler, AuthenticationEntryPoint {}
