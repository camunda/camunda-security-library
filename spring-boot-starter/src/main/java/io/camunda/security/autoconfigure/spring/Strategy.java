/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.autoconfigure.spring;

/**
 * Deployment strategy selected by the host application via the
 * {@code camunda.security.strategy} property.
 *
 * <p>Spring's relaxed binding maps kebab-case property values to enum
 * constants: {@code oc-standalone} → {@link #OC_STANDALONE},
 * {@code oc-managed} → {@link #OC_MANAGED}, {@code hub} → {@link #HUB}.
 */
public enum Strategy {
    OC_STANDALONE,
    OC_MANAGED,
    HUB
}
