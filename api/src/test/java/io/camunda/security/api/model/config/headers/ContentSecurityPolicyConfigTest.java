/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config.headers;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import org.junit.jupiter.api.Test;

class ContentSecurityPolicyConfigTest {

  @Test
  void saasPolicyImgSrcShouldPermitBlobScheme() {
    // expect:
    assertThat(imgSrcDirective(ContentSecurityPolicyConfig.DEFAULT_SAAS_SECURITY_POLICY))
        .contains("blob:");
  }

  @Test
  void selfManagedPolicyImgSrcShouldPermitBlobScheme() {
    // expect:
    assertThat(imgSrcDirective(ContentSecurityPolicyConfig.DEFAULT_SM_SECURITY_POLICY))
        .contains("blob:");
  }

  private static String imgSrcDirective(final String policy) {
    return Arrays.stream(policy.split("; "))
        .map(String::trim)
        .filter(directive -> directive.startsWith("img-src "))
        .findFirst()
        .orElseThrow(() -> new AssertionError("No img-src directive found in policy: " + policy));
  }
}
