/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.client;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.client.OutboundCredentialsProvider.StatusCode;
import org.junit.jupiter.api.Test;

class StatusCodeTest {

  @Test
  void onlyHttp401IsUnauthorized() {
    assertThat(StatusCode.ofHttp(401).isUnauthorized()).isTrue();
    assertThat(StatusCode.ofHttp(403).isUnauthorized()).isFalse();
    assertThat(StatusCode.ofHttp(403).code()).isEqualTo(403);
  }
}
