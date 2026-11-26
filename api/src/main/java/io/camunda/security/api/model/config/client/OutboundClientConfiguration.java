/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config.client;

import org.jspecify.annotations.Nullable;

/**
 * Settings of one named outbound client, bound from {@code camunda.security.client.<name>}. Set
 * exactly one of {@link #getOidc() oidc} and {@link #getBasic() basic}. The starter checks this
 * rule at startup.
 */
public final class OutboundClientConfiguration {

  private @Nullable OutboundOidcConfiguration oidc;
  private @Nullable OutboundBasicConfiguration basic;

  public @Nullable OutboundOidcConfiguration getOidc() {
    return oidc;
  }

  public void setOidc(final @Nullable OutboundOidcConfiguration oidc) {
    this.oidc = oidc;
  }

  public @Nullable OutboundBasicConfiguration getBasic() {
    return basic;
  }

  public void setBasic(final @Nullable OutboundBasicConfiguration basic) {
    this.basic = basic;
  }
}
