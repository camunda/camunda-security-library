/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.auth;

import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.core.auth.condition.AuthorizationCondition;
import io.camunda.security.core.auth.condition.AuthorizationConditions;
import java.util.function.Function;

/**
 * Represents the security context for the current operation, containing both authentication and
 * authorization information. It encapsulates the user's identity, group and tenant affiliations,
 * along with the permissions that need to be checked for the current operation.
 */
public record SecurityContext(
    CamundaAuthentication authentication, AuthorizationCondition authorizationCondition) {

  public static SecurityContext of(final Function<Builder, Builder> builderFunction) {
    return builderFunction.apply(new Builder()).build();
  }

  public static final class Builder {
    private CamundaAuthentication authentication;
    private AuthorizationCondition authorizationCondition;

    public Builder withAuthentication(final CamundaAuthentication authentication) {
      this.authentication = authentication;
      return this;
    }

    public Builder withAuthentication(
        final Function<CamundaAuthentication.Builder, CamundaAuthentication.Builder>
            builderFunction) {
      return withAuthentication(CamundaAuthentication.of(builderFunction));
    }

    public Builder withAuthorization(final RequiredAuthorization<?> authorization) {
      return withAuthorizationCondition(AuthorizationConditions.single(authorization));
    }

    public <T> Builder withAuthorization(
        final Function<RequiredAuthorization.Builder<T>, RequiredAuthorization.Builder<T>>
            builderFunction) {
      return withAuthorization(RequiredAuthorization.of(builderFunction));
    }

    public Builder withAuthorizationCondition(final AuthorizationCondition authorizationCondition) {
      this.authorizationCondition = authorizationCondition;
      return this;
    }

    public SecurityContext build() {
      return new SecurityContext(authentication, authorizationCondition);
    }
  }
}
