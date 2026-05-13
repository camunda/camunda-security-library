/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring;

import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.CsrfConfiguration;
import io.camunda.security.api.model.config.PhysicalTenantConfiguration;
import io.camunda.security.api.model.config.headers.HeaderConfiguration;
import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** Binds {@code camunda.security.*} configuration values for the CSL filter chains. */
@ConfigurationProperties(prefix = "camunda.security")
public class CamundaSecurityLibraryProperties {

  private AuthenticationConfiguration authentication = new AuthenticationConfiguration();
  private CsrfConfiguration csrf = new CsrfConfiguration();
  private HeaderConfiguration httpHeaders = new HeaderConfiguration();
  private List<PhysicalTenantConfiguration> physicalTenants = new ArrayList<>();

  public AuthenticationConfiguration getAuthentication() {
    return authentication;
  }

  public void setAuthentication(final AuthenticationConfiguration authentication) {
    this.authentication = authentication;
  }

  public CsrfConfiguration getCsrf() {
    return csrf;
  }

  public void setCsrf(final CsrfConfiguration csrf) {
    this.csrf = csrf;
  }

  public HeaderConfiguration getHttpHeaders() {
    return httpHeaders;
  }

  public void setHttpHeaders(final HeaderConfiguration httpHeaders) {
    this.httpHeaders = httpHeaders;
  }

  public List<PhysicalTenantConfiguration> getPhysicalTenants() {
    return physicalTenants;
  }

  public void setPhysicalTenants(final List<PhysicalTenantConfiguration> physicalTenants) {
    this.physicalTenants = physicalTenants;
  }
}
