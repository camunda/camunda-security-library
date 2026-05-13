/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config.initialization;

import java.util.*;

public class InitializationConfiguration {

  public static final String DEFAULT_USER_USERNAME = "demo";
  public static final String DEFAULT_USER_PASSWORD = "demo";
  public static final String DEFAULT_USER_NAME = "Demo";
  public static final String DEFAULT_USER_EMAIL = "demo@example.com";

  private List<ConfiguredUser> users = List.of();
  private List<ConfiguredMappingRule> mappingRules = List.of();
  private Map<String, Map<String, Collection<String>>> defaultRoles = Map.of();
  private List<ConfiguredAuthorization> authorizations = List.of();
  private List<ConfiguredTenant> tenants = List.of();
  private List<ConfiguredGroup> groups = List.of();
  private List<ConfiguredRole> roles = List.of();

  public List<ConfiguredUser> getUsers() {
    return users;
  }

  public void setUsers(final List<ConfiguredUser> users) {
    this.users = users;
  }

  public List<ConfiguredMappingRule> getMappingRules() {
    return mappingRules;
  }

  public void setMappingRules(final List<ConfiguredMappingRule> mappingRules) {
    this.mappingRules = mappingRules;
  }

  public Map<String, Map<String, Collection<String>>> getDefaultRoles() {
    return defaultRoles;
  }

  public void setDefaultRoles(final Map<String, Map<String, Collection<String>>> defaultRoles) {
    this.defaultRoles = defaultRoles;
  }

  public List<ConfiguredAuthorization> getAuthorizations() {
    return authorizations;
  }

  public void setAuthorizations(final List<ConfiguredAuthorization> authorizations) {
    this.authorizations = authorizations;
  }

  public List<ConfiguredTenant> getTenants() {
    return tenants;
  }

  public void setTenants(final List<ConfiguredTenant> tenants) {
    this.tenants = tenants;
  }

  public List<ConfiguredGroup> getGroups() {
    return groups;
  }

  public void setGroups(final List<ConfiguredGroup> groups) {
    this.groups = groups;
  }

  public List<ConfiguredRole> getRoles() {
    return roles;
  }

  public void setRoles(final List<ConfiguredRole> roles) {
    this.roles = roles;
  }
}
