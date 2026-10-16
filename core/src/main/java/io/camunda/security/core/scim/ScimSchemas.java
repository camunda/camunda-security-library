/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.scim;

/** Schema and message URNs defined by RFC 7643 / RFC 7644. */
public final class ScimSchemas {

  public static final String USER = "urn:ietf:params:scim:schemas:core:2.0:User";
  public static final String ENTERPRISE_USER =
      "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
  public static final String PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
  public static final String LIST_RESPONSE = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
  public static final String ERROR = "urn:ietf:params:scim:api:messages:2.0:Error";
  public static final String SERVICE_PROVIDER_CONFIG =
      "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
  public static final String RESOURCE_TYPE = "urn:ietf:params:scim:schemas:core:2.0:ResourceType";

  private ScimSchemas() {}
}
