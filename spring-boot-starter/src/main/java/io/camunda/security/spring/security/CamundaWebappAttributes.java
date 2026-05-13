/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

/**
 * Well-known request and session attribute names exposed by the CSL webapp filter chains. Hosts
 * that want to read these attributes (for example, to render a post-logout page) reference these
 * constants instead of hard-coding the strings.
 */
public final class CamundaWebappAttributes {

  /**
   * Session attribute under which the {@link CamundaOidcLogoutSuccessHandler} stores the validated,
   * same-origin {@code Referer} as the post-logout redirect URI.
   */
  public static final String POST_LOGOUT_REDIRECT_ATTRIBUTE = "postLogoutRedirect";

  /**
   * Request attribute used by the {@link CamundaOidcLogoutSuccessHandler} to surface a
   * human-readable explanation when RP-initiated logout cannot reach the IdP (for example, no
   * {@code end_session_endpoint} was published).
   */
  public static final String REDIRECT_MESSAGE_ATTRIBUTE = "redirectMessage";

  private CamundaWebappAttributes() {}
}
