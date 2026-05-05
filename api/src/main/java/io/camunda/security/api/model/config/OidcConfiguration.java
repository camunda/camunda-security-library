/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config;

import java.util.ArrayList;
import java.util.List;

/** OIDC configuration bound to {@code camunda.security.authentication.oidc.*}. */
public class OidcConfiguration {

  private String issuerUri;
  private String clientId;
  private String clientSecret;
  private String jwkSetUri;
  private List<String> additionalJwkSetUris = new ArrayList<>();
  private String authorizationUri;
  private String tokenUri;
  private String userInfoUri;
  private String redirectUri;
  private List<String> scope = List.of("openid", "profile");
  private List<String> audiences = new ArrayList<>();
  private String registrationId = "oidc";
  private String clientAuthenticationMethod = "client_secret_basic";

  public String getIssuerUri() {
    return issuerUri;
  }

  public void setIssuerUri(final String issuerUri) {
    this.issuerUri = issuerUri;
  }

  public String getClientId() {
    return clientId;
  }

  public void setClientId(final String clientId) {
    this.clientId = clientId;
  }

  public String getClientSecret() {
    return clientSecret;
  }

  public void setClientSecret(final String clientSecret) {
    this.clientSecret = clientSecret;
  }

  public String getJwkSetUri() {
    return jwkSetUri;
  }

  public void setJwkSetUri(final String jwkSetUri) {
    this.jwkSetUri = jwkSetUri;
  }

  public List<String> getAdditionalJwkSetUris() {
    return additionalJwkSetUris;
  }

  public void setAdditionalJwkSetUris(final List<String> additionalJwkSetUris) {
    this.additionalJwkSetUris = additionalJwkSetUris;
  }

  public String getAuthorizationUri() {
    return authorizationUri;
  }

  public void setAuthorizationUri(final String authorizationUri) {
    this.authorizationUri = authorizationUri;
  }

  public String getTokenUri() {
    return tokenUri;
  }

  public void setTokenUri(final String tokenUri) {
    this.tokenUri = tokenUri;
  }

  public String getUserInfoUri() {
    return userInfoUri;
  }

  public void setUserInfoUri(final String userInfoUri) {
    this.userInfoUri = userInfoUri;
  }

  public String getRedirectUri() {
    return redirectUri;
  }

  public void setRedirectUri(final String redirectUri) {
    this.redirectUri = redirectUri;
  }

  public List<String> getScope() {
    return scope;
  }

  public void setScope(final List<String> scope) {
    this.scope = scope;
  }

  public List<String> getAudiences() {
    return audiences;
  }

  public void setAudiences(final List<String> audiences) {
    this.audiences = audiences;
  }

  public String getRegistrationId() {
    return registrationId;
  }

  public void setRegistrationId(final String registrationId) {
    this.registrationId = registrationId;
  }

  public String getClientAuthenticationMethod() {
    return clientAuthenticationMethod;
  }

  public void setClientAuthenticationMethod(final String clientAuthenticationMethod) {
    this.clientAuthenticationMethod = clientAuthenticationMethod;
  }
}
