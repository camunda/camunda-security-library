/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import io.camunda.security.api.context.CamundaAuthenticationProvider;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.core.port.out.AuthorizedComponentsPort;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;

@ExtendWith(MockitoExtension.class)
class OidcCamundaUserServiceTest {

  @Mock CamundaAuthenticationProvider authenticationProvider;
  @Mock AuthorizedComponentsPort authorizedComponentsPort;
  @Mock OAuth2AuthorizedClientRepository authorizedClientRepository;
  @Mock HttpServletRequest request;
  @InjectMocks OidcCamundaUserService service;

  @AfterEach
  void clearSecurityContext() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void returnsNullWhenAuthenticationAbsent() {
    when(authenticationProvider.getCamundaAuthentication()).thenReturn(null);
    assertThat(service.getCurrentUser()).isNull();
  }

  @Test
  void returnsNullWhenAuthenticationIsAnonymous() {
    when(authenticationProvider.getCamundaAuthentication())
        .thenReturn(CamundaAuthentication.anonymous());
    assertThat(service.getCurrentUser()).isNull();
  }

  @Test
  void buildsDtoFromAuthenticationWhenPresent() {
    final var authentication =
        CamundaAuthentication.of(
            b ->
                b.user("alice")
                    .tenants(List.of("tenant-1", "tenant-2"))
                    .group("group-1")
                    .role("role-1"));
    when(authenticationProvider.getCamundaAuthentication()).thenReturn(authentication);
    when(authorizedComponentsPort.resolve(authentication)).thenReturn(List.of("operate", "admin"));

    final var dto = service.getCurrentUser();

    assertThat(dto).isNotNull();
    assertThat(dto.username()).isEqualTo("alice");
    assertThat(dto.tenants()).containsExactly("tenant-1", "tenant-2");
    assertThat(dto.groups()).containsExactly("group-1");
    assertThat(dto.roles()).containsExactly("role-1");
    assertThat(dto.authorizedComponents()).containsExactly("operate", "admin");
    assertThat(dto.c8Links()).isEmpty();
    assertThat(dto.canLogout()).isTrue();
  }
}
