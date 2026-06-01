/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.session;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class WebSessionDeletionTaskTest {

  @Mock private WebSessionRepository webSessionRepository;
  @InjectMocks private WebSessionDeletionTask task;

  @Test
  void delegatesToRepository() {
    task.run();

    verify(webSessionRepository).deleteExpiredWebSessions();
  }

  @Test
  void swallowsRepositoryException() {
    doThrow(new RuntimeException("storage down"))
        .when(webSessionRepository)
        .deleteExpiredWebSessions();

    assertThatCode(() -> task.run()).doesNotThrowAnyException();
    verify(webSessionRepository).deleteExpiredWebSessions();
  }
}
