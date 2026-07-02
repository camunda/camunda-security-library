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

import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class WebSessionDeletionTaskTest {

  @Mock private WebSessionRepository repositoryA;
  @Mock private WebSessionRepository repositoryB;

  @Test
  void sweepsEveryRepository() {
    final var task = new WebSessionDeletionTask(() -> List.of(repositoryA, repositoryB));

    task.run();

    verify(repositoryA).deleteExpiredWebSessions();
    verify(repositoryB).deleteExpiredWebSessions();
  }

  @Test
  void oneFailingRepositoryDoesNotStopTheOthers() {
    doThrow(new RuntimeException("storage down")).when(repositoryA).deleteExpiredWebSessions();
    final var task = new WebSessionDeletionTask(() -> List.of(repositoryA, repositoryB));

    assertThatCode(task::run).doesNotThrowAnyException();

    // the failing store is swept, and the next store is still swept afterwards
    verify(repositoryA).deleteExpiredWebSessions();
    verify(repositoryB).deleteExpiredWebSessions();
  }
}
