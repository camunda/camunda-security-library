/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.session;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.camunda.security.spring.session.WebSessionConfiguration.SelfSchedulingTask;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class SelfSchedulingTaskTest {

  private static final long DELAY_MILLIS = 1_000L;

  @Mock private ScheduledThreadPoolExecutor executor;
  @Mock private Runnable task;

  @Test
  void runsTaskAndReschedulesWhenExecutorIsLive() {
    final var selfScheduling = new SelfSchedulingTask(executor, task, DELAY_MILLIS);
    when(executor.isShutdown()).thenReturn(false);

    selfScheduling.run();

    verify(task).run();
    verify(executor).schedule(selfScheduling, DELAY_MILLIS, TimeUnit.MILLISECONDS);
  }

  @Test
  void runsTaskButSkipsRescheduleWhenExecutorIsShutdown() {
    final var selfScheduling = new SelfSchedulingTask(executor, task, DELAY_MILLIS);
    when(executor.isShutdown()).thenReturn(true);

    selfScheduling.run();

    verify(task).run();
    verify(executor, never()).schedule(selfScheduling, DELAY_MILLIS, TimeUnit.MILLISECONDS);
  }
}
