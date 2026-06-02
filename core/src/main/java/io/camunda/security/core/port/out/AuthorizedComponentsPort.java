/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.out;

import io.camunda.security.api.model.CamundaAuthentication;
import java.util.List;

/**
 * Outbound port returning the list of webapp components the authenticated principal is allowed to
 * use. Populates {@code CamundaUserDTO.authorizedComponents} for the {@link
 * io.camunda.security.core.port.in.CamundaUserPort} default implementation.
 *
 * <p>Intentionally narrow: it bridges the host's component-access lookup (in OC, {@code
 * ResourceAccessProvider} resolving {@code COMPONENT_ACCESS_AUTHORIZATION}) into the library
 * without dragging the full resource-access surface into CSL. A future increment may subsume this
 * port when the broader resource-access framework migrates.
 */
public interface AuthorizedComponentsPort {

  List<String> resolve(CamundaAuthentication authentication);
}
