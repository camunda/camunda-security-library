/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.session;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.module.SimpleModule;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.authz.ConditionalMembership;
import io.camunda.security.api.model.authz.MembershipCondition;
import io.camunda.security.api.model.authz.Operand;
import io.camunda.security.api.model.authz.ResourceAttribute;
import java.io.IOException;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * A host that stores {@link CamundaAuthentication} as JSON, for example in a web session or a batch
 * operation, must be able to read conditional memberships back. The API types carry no Jackson
 * annotations, so the host tells Jackson which {@link Operand} type a JSON object is; this test
 * registers the deserializer such a host needs.
 */
class CamundaAuthenticationJacksonTest {

  private final ObjectMapper objectMapper =
      new ObjectMapper()
          .registerModule(
              new SimpleModule().addDeserializer(Operand.class, new OperandDeserializer()))
          .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

  @Test
  void shouldRoundTripConditionalMemberships() throws Exception {
    // given
    final var reviewerInPaymentsInvoicing =
        new ConditionalMembership(
            "reviewer",
            List.of(
                new MembershipCondition(
                    ResourceAttribute.WORKSPACE_ID, new Operand.Equals("payments")),
                new MembershipCondition(
                    ResourceAttribute.PROJECT_ID, new Operand.Equals("invoicing"))));
    final var authentication =
        CamundaAuthentication.of(
            b ->
                b.user("demo-user")
                    .role("viewer")
                    .conditionalRoleMembershipsSupplier(
                        () -> List.of(reviewerInPaymentsInvoicing)));

    // when
    final var json = objectMapper.writeValueAsString(authentication);
    final var restored = objectMapper.readValue(json, CamundaAuthentication.class);

    // then
    assertThat(restored).isEqualTo(authentication);
    assertThat(restored.authenticatedRoleIds()).containsExactly("viewer");
    assertThat(restored.conditionalRoleMemberships()).containsExactly(reviewerInPaymentsInvoicing);
  }

  @Test
  void shouldReadAnAuthenticationStoredBeforeConditionalMemberships() throws Exception {
    // given JSON written by a version without the field
    final var json =
        """
        {"authenticatedUsername":"demo-user","authenticatedClientId":null,"anonymousUser":false,
         "authenticatedGroupIds":[],"authenticatedRoleIds":["viewer"],"authenticatedTenantIds":[],
         "authenticatedMappingRuleIds":[],"claims":{}}
        """;

    // when
    final var restored = objectMapper.readValue(json, CamundaAuthentication.class);

    // then
    assertThat(restored.authenticatedRoleIds()).containsExactly("viewer");
    assertThat(restored.conditionalRoleMemberships()).isEmpty();
  }

  /**
   * Reads {@link Operand.Equals}, the only kind of operand so far. Any other shape fails, so a
   * later kind of operand can't be read as {@code Equals}.
   */
  private static final class OperandDeserializer extends StdDeserializer<Operand> {

    private OperandDeserializer() {
      super(Operand.class);
    }

    @Override
    public Operand deserialize(final JsonParser parser, final DeserializationContext context)
        throws IOException {
      final JsonNode node = parser.readValueAsTree();
      if (node.size() != 1 || !node.has("value")) {
        throw context.weirdStringException(node.toString(), Operand.class, "Unknown operand shape");
      }
      return parser.getCodec().treeToValue(node, Operand.Equals.class);
    }
  }
}
