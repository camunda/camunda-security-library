/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.scim;

import io.camunda.security.core.port.in.ScimUserPort;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Transport-neutral SCIM protocol layer (RFC 7644): routes a method and path below the SCIM base
 * path to {@link ScimUserPort}, maps results to status codes, headers and RFC 7643 JSON trees, and
 * translates {@link ScimException} to the SCIM error format. A thin HTTP adapter (servlet, Spring
 * MVC, JDK HttpServer) only has to parse JSON, authenticate, and call {@link #handle}.
 *
 * <p>Only Users and discovery are served; {@code /Groups} answers 501.
 */
public final class ScimRequestHandler {

  private static final Logger LOG = LoggerFactory.getLogger(ScimRequestHandler.class);

  private static final int DEFAULT_PAGE_SIZE = 100;

  private final ScimUserPort users;
  private final String baseUrl;

  /**
   * @param users the User port
   * @param baseUrl absolute SCIM base URL without trailing slash, for example {@code
   *     https://host/scim/v2}; used for {@code meta.location}
   */
  public ScimRequestHandler(final ScimUserPort users, final String baseUrl) {
    this.users = users;
    this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
  }

  /**
   * @param method HTTP method
   * @param path path relative to the SCIM base path, for example {@code /Users/123}
   * @param query single-valued query parameters, already URL-decoded
   * @param body parsed JSON body, or {@code null}
   */
  public ScimResponse handle(
      final String method,
      final String path,
      final Map<String, String> query,
      final Map<String, Object> body) {
    LOG.debug("SCIM request: {} {}", method, path);
    try {
      final ScimResponse response = route(method.toUpperCase(), segments(path), query, body);
      LOG.debug("SCIM response: {} {} -> {}", method, path, response.status());
      return response;
    } catch (final ScimException e) {
      LOG.warn(
          "SCIM request rejected: {} {} -> {} {}: {}",
          method,
          path,
          e.status(),
          e.scimType(),
          e.getMessage());
      return ScimResponse.error(e);
    } catch (final RuntimeException e) {
      LOG.error("SCIM request failed unexpectedly: {} {}", method, path, e);
      return ScimResponse.error(500, null, "Internal server error");
    }
  }

  private ScimResponse route(
      final String method,
      final List<String> segments,
      final Map<String, String> query,
      final Map<String, Object> body) {
    if (segments.isEmpty()) {
      throw ScimException.notFound("Unknown SCIM endpoint");
    }
    return switch (segments.get(0)) {
      case "Users" -> routeUsers(method, segments, query, body);
      case "ServiceProviderConfig" -> serviceProviderConfig();
      case "ResourceTypes" -> resourceTypes();
      case "Groups" -> throw ScimException.notImplemented("Groups are not supported yet");
      default -> throw ScimException.notFound("Unknown SCIM endpoint");
    };
  }

  private ScimResponse routeUsers(
      final String method,
      final List<String> segments,
      final Map<String, String> query,
      final Map<String, Object> body) {
    if (segments.size() == 1) {
      return switch (method) {
        case "GET" -> list(query);
        case "POST" -> created(users.create(requireBody(body)));
        default -> throw ScimException.methodNotAllowed(method + " is not allowed on /Users");
      };
    }
    if (segments.size() != 2) {
      throw ScimException.notFound("Unknown SCIM endpoint");
    }
    final String id = segments.get(1);
    return switch (method) {
      case "GET" -> ok(users.get(id));
      case "PUT" -> ok(users.replace(id, requireBody(body)));
      case "PATCH" -> ok(users.patch(id, requireBody(body)));
      case "DELETE" -> {
        users.delete(id);
        yield new ScimResponse(204, Map.of(), null);
      }
      default -> throw ScimException.methodNotAllowed(method + " is not allowed on /Users/{id}");
    };
  }

  private ScimResponse list(final Map<String, String> query) {
    final ScimUserPage page =
        users.search(
            query.get("filter"),
            intParam(query, "startIndex", 1),
            intParam(query, "count", DEFAULT_PAGE_SIZE));
    final List<Map<String, Object>> resources = new ArrayList<>();
    page.resources().forEach(u -> resources.add(document(u)));
    final Map<String, Object> body = new LinkedHashMap<>();
    body.put("schemas", List.of(ScimSchemas.LIST_RESPONSE));
    body.put("totalResults", page.totalResults());
    body.put("startIndex", page.startIndex());
    body.put("itemsPerPage", resources.size());
    body.put("Resources", resources);
    return ScimResponse.of(200, body);
  }

  private static int intParam(final Map<String, String> query, final String name, final int dflt) {
    final String raw = query.get(name);
    if (raw == null || raw.isBlank()) {
      return dflt;
    }
    try {
      return Integer.parseInt(raw.trim());
    } catch (final NumberFormatException e) {
      throw ScimException.invalidValue("'" + name + "' must be an integer");
    }
  }

  private static Map<String, Object> requireBody(final Map<String, Object> body) {
    if (body == null) {
      throw ScimException.invalidSyntax("Request body is required");
    }
    return body;
  }

  private ScimResponse ok(final ScimUserResource user) {
    return new ScimResponse(200, Map.of("Location", location(user)), document(user));
  }

  private ScimResponse created(final ScimUserResource user) {
    return new ScimResponse(201, Map.of("Location", location(user)), document(user));
  }

  private Map<String, Object> document(final ScimUserResource user) {
    return ScimUserRepresentation.toDocument(user, location(user));
  }

  private String location(final ScimUserResource user) {
    return baseUrl + "/Users/" + user.id();
  }

  private static List<String> segments(final String path) {
    final List<String> result = new ArrayList<>();
    for (final String s : path.split("/")) {
      if (!s.isEmpty()) {
        result.add(s);
      }
    }
    return result;
  }

  private ScimResponse serviceProviderConfig() {
    final Map<String, Object> body = new LinkedHashMap<>();
    body.put("schemas", List.of(ScimSchemas.SERVICE_PROVIDER_CONFIG));
    body.put("patch", Map.of("supported", true));
    body.put("bulk", Map.of("supported", false, "maxOperations", 0, "maxPayloadSize", 0));
    body.put("filter", Map.of("supported", true, "maxResults", ScimUserService.MAX_PAGE_SIZE));
    body.put("changePassword", Map.of("supported", false));
    body.put("sort", Map.of("supported", false));
    body.put("etag", Map.of("supported", false));
    body.put(
        "authenticationSchemes",
        List.of(
            Map.of(
                "type", "oauthbearertoken",
                "name", "OAuth Bearer Token",
                "description", "Authentication via the OAuth Bearer Token standard")));
    return ScimResponse.of(200, body);
  }

  private ScimResponse resourceTypes() {
    final Map<String, Object> user = new LinkedHashMap<>();
    user.put("schemas", List.of(ScimSchemas.RESOURCE_TYPE));
    user.put("id", "User");
    user.put("name", "User");
    user.put("endpoint", "/Users");
    user.put("schema", ScimSchemas.USER);
    user.put(
        "schemaExtensions",
        List.of(Map.of("schema", ScimSchemas.ENTERPRISE_USER, "required", false)));
    final Map<String, Object> body = new LinkedHashMap<>();
    body.put("schemas", List.of(ScimSchemas.LIST_RESPONSE));
    body.put("totalResults", 1);
    body.put("startIndex", 1);
    body.put("itemsPerPage", 1);
    body.put("Resources", List.of(user));
    return ScimResponse.of(200, body);
  }
}
