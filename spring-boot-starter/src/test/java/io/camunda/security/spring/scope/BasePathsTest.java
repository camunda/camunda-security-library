/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import org.junit.jupiter.api.Test;

class BasePathsTest {

  @Test
  void shouldReturnPathUnchangedWhenNoTrailingSlash() {
    assertThat(BasePaths.normalize("/scope", "field")).isEqualTo("/scope");
  }

  @Test
  void shouldStripTrailingSlash() {
    assertThat(BasePaths.normalize("/scope/", "field")).isEqualTo("/scope");
  }

  @Test
  void shouldReturnNestedPathUnchanged() {
    assertThat(BasePaths.normalize("/a/b", "field")).isEqualTo("/a/b");
  }

  @Test
  void shouldStripTrailingSlashFromNestedPath() {
    assertThat(BasePaths.normalize("/a/b/", "field")).isEqualTo("/a/b");
  }

  @Test
  void shouldAcceptUnreservedSegmentCharacters() {
    // given — real base paths use hyphens and dots; both are on the allowlist
    assertThat(BasePaths.normalize("/physical-tenants/t1", "field"))
        .isEqualTo("/physical-tenants/t1");
  }

  @Test
  void shouldMapRootPathToEmptyPrefix() {
    // given — root "/" is the cluster / non-PT default

    // when / then — must return "" (no prefix), not throw
    assertThat(BasePaths.normalize("/", "myField")).isEqualTo("");
  }

  @Test
  void shouldRejectRelativePath() {
    // given
    final var relative = "scope";

    // when / then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> BasePaths.normalize(relative, "myField"))
        .withMessageContaining("myField");
  }

  @Test
  void shouldRejectEmptyString() {
    // given
    final var empty = "";

    // when / then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> BasePaths.normalize(empty, "myField"))
        .withMessageContaining("myField");
  }

  @Test
  void shouldRejectNull() {
    // when / then — null is an invalid base path, rejected uniformly like any other
    assertThatIllegalArgumentException()
        .isThrownBy(() -> BasePaths.normalize(null, "myField"))
        .withMessageContaining("myField");
  }

  @Test
  void shouldRejectBareDoubleSlash() {
    // given — "//" is an empty segment; the allowlist requires non-empty segments
    final var doubleSlash = "//";

    // when / then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> BasePaths.normalize(doubleSlash, "myField"))
        .withMessageContaining("myField");
  }

  @Test
  void shouldRejectTripleSlash() {
    // given — "///" is all empty segments
    final var tripleSlash = "///";

    // when / then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> BasePaths.normalize(tripleSlash, "myField"))
        .withMessageContaining("myField");
  }

  @Test
  void shouldRejectLeadingDoubleSlashWithSegment() {
    // given — "//scope" has a leading empty segment
    final var malformed = "//scope";

    // when / then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> BasePaths.normalize(malformed, "myField"))
        .withMessageContaining("myField");
  }

  @Test
  void shouldRejectInternalDoubleSlash() {
    // given — "/a//b" has an empty internal segment; rejected (no more collapse special-casing)
    final var path = "/a//b";

    // when / then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> BasePaths.normalize(path, "myField"))
        .withMessageContaining("myField");
  }

  @Test
  void shouldRejectTrailingDoubleSlash() {
    // given — "/scope//" has a trailing empty segment; only a single trailing slash is allowed
    final var path = "/scope//";

    // when / then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> BasePaths.normalize(path, "myField"))
        .withMessageContaining("myField");
  }

  @Test
  void shouldRejectSingleWildcard() {
    // given — a '*' would broaden Spring Security path matchers (CSRF bypass)
    final var path = "/scope/*";

    // when / then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> BasePaths.normalize(path, "myField"))
        .withMessageContaining("myField");
  }

  @Test
  void shouldRejectDoubleWildcard() {
    // given — "**" is even broader; both forms must be rejected
    final var path = "/scope/**";

    // when / then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> BasePaths.normalize(path, "myField"))
        .withMessageContaining("myField");
  }

  @Test
  void shouldRejectStarInSegment() {
    // given — '*' anywhere in a segment is a PathPattern wildcard
    final var path = "/a*b";

    // when / then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> BasePaths.normalize(path, "myField"))
        .withMessageContaining("myField");
  }

  @Test
  void shouldRejectQuestionMarkWildcard() {
    // given — '?' is a single-character wildcard in Spring path matchers
    final var path = "/a?b";

    // when / then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> BasePaths.normalize(path, "myField"))
        .withMessageContaining("myField");
  }

  @Test
  void shouldRejectPathVariableBraces() {
    // given — "{x}" is PathPattern path-variable syntax; braces are not on the allowlist
    final var path = "/{x}";

    // when / then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> BasePaths.normalize(path, "myField"))
        .withMessageContaining("myField");
  }

  @Test
  void shouldRejectBracesInsideSegment() {
    // given — braces anywhere widen a PathPattern matcher
    final var path = "/a{b}c";

    // when / then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> BasePaths.normalize(path, "myField"))
        .withMessageContaining("myField");
  }
}
