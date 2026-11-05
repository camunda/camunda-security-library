# CSL client module

This module adds credentials to calls to CSL-protected services.
See the [adopter guide](../docs/adopters/outbound-client.md) and
[ADR-0042](../docs/adr/0042-spring-free-client-for-csl-protected-services.md).

## Java 8

The module targets Java 8 for now. The Camunda Java client has a Java 8 baseline, and it will use
this module (#133). The rest of CSL uses Java 21.

- Main code must not use Java 9 or later. Do not use records, `var`, `List.of`, `Map.copyOf`,
  `String.isBlank`, `String.formatted`, switch expressions, text blocks, pattern matching for
  `instanceof`, or the JDK `HttpClient`.
- The build enforces this with `--release 8` (`maven.compiler.release` in `pom.xml`). Tests use
  Java 21.
- Dependencies must also run on Java 8. All runtime dependencies have class version 52 or lower.
  The build does not check this. When you add or upgrade a dependency, check its class version.

When the Java client raises its baseline, you can remove this limit.
