# Commands

Commands will be documented in detail as the build tooling is established. The following are the expected conventions.

## Build

- Full build: `mvn clean install`
- Skip tests (faster iteration): `mvn clean install -DskipTests`
- Single module: `mvn clean install -pl <module>`

## Test

- All tests: `mvn test`
- Single module: `mvn test -pl <module>`
- Single test class or method: `mvn test -pl <module> -Dtest=ClassName#methodName`
- Integration tests (requires Docker): `mvn clean verify -Pintegration-tests`

## Gradle (parallel build, ADR-0034)

Maven is the source of truth; the Gradle build mirrors it. See [`docs/workflows/gradle-build-parity.md`](../../docs/workflows/gradle-build-parity.md).

- Full build with all checks: `./gradlew build`
- Single module: `./gradlew :camunda-security-library-core:build` (project names equal the Maven artifactIds)
- Single test class or method: `./gradlew :camunda-security-library-core:test --tests 'ClassName.methodName'`
- Build-logic tests (not run by the root build): `./gradlew -p gradle/build-logic check`
- Maven vs Gradle classpath parity: `python3 .github/scripts/compare-module-deps.py [module] [--scope compile|runtime|test]`
- Parity script's own tests: `python3 -m unittest discover -s .github/scripts -p 'test_*.py'`

## Local Dev Setup

- No external database required for local dev — H2 in-memory by default
- Docker must be running for integration tests (Testcontainers)

## Verification

Run `mvn verify` before claiming any work is complete. A clean run produces no test failures and a `BUILD SUCCESS` output.

Formatting, license headers, and other quality checks will be added as the build matures — update this file when they are.
