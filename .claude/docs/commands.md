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

## Local Dev Setup

- No external database required for local dev — H2 in-memory by default
- Docker must be running for integration tests (Testcontainers)

## Verification

Run `mvn verify` before claiming any work is complete. A clean run produces no test failures and a `BUILD SUCCESS` output.

Formatting, license headers, and other quality checks will be added as the build matures — update this file when they are.
