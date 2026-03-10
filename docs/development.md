---
connie-title: "latticepay-security: Development Guide"
---

# Latticepay Security Library - Development Guide

**Prerequisites:** Java 25+, Maven Wrapper (`./mvnw`)

## Build

```bash
./mvnw clean install
```

### Common commands

| Goal | Command |
|------|---------|
| Full build | `./mvnw clean install` |
| Run tests | `./mvnw test` |
| Verify (tests + checks) | `./mvnw verify` |
| Run one test class (runtime) | `./mvnw test -pl runtime,deployment -Dtest=GcipConfigValidatorTest -Dsurefire.failIfNoSpecifiedTests=false` |
| Build single module | `./mvnw -pl runtime install` |
| Skip integration tests | `./mvnw -DskipITs=true clean install` |

## Project layout

- **runtime** — Quarkus extension runtime (auth, identity, config, GCP)
- **deployment** — Build-time processor and bean registration
- **integration-tests** — Quarkus integration tests

See [CLAUDE.md](../CLAUDE.md) for package structure and coding standards. For extension architecture (Jandex, deployment module, bean registration), see [architecture.md](architecture.md).

## Testing

See [testing.md](testing.md) for unit and integration testing patterns.

## Updating the Maven Wrapper

To change the Maven version or regenerate wrapper files (requires Maven installed):

```bash
mvn -N wrapper:wrapper -Dmaven=3.9.9 -Dtype=bin
chmod +x mvnw
```

Commit `mvnw`, `mvnw.cmd`, `.mvn/wrapper/maven-wrapper.properties`, and `.mvn/wrapper/maven-wrapper.jar`.
