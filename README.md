# Latticepay Security Library

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=latticeorg_latticepay-security&metric=alert_status&token=660aa2a4d491f2abbed6c66e4868ab45b27c4c4a)](https://sonarcloud.io/summary/new_code?id=latticeorg_latticepay-security)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=latticeorg_latticepay-security&metric=coverage&token=660aa2a4d491f2abbed6c66e4868ab45b27c4c4a)](https://sonarcloud.io/summary/new_code?id=latticeorg_latticepay-security)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=latticeorg_latticepay-security&metric=security_rating&token=660aa2a4d491f2abbed6c66e4868ab45b27c4c4a)](https://sonarcloud.io/summary/new_code?id=latticeorg_latticepay-security)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=latticeorg_latticepay-security&metric=sqale_rating&token=660aa2a4d491f2abbed6c66e4868ab45b27c4c4a)](https://sonarcloud.io/summary/new_code?id=latticeorg_latticepay-security)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=latticeorg_latticepay-security&metric=ncloc&token=660aa2a4d491f2abbed6c66e4868ab45b27c4c4a)](https://sonarcloud.io/summary/new_code?id=latticeorg_latticepay-security)


![Java](https://img.shields.io/badge/Java-25-orange?logo=openjdk&logoColor=white)
![Quarkus](https://img.shields.io/badge/Quarkus-3.31.2-blue?logo=quarkus&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-18-336791?logo=postgresql&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-7-DC382D?logo=redis&logoColor=white)
![GraalVM](https://img.shields.io/badge/GraalVM-Native-green?logo=oracle&logoColor=white)

Quarkus extension for LatticePay security: Hybrid OIDC (IAP + GCIP), ForwardedAuthFilter, IdentityUtils, and GCP IAM service-to-service authentication.

## Features
- **Hybrid OIDC Multi-tenant Authentication**: IAP for internal users, GCIP/Firebase for external customers

- **Swagger-UI Protection**: Restricts `/q/docs`, `/q/openapi` to internal users only
- **ForwardedAuthFilter**: Secure `X-Forwarded-Authorization` handling from trusted proxies
- **IdentityUtils**: Extract identity from JWT (email, entity_id, caller type)
- **GCP IAM Service-to-Service Auth**: Outbound filter for GCP IAM identity tokens on REST clients

## Quick Start

Add the dependency and configure at least one auth method. See [docs/usage.md](docs/usage.md).

## Swagger-UI Protection

InternalOnlyFilter restricts documentation endpoints to internal users (`@latticepay.io`). Default: enabled. See [docs/usage.md](docs/usage.md) for configuration and path setup.

## Configuration Reference

See [Configuration reference](docs/usage.md#configuration-reference) in Usage.

## Documentation

- [Architecture](docs/architecture.md) — Authentication flows, tenant resolution, extension guide
- [Usage](docs/usage.md) — Dependency, configuration, code patterns
- [Testing](docs/testing.md) — Unit and integration patterns
- [Development](docs/development.md) — Build, layout
- [Release Process](docs/release-process.md) — Publishing and versioning

## Requirements

Java 25+, Quarkus 3.31.2+

## License

Internal LatticePay library.
