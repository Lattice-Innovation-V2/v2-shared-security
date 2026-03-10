# Latticepay Security Library - Overview

> Quarkus extension providing authentication/authorization infrastructure for Latticepay services

## Tech Stack
- **Java 25**: Records, pattern matching, enhanced switch, text blocks
- **Quarkus 3.31.2**: Extension architecture (deployment + runtime separation)
- **JUnit 6**: Testing framework
- **GraalVM Native**: Fully compatible

## Module-Specific Guides
- **[runtime/CLAUDE.md](runtime/CLAUDE.md)** - Runtime bean development rules
- **[deployment/CLAUDE.md](deployment/CLAUDE.md)** - Bean registration and build step rules
- **[integration-tests/CLAUDE.md](integration-tests/CLAUDE.md)** - Integration testing rules

## Architecture Rules
Detailed coding standards in [.cursor/rules/](.cursor/rules/):
- **[global.mdc](.cursor/rules/global.mdc)** - Global standards, extension architecture
- **[project-standards.mdc](.cursor/rules/project-standards.mdc)** - Java 25, Quarkus, testing
- **[library-context.mdc](.cursor/rules/library-context.mdc)** - Library context, patterns

## Extension Architecture

### Three-Module Structure
- **runtime/**: CDI beans, filters, utilities (runtime execution)
- **deployment/**: Build processors (build-time only)
- **integration-tests/**: Consumer simulation tests

### Critical Rules
1. **Runtime**: All beans `@ApplicationScoped` with constructor injection
2. **Deployment**: Register ALL runtime beans via `AdditionalBeanBuildItem` with `.setUnremovable()`
3. **Never mix**: Deployment code in deployment, runtime code in runtime

## Package Structure
- **auth/**: HybridTenantConfigResolver, ForwardedAuthFilter, InternalOnlyFilter
- **identity/**: IdentityUtils, CallerType, CallerScope, HierarchyResolver, MerchantAccessResolver, MerchantHierarchyCache
- **gcp/**: GcpTokenProvider, DefaultGcpTokenProvider, GcpIamClientFilter
- **config/**: LatticeSecurityConfig (@ConfigMapping root)

## Configuration

### Root Interface
`LatticeSecurityConfig` with `@ConfigMapping(prefix = "latticepay.security")`

### Nested Groups
- `Iap`: IAP tenant config
- `Gcip`: GCIP tenant config
- `ForwardedAuth`: Forwarded auth filter config
- `GcpServiceAuth`: Outbound GCP IAM auth config
- `MerchantHierarchy`: Redis-backed merchant hierarchy cache config

### Feature Flags
All features opt-in via `<prefix>.<feature>.enabled` (default: `false`)

### Required-When-Enabled
Use `Optional<T>`, validate in constructors, fail fast with `IllegalStateException`

## Development Workflow

### Adding New Runtime Bean
1. Create in `runtime/` with `@ApplicationScoped` and constructor injection
2. Register in `deployment/LatticeSecurityProcessor` via `AdditionalBeanBuildItem`
3. Add unit tests in `runtime/src/test/java`
4. Add integration test in `integration-tests/` verifying bean is injectable
5. Document in appropriate module CLAUDE.md

### Adding New Configuration
1. Add nested interface to `LatticeSecurityConfig`
2. Use `Optional<T>` for required-when-enabled properties
3. Validate in bean constructor, throw `IllegalStateException` if invalid
4. Add integration test verifying validation works
5. Update consumer documentation in `docs/usage.md`

## Java 25 Patterns

### Thread Safety
Use `AtomicReference` for lazy initialization. See `HybridTenantConfigResolver` and `DefaultGcpTokenProvider` for reference implementations.

### Modern Java Features
- Records for immutable data
- Pattern matching in switch/instanceof
- Text blocks for multi-line strings
- Markdown syntax in JavaDocs (JEP 467)

## Testing

### Unit Tests
- Location: `runtime/src/test/java`
- Framework: JUnit 6 + Mockito
- Mock: `JsonWebToken`, `LatticeSecurityConfig`, external libraries
- Organization: Use `@Nested` classes

### Integration Tests
- Location: `integration-tests/`
- Framework: `@QuarkusTest` with `@TestSecurity` and `@OidcSecurity`
- Verify: Bean registration, config validation, end-to-end flows

## Library Boundaries
❌ No database, REST endpoints, MapStruct, business logic
✅ Auth filters, tenant resolution, identity utils, config, token providers, merchant hierarchy cache (Redis + SPI)

## Documentation

### For AI Agents (Development)
- **[runtime/CLAUDE.md](runtime/CLAUDE.md)** - Runtime bean development guide
- **[deployment/CLAUDE.md](deployment/CLAUDE.md)** - Build-time development guide
- **[integration-tests/CLAUDE.md](integration-tests/CLAUDE.md)** - Integration testing guide
- **[.cursor/rules/](.cursor/rules/)** - Coding standards (global, project, library context)

### For Library Consumers (Usage)
- **[docs/usage.md](docs/usage.md)** - Dependency setup, configuration, usage patterns
- **[docs/architecture.md](docs/architecture.md)** - Authentication flows, tenant resolution
- **[docs/development.md](docs/development.md)** - Building and testing
- **API Reference**: Javadoc in `io.latticepay.security` package
