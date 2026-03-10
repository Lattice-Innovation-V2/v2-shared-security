# Deployment Module - Development Rules

> Inherits all rules from root [CLAUDE.md](../CLAUDE.md) and [.cursor/rules/](.cursor/rules/)

## Module Purpose
Contains build processors that register runtime beans and perform build-time augmentation. Executes during application build, NOT at runtime.

## Key File
`LatticeSecurityProcessor.java` - Main build processor with `@BuildStep` methods

## Deployment-Specific Rules

### Build Step Requirements
- Produce `FeatureBuildItem` for extension feature tracking
- Register all `@ApplicationScoped` runtime beans via `AdditionalBeanBuildItem`
- Always use `.setUnremovable()` to prevent Arc from removing beans
- Keep `@Recorder` methods lean with only serializable data

### Build vs Runtime Separation
- **Build-Time**: `@BuildStep` methods, bean registration, feature detection
- **Runtime**: Never put runtime logic here - it runs during compilation
- Use `@Record(ExecutionTime.RUNTIME_INIT)` only when passing build data to runtime

### Critical Rules
❌ **Never**:
- Put runtime logic in deployment module
- Use non-serializable data in recorders
- Forget to register new runtime beans
- Skip `.setUnremovable()` on bean registration

✅ **Always**:
- Register all new `@ApplicationScoped` runtime beans
- Test native builds: `./mvnw clean install -Dnative`
- Verify beans are injectable in integration-tests

## Module Dependencies
- **Depends on**: `runtime` (processor references runtime classes)
- **NOT depended on by**: `runtime` (one-way dependency)
- Consumers don't depend on deployment - auto-registered via Quarkus

## Reference Implementation
See `LatticeSecurityProcessor` for bean registration and feature detection patterns.
