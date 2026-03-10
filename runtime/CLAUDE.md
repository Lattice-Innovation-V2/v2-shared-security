# Runtime Module - Development Rules

> Inherits all rules from root [CLAUDE.md](../CLAUDE.md) and [.cursor/rules/](.cursor/rules/)

## Module Purpose
Contains all CDI beans, filters, utilities, and configuration interfaces that execute at application runtime.

## Package Structure
- **auth/**: HybridTenantConfigResolver, ForwardedAuthFilter, InternalOnlyFilter
- **identity/**: IdentityUtils, CallerType, CallerScope, HierarchyResolver, MerchantAccessResolver, MerchantHierarchyCache
- **gcp/**: GcpTokenProvider, DefaultGcpTokenProvider, GcpIamClientFilter
- **config/**: LatticeSecurityConfig (@ConfigMapping root)

## Runtime-Specific Rules

### Bean Lifecycle
- Inject `LatticeSecurityConfig` for configuration access via constructor
- Validate required-when-enabled config in constructor
- Fail fast with `IllegalStateException` if invalid config

### Configuration Access
- Inject `LatticeSecurityConfig` root interface via constructor
- Access nested config via methods: `config.iap()`, `config.gcip()`, `config.forwardedAuth()`, etc.
- NEVER read properties directly with `@ConfigProperty`

### Error Handling
- Validate config in constructors only
- Message format: "latticepay.security.X.Y is required when latticepay.security.X.enabled=true"
- Include exact property name and context

### Logging Levels
- `DEBUG`: Request-level flow (tenant resolution, token extraction)
- `INFO`: Bean initialization, config loaded
- `WARN`: Config warnings (defaults, deprecated)
- `ERROR`: Rare - prefer fail fast

## Reference Implementations

Study these for patterns:
- **AtomicReference lazy init**: `HybridTenantConfigResolver`, `DefaultGcpTokenProvider`
- **Filter + validation**: `ForwardedAuthFilter`, `InternalOnlyFilter`
- **@ConfigMapping**: `LatticeSecurityConfig`
- **JWT claim extraction**: `IdentityUtils`
- **Unit tests**: `runtime/src/test/java` (mocking patterns)
- **Merchant hierarchy**: `MerchantHierarchyCache`, `MerchantAccessResolver`, `HierarchyResolver.resolveAccessibleMerchantIds`
