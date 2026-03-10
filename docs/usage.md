---
connie-title: "latticepay-security: Usage Guide"
---

# Latticepay Security Library - Usage Guide

> For services that depend on this library

## Adding the Dependency

Add to your service's `pom.xml`:

```xml
<dependency>
    <groupId>io.latticepay</groupId>
    <artifactId>latticepay-security</artifactId>
    <version>${latticepay-security.version}</version>
</dependency>
```

No `quarkus.index-dependency` required; beans are registered by the deployment module.

### Repository

Use HTTPS for GCP Artifact Registry (no wagon):

```xml
<repositories>
    <repository>
        <id>artifact-registry</id>
        <url>https://us-central1-maven.pkg.dev/latticepay-prod/maven-libs</url>
        <releases><enabled>true</enabled></releases>
        <snapshots><enabled>true</enabled></snapshots>
    </repository>
</repositories>

<pluginRepositories>
    <pluginRepository>
        <id>artifact-registry</id>
        <url>https://us-central1-maven.pkg.dev/latticepay-prod/maven-libs</url>
        <releases><enabled>true</enabled></releases>
        <snapshots><enabled>true</enabled></snapshots>
    </pluginRepository>
</pluginRepositories>
```

## Configuration

### Minimum Required Configuration

Configure at least one authentication method in `application.properties`:

#### Option 1: IAP (Internal Users)
```properties
latticepay.security.iap.enabled=true
latticepay.security.iap.client-id=${IAP_CLIENT_ID}
```

#### Option 2: GCIP (External Users)
```properties
latticepay.security.gcip.enabled=true
latticepay.security.gcip.project-id=${GCP_PROJECT_ID:MISSING_GCP_PROJECT_ID}
```
If `GCP_PROJECT_ID` is not set, the extension fails at startup with an actionable error. No need to add your own validator.

#### Both Methods
You can configure both methods - tenant resolution is automatic based on request headers:
```properties
# Internal users via IAP
latticepay.security.iap.enabled=true
latticepay.security.iap.client-id=${IAP_CLIENT_ID}

# External users via GCIP
latticepay.security.gcip.enabled=true
latticepay.security.gcip.project-id=${GCP_PROJECT_ID:MISSING_GCP_PROJECT_ID}

# Internal domain for caller type detection (default: @latticepay.io)
latticepay.security.internal-domain=@latticepay.io
```

### Opt-In Features

#### ForwardedAuthFilter
Copies `X-Forwarded-Authorization` header to `Authorization` header from trusted proxy IPs:

```properties
latticepay.security.forwarded-auth.enabled=true
latticepay.security.forwarded-auth.trusted-proxy-ips=10.0.0.0/8,172.16.0.0/12
```

**Use case**: Cloud Load Balancer adds authentication headers that need to be forwarded to the service.

#### GCP Service-to-Service Authentication
Automatically attaches GCP IAM identity tokens to outbound REST client requests:

```properties
latticepay.security.gcp-service-auth.enabled=true
latticepay.security.gcp-service-auth.target-audience=https://target-service-xyz.run.app
```

**Use case**: Your service calls another internal service protected by Cloud Run IAM (`roles/run.invoker`).

#### Swagger / OpenAPI protection (InternalOnlyFilter)
Restricts access to Quarkus documentation endpoints to internal users only (`@latticepay.io`). External users receive **403 Forbidden** on `/q/docs` and `/q/openapi`. Enabled by default. If the security config is not available at runtime (e.g. config mapping not registered), the filter fails closed and returns **503 Service Unavailable** with "Security configuration unavailable".

```properties
# Default: true. Set to false to allow external users to access /q/docs and /q/openapi
latticepay.security.swagger-protection.enabled=true
```

**Use case**: Keep API documentation (Swagger UI, OpenAPI spec) visible only to internal users. For custom paths (e.g. `/admin/*`, `/internal/*`), enforce in your own resources using `IdentityUtils.getCallerType(jwt)` and return 403 for non-internal users.

#### Merchant Hierarchy Resolution (resolveAccessibleMerchantIds)

For integrator callers, resolves the set of merchant IDs they may access (for get-by-id and list filtering). Uses Redis cache with SPI fallback on miss. Hierarchy is determined by `parentId` in your DB (top-level integrator vs sub-integrator), not JWT claims.

```properties
latticepay.security.merchant-hierarchy.enabled=true
quarkus.redis.hosts=redis://your-redis-host:6379
```

**Requirements:**
- Implement `MerchantAccessResolver` (DB/API lookup) as a CDI bean
- Call `MerchantHierarchyCache` write methods on entity lifecycle events

```java
@ApplicationScoped
public class DbMerchantAccessResolver implements MerchantAccessResolver {
    @Override
    public Set<UUID> resolveMerchantIds(UUID integratorId) {
        // Top-level (parentId=null): direct merchants + sub-integrator merchants (full subtree)
        // Sub-integrator (parentId!=null): only direct merchants
        return merchantRepository.findAccessibleMerchantIds(integratorId);
    }
}
```

```java
@Inject HierarchyResolver hierarchyResolver;
@Inject MerchantHierarchyCache cache;

Set<UUID> accessibleIds = hierarchyResolver.resolveAccessibleMerchantIds(securityContext);
if (accessibleIds.isEmpty() && !scope.isAdmin()) {
    return Response.status(403).build();  // or skip filtering for admin
}
// get-by-id: if (!accessibleIds.contains(merchantId)) return 404;
// list: filter results to accessibleIds
```

**Cache writes** (on merchant create/update/delete):

```java
cache.addMerchant(integratorId, merchantId);
cache.removeMerchant(integratorId, merchantId);
cache.evict(parentIntegratorId);  // when sub-integrator's merchants change
```

#### Dev tenant (self-issued JWT, local development only)

Allows accepting Bearer tokens issued by a local dev issuer (e.g. `https://dev.issuer.local`) with verification via a PEM public key—no OIDC discovery. **Intended for `%dev` only.** The dev tenant is available only when the application runs in Quarkus dev or test mode; the extension registers the required `ActiveProfileSupplier` bean only in those modes, and the resolver depends on it. In production (NORMAL) builds, the dev tenant cannot be activated regardless of configuration. When enabled, the resolver decodes the Bearer token (without verifying the signature), reads the `iss` claim, and if it matches the configured dev issuer, selects the dev tenant. IAP and GCIP behavior is unchanged.

```properties
# Enable only in dev profile
%dev.latticepay.security.dev.enabled=true
%dev.latticepay.security.dev.issuer=https://dev.issuer.local
%dev.latticepay.security.dev.public-key-location=test-publicKey.pem
# Optional: audience to accept (default: any)
%dev.latticepay.security.dev.audience=any
```

Place the matching **public** key (e.g. `test-publicKey.pem`) on the classpath (e.g. `src/main/resources/`) or use an absolute file path. Use the same issuer and **private** key in your token generator (e.g. `JwtTokenGenerator`, jwt-cli) so tokens are accepted by the dev tenant.

**Use case**: Local development and Swagger UI testing with self-issued JWTs without IAP/GCIP.

### Configuration Reference

All configuration under `latticepay.security`:

| Property | Default | Description |
|----------|---------|--------------|
| `latticepay.security.internal-domain` | `@latticepay.io` | Email domain suffix for internal users |
| `latticepay.security.entity-id-claim` | `entity_id` | JWT claim name for entity/tenant ID |
| `latticepay.security.role-claim` | `role` | JWT claim name for authorization role (GCIP tokens only) |
| `latticepay.security.swagger-protection.enabled` | `true` | Restrict `/q/docs`, `/q/openapi` to internal users |
| `latticepay.security.forwarded-auth.enabled` | `false` | Enable ForwardedAuthFilter |
| `latticepay.security.forwarded-auth.trusted-proxy-ips` | `NONE` | Comma-separated trusted proxy IPs |
| `latticepay.security.iap.enabled` | `false` | Enable IAP tenant |
| `latticepay.security.iap.client-id` | - | OAuth2 client ID (required when IAP enabled) |
| `latticepay.security.gcip.enabled` | `false` | Enable GCIP tenant |
| `latticepay.security.gcip.project-id` | - | GCP/Firebase project ID (required when GCIP enabled). Use `${GCP_PROJECT_ID:MISSING_GCP_PROJECT_ID}` for fail-fast if unset. |
| `latticepay.security.gcp-service-auth.enabled` | `false` | Enable outbound GCP IAM auth filter |
| `latticepay.security.gcp-service-auth.target-audience` | - | Target audience for outbound identity tokens |
| `latticepay.security.merchant-hierarchy.enabled` | `false` | Enable Redis-backed merchant hierarchy cache |
| `latticepay.security.merchant-hierarchy.redis-key-prefix` | `latticepay:hierarchy` | Redis key prefix for cache entries |
| `latticepay.security.merchant-hierarchy.ttl` | `PT1H` | Cache entry TTL (ISO-8601 duration) |
| `latticepay.security.dev.enabled` | `false` | Enable dev tenant (self-issued JWT; use in %dev only) |
| `latticepay.security.dev.issuer` | - | Issuer that must match JWT `iss` (e.g. `https://dev.issuer.local`); required when dev enabled |
| `latticepay.security.dev.public-key-location` | - | Path to PEM public key (classpath or file); required when dev enabled |
| `latticepay.security.dev.audience` | `any` | Audience to accept for dev tokens |

## Usage in Code

### Role Augmentation (Automatic)

`LatticeRolesAugmentor` runs automatically on every authenticated request. It populates roles into the Quarkus `SecurityIdentity`:

| Token Source | Role Assignment |
|---|---|
| IAP (internal `@latticepay.io` email) | `"admin"` |
| GCIP (external) | Read from `role` claim in JWT |

No configuration required — the augmentor is registered by the deployment module. GCIP tokens must include a `role` claim (set during Firebase user provisioning). Valid role values: `"admin"`, `"integrator"`, `"merchant"`.

### Authenticating Requests

`@Authenticated` on resource classes, `@RolesAllowed` on methods:

```java
@Path("/merchants")
@Authenticated
public class MerchantResource {

    @GET
    @RolesAllowed({"admin", "integrator"})
    public Response listMerchants() { ... }

    @DELETE
    @Path("/{id}")
    @RolesAllowed("admin")
    public Response deleteMerchant(@PathParam("id") UUID id) { ... }
}
```

### Resolving Caller Identity with CallerScope

`HierarchyResolver` resolves the authenticated caller into a `CallerScope` record. This is the canonical way to determine caller identity for authorization and data filtering.

```java
@Path("/merchants")
@Authenticated
public class MerchantResource {

    @Inject HierarchyResolver hierarchyResolver;
    @Context SecurityContext securityContext;

    @GET
    @RolesAllowed({"admin", "integrator"})
    public Response listMerchants() {
        CallerScope scope = hierarchyResolver.resolve(securityContext);

        if (scope.isAdmin()) {
            return Response.ok(listAllMerchants()).build();
        }
        UUID integratorId = scope.requireEntityId();
        return Response.ok(listByIntegrator(integratorId)).build();
    }
}
```

**CallerScope fields:**

| Field | Type | Description |
|---|---|---|
| `role` | `String` | `"admin"`, `"integrator"`, `"merchant"`, or `null` (anonymous) |
| `entityId` | `UUID` | Entity/tenant ID from JWT, or `null` (admins) |
| `email` | `String` | Caller's email address |

**Convenience methods:** `isAdmin()`, `isIntegrator()`, `isMerchant()`, `isAnonymous()`, `requireEntityId()` (throws `NotAuthorizedException` if null).

### Low-Level Identity Access

`IdentityUtils` provides direct JWT claim access when `CallerScope` is not needed:

```java
@Inject IdentityUtils identityUtils;
@Inject JsonWebToken jwt;

String email = identityUtils.getEmail(jwt);
Optional<UUID> entityId = identityUtils.getEntityId(jwt);
Optional<String> role = identityUtils.getRole(jwt);
CallerType callerType = identityUtils.getCallerType(jwt);
boolean internal = identityUtils.isInternalUser(jwt);
```

### GCP Service-to-Service Calls

REST client interfaces; `GcpIamClientFilter` attaches tokens automatically:

```java
@RegisterRestClient(configKey = "merchant-service")
public interface MerchantServiceClient {

    @GET
    @Path("/merchants/{id}")
    MerchantDTO getMerchant(@PathParam("id") UUID id);
}
```

```properties
# Configure the REST client
quarkus.rest-client.merchant-service.url=https://merchant-service-xyz.run.app

# GCP IAM token automatically attached by GcpIamClientFilter
latticepay.security.gcp-service-auth.enabled=true
latticepay.security.gcp-service-auth.target-audience=https://merchant-service-xyz.run.app
```

Filter uses ADC; attaches `Authorization: Bearer`; refreshes automatically.

## Testing Your Service

### Unit Tests

Mock `HierarchyResolver` returning `CallerScope` instances:

```java
@ExtendWith(MockitoExtension.class)
class MerchantServiceTest {

    @Mock HierarchyResolver hierarchyResolver;
    @Mock SecurityContext securityContext;

    @Test
    void adminShouldListAllMerchants() {
        var scope = new CallerScope("admin", null, "admin@latticepay.io");
        when(hierarchyResolver.resolve(securityContext)).thenReturn(scope);
        // ...
    }

    @Test
    void integratorShouldListOwnMerchants() {
        UUID integratorId = UUID.randomUUID();
        var scope = new CallerScope("integrator", integratorId, "user@example.com");
        when(hierarchyResolver.resolve(securityContext)).thenReturn(scope);
        // ...
    }
}
```

### Integration Tests

`@TestSecurity` with `roles` matching augmentor output, and `@OidcSecurity` for JWT claims:

```java
@QuarkusTest
class MerchantResourceIT {

    @Test
    @TestSecurity(user = "admin@latticepay.io", roles = {"admin"})
    @OidcSecurity(claims = @Claim(key = "email", value = "admin@latticepay.io"))
    void adminShouldListAllMerchants() {
        given()
            .when().get("/merchants")
            .then()
            .statusCode(200);
    }

    @Test
    @TestSecurity(user = "user@example.com", roles = {"integrator"})
    @OidcSecurity(claims = {
        @Claim(key = "email", value = "user@example.com"),
        @Claim(key = "entity_id", value = "123e4567-e89b-12d3-a456-426614174000"),
        @Claim(key = "role", value = "integrator")
    })
    void integratorShouldListOwnMerchants() {
        given()
            .when().get("/merchants")
            .then()
            .statusCode(200);
    }
}
```

**Important:** The `roles` parameter in `@TestSecurity` must match the role that `LatticeRolesAugmentor` would assign in production. Use `"admin"` for internal users, `"integrator"` or `"merchant"` for external users.

## Troubleshooting

| Error | Fix |
|-------|-----|
| `Unsatisfied dependency for type IdentityUtils` | Use `latticepay-security` (not `-deployment`) |
| `latticepay.security.iap.client-id is required when enabled=true` | Set required props when enabling a feature |
| `Failed to obtain GCP IAM token` | ADC: `gcloud auth application-default login` locally; Cloud Run needs service account |
| `401` with `X-Forwarded-Authorization` | Add requesting IP to `forwarded-auth.trusted-proxy-ips` |
| `503` "Security configuration unavailable" | Ensure `LatticeSecurityConfig` is resolvable (extension deployed; no classloader/config mapping issues). Filter fails closed when config is unavailable. |
| `403` on `@RolesAllowed` endpoints | Ensure `roles` in `@TestSecurity` matches augmentor output (`"admin"`, `"integrator"`, `"merchant"`). In production, verify GCIP tokens include the `role` claim. |

## See Also

- [Architecture](architecture.md) - Authentication flows and tenant resolution
- [Development Guide](development.md) - Building and testing the library
- [API Reference](../runtime/src/main/java/io/latticepay/security/) - JavaDoc for all public APIs
