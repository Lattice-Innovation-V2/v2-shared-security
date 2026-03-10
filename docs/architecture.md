---
connie-title: "latticepay-security: Architecture"
---

# Latticepay Security Library - Architecture

## Authentication Flows

The library handles two inbound authentication flows (user-facing) and one outbound flow (service-to-service):

### Flow 1: IAP - Admin Portal (Internal Users)

- **Use case**: Google Workspace users accessing `admin.latticepay.io`
- **Header**: `x-goog-iap-jwt-assertion`
- **Issuer**: `https://cloud.google.com/iap`
- **JWKS**: `https://www.gstatic.com/iap/verify/public_key-jwk`
- **Signature**: ES256
- **Configuration**: `latticepay.security.iap.client-id` (required when enabled)

### Flow 2: GCIP/Firebase - External API Customers

- **Use case**: External customers accessing `api.latticepay.io`
- **Header**: `Authorization: Bearer <token>`
- **Issuer**: `https://securetoken.google.com/{project-id}`
- **JWKS**: OIDC discovery from issuer URL
- **Signature**: RS256
- **Configuration**: `latticepay.security.gcip.project-id` (required when enabled)

### Flow 2b: Dev tenant - Self-issued JWT (local development only)

- **Use case**: Local dev and Swagger UI with self-issued tokens (e.g. JwtTokenGenerator, jwt-cli)
- **Header**: `Authorization: Bearer <token>` (same as GCIP; selection is by decoding token and matching `iss`)
- **Issuer**: Configurable (e.g. `https://dev.issuer.local`)
- **Verification**: PEM public key from config (no OIDC discovery)
- **Configuration**: `latticepay.security.dev.enabled`, `dev.issuer`, `dev.public-key-location` (use in `%dev` only)

### Flow 2c: WIF - Workforce Identity Federation

- **Use case**: External customers using STS token exchange to obtain GCP WIF tokens
- **Header**: `Authorization: Bearer <token>` (same as GCIP; selection is by decoding token and matching `iss`)
- **Issuer**: `https://sts.googleapis.com`
- **JWKS**: Static endpoint (no OIDC discovery) — defaults to `https://www.googleapis.com/oauth2/v3/certs`
- **Signature**: RS256
- **Configuration**: `latticepay.security.wif.enabled`, `wif.audience`, `wif.pool-id` (required when enabled); `wif.jwks-url` (optional override)

### Flow 3: GCP IAM - Internal Service-to-Service (Outbound Only)

- **Use case**: Internal services calling each other over private network
- **Outbound**: `GcpIamClientFilter` attaches a GCP IAM identity token to the outbound request
- **Inbound validation**: Handled by **Cloud Run infrastructure** (IAM `roles/run.invoker`), NOT by the library
- **Configuration**: `latticepay.security.gcp-service-auth.enabled`, `latticepay.security.gcp-service-auth.target-audience`

## Tenant Resolution Sequence

```
Request arrives
    ↓
ForwardedAuthFilter (if enabled)
    ↓ Copies X-Forwarded-Authorization → Authorization (if trusted)
    ↓
HybridTenantConfigResolver.resolve()
    ↓
Has x-goog-iap-jwt-assertion header?
    ├─ Yes → IAP tenant (if enabled)
    └─ No → Dev enabled and Bearer present and token iss = dev issuer?
        ├─ Yes → Dev tenant (if enabled)
        └─ No → WIF enabled and Bearer present and token iss = https://sts.googleapis.com?
            ├─ Yes → WIF tenant (if enabled)
            └─ No → Has Authorization: Bearer or X-Forwarded-Authorization?
                ├─ Yes → GCIP tenant (if enabled)
                └─ No → null (Quarkus returns 401)
```

## Service-to-Service Authentication Model

**Important**: The library does NOT provide an inbound OIDC tenant for service-to-service authentication. Cloud Run handles this at the infrastructure level.

### How It Works

1. **Service A** calls **Service B**'s internal Cloud Run URL
2. `GcpIamClientFilter` (outbound, from the library) attaches a GCP IAM identity token
3. **Cloud Run** validates the token and checks `roles/run.invoker` permission **before** the request reaches Service B's code
4. **Service B** receives an already-authenticated request -- no app-level token validation needed

### IAM Authorization

Authorization is managed via GCP IAM policy:
- Grant `roles/run.invoker` only to specific service accounts
- This is auditable, centralized, and requires no redeployment to change
- No application-level allowlisting needed

---

## Extension Architecture (Quarkus 3.31.2 + Java 25)

Guide for creating another Quarkus extension.

### Why This Is a Quarkus Extension

This library follows the **Quarkus Extension pattern** to provide CDI beans to consuming applications. This requires specific build configuration that differs from regular libraries.

### Required Build Components

#### 1. Jandex Maven Plugin (REQUIRED for extensions)

```xml
<plugin>
    <groupId>io.smallrye</groupId>
    <artifactId>jandex-maven-plugin</artifactId>
    <version>3.2.3</version>
</plugin>
```

**Why Jandex is REQUIRED:**
- Consuming applications cannot auto-index external JARs
- `@ConfigMapping` interfaces must be indexed to be injectable
- CDI bean discovery requires indexed annotations
- Native image compilation needs compile-time metadata
- **Official Quarkus Extension Guide mandates this**

Without Jandex, consuming apps see:
```
❌ Unsatisfied dependency for type LatticeSecurityConfig
❌ Manual quarkus.index-dependency configuration required
❌ Native compilation failures
```

#### 2. Quarkus Extension Maven Plugin

Generates `META-INF/quarkus-extension.properties` linking runtime → deployment artifacts.

#### 3. Deployment Module

The `latticepay-security-deployment` module registers all CDI beans at build time via `LatticeSecurityProcessor`:

```java
@BuildStep
AdditionalBeanBuildItem registerBeans() {
    return AdditionalBeanBuildItem.builder()
            .addBeanClasses(
                    ForwardedAuthFilter.class,
                    HybridTenantConfigResolver.class,
                    IdentityUtils.class,
                    DefaultGcpTokenProvider.class,
                    GcpIamClientFilter.class)
            .setUnremovable()
            .build();
}
```

**Note:** `@ConfigMapping` interfaces (like `LatticeSecurityConfig`) are NOT registered here - they're automatically handled by SmallRye Config when Jandex-indexed.

### Key Dependencies

**Runtime module uses Quarkus libraries first:**
- `quarkus-arc` - CDI container
- `quarkus-oidc` - OIDC authentication
- `quarkus-rest-client` - JAX-RS client with native image support (NOT `jakarta.ws.rs-api`)
- `quarkus-vertx-http` - HTTP filters

**Third-party libraries (not in Quarkus BOM):**
- `google-auth-library-oauth2-http:1.24.1` - GCP IAM authentication

**Deployment module mirrors runtime dependencies:**
- Every `quarkus-*` runtime dependency requires a corresponding `quarkus-*-deployment` dependency
- Example: `quarkus-rest-client` → `quarkus-rest-client-deployment`

### Testing Standards (Quarkus 3.31.2)

**Use modern Quarkus 3.31+ artifacts:**
```xml
<!-- ✅ Correct (Quarkus 3.31+) -->
<dependency>
    <groupId>io.quarkus</groupId>
    <artifactId>quarkus-junit</artifactId>
</dependency>

<!-- ❌ Deprecated in 3.31 -->
<dependency>
    <groupId>io.quarkus</groupId>
    <artifactId>quarkus-junit</artifactId>
</dependency>
```

**Test Stack:**
- `quarkus-junit` - `@QuarkusTest` support
- `quarkus-junit-mockito` - Mockito integration
- `quarkus-test-security-oidc` - Security testing
- `rest-assured` - HTTP API testing (Quarkus default)

**Unit Test Pattern (Mockito):**
```java
@ExtendWith(MockitoExtension.class)
class IdentityUtilsTest {
    @Mock
    private LatticeSecurityConfig mockConfig;

    @Nested
    class GetEmailTests {
        @Test
        void shouldReturnEmailClaim() {
            // Test implementation
        }
    }
}
```

**Integration Test Pattern:**
```java
@QuarkusTest
class LatticeSecurityIT {
    @Inject
    IdentityUtils identityUtils;

    @Test
    void shouldInjectBeans() {
        assertNotNull(identityUtils);
    }
}
```

### Consumer Usage

See [Usage](usage.md) for dependency and configuration.
