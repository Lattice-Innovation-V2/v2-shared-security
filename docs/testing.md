---
connie-title: "latticepay-security: Testing Guide"
---

# Latticepay Security Library - Testing Guide

## Unit Testing

### IdentityUtils

```java
import io.latticepay.security.identity.IdentityUtils;
import io.latticepay.security.config.LatticeSecurityConfig;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class IdentityUtilsTest {
    
    @Mock
    private LatticeSecurityConfig mockConfig;
    @Mock
    private JsonWebToken jwt;
    
    private IdentityUtils identityUtils;
    
    @BeforeEach
    void setUp() {
        when(mockConfig.internalDomain()).thenReturn("@latticepay.io");
        when(mockConfig.entityIdClaim()).thenReturn("entity_id");
        identityUtils = new IdentityUtils(mockConfig);
    }
    
    @Test
    void testIsInternalUser() {
        when(jwt.getClaim("email")).thenReturn("user@latticepay.io");
        assertTrue(identityUtils.isInternalUser(jwt));
    }
}
```

## Integration Testing

### @TestSecurity and @OidcSecurity

```java
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.security.TestSecurity;
import io.quarkus.test.security.oidc.Claim;
import io.quarkus.test.security.oidc.OidcSecurity;

@QuarkusTest
class MyResourceIT {
    
    @Test
    @TestSecurity(user = "admin@latticepay.io")
    @OidcSecurity(claims = {
        @Claim(key = "email", value = "admin@latticepay.io")
    })
    void testAsInternalUser() { /* ... */ }
    
    @Test
    @TestSecurity(user = "user@external.com")
    @OidcSecurity(claims = {
        @Claim(key = "email", value = "user@external.com"),
        @Claim(key = "entity_id", value = "019478a1-0001-7000-8000-000000000001")
    })
    void testAsExternalUser() { /* ... */ }
}
```

### Test Configuration

Add to `src/test/resources/application.properties`:

```properties
# Latticepay Security Library Configuration (test)
latticepay.security.internal-domain=@latticepay.io
latticepay.security.entity-id-claim=entity_id
latticepay.security.forwarded-auth.enabled=false
latticepay.security.iap.enabled=true
latticepay.security.iap.client-id=test-client-id
latticepay.security.gcip.enabled=true
latticepay.security.gcip.project-id=test-project
latticepay.security.gcp-service-auth.enabled=false
```

## Mocking Patterns

### Mocking LatticeSecurityConfig

```java
@Mock
private LatticeSecurityConfig mockConfig;
@Mock
private LatticeSecurityConfig.Iap mockIap;
@Mock
private LatticeSecurityConfig.Gcip mockGcip;
@Mock
private LatticeSecurityConfig.ForwardedAuth mockForwardedAuth;
@Mock
private LatticeSecurityConfig.GcpServiceAuth mockGcpServiceAuth;

@BeforeEach
void setUp() {
    when(mockConfig.internalDomain()).thenReturn("@latticepay.io");
    when(mockConfig.entityIdClaim()).thenReturn("entity_id");
    when(mockConfig.iap()).thenReturn(mockIap);
    when(mockConfig.gcip()).thenReturn(mockGcip);
    when(mockConfig.forwardedAuth()).thenReturn(mockForwardedAuth);
    when(mockConfig.gcpServiceAuth()).thenReturn(mockGcpServiceAuth);
    when(mockIap.enabled()).thenReturn(true);
    when(mockGcip.enabled()).thenReturn(true);
}
```

### Mocking JsonWebToken

```java
@Mock
private JsonWebToken jwt;

@Test
void testWithEmail() {
    when(jwt.getClaim("email")).thenReturn("user@latticepay.io");
    when(jwt.getName()).thenReturn("fallback-name");
}
```
