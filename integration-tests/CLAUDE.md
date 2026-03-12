# Integration Tests Module - Testing Rules

> Inherits all rules from root [CLAUDE.md](../CLAUDE.md) and [.cursor/rules/](.cursor/rules/)

## Module Purpose
Simulates a real Quarkus application consuming this library. Verifies correct integration behavior.

## Test Strategy

### What to Test Here
- Bean registration (all beans injectable without `quarkus.index-dependency`)
- Configuration validation (`IllegalStateException` for invalid config)
- Integration between library components and Quarkus OIDC
- End-to-end request flows through filters

### What NOT to Test Here
- Unit-level logic (use `runtime/src/test/java`)
- Deployment processor logic (use `deployment/src/test/java`)

## Integration-Specific Patterns

### JWT Simulation
Use `@TestSecurity` and `@OidcSecurity` to simulate authenticated requests with claims.

### Test Profiles
Create `QuarkusTestProfile` implementations for different config scenarios (valid, invalid, enabled/disabled).

### Mock External Services
Use `@InjectMock` for `GcpTokenProvider` to avoid real GCP API calls.

## Test Configuration
Minimal config in `src/test/resources/application.properties`:
- Enable features needed for testing
- Use test values for IDs and secrets
- Set `quarkus.http.test-port=0`

## Testing Checklist
For new library features:
- [ ] Bean registration test (verify injectable)
- [ ] Config validation test (verify throws `IllegalStateException`)
- [ ] Integration test (end-to-end feature verification)
- [ ] JWT simulation test (if feature uses JWT)
- [ ] Negative test cases (error conditions)
- [ ] Test with IAP and GCIP configurations

## Reference Tests
Study existing patterns in `integration-tests/src/test/java`:
- Bean registration verification
- Configuration validation
- Filter integration
- Tenant resolution
