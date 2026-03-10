package io.latticepay.security.identity;

import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.SecurityIdentity;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.Principal;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@DisplayName("LatticeRolesAugmentor")
@ExtendWith(MockitoExtension.class)
class LatticeRolesAugmentorTest {

    @Mock
    private IdentityUtils identityUtils;
    @Mock
    private SecurityIdentity identity;
    @Mock
    private AuthenticationRequestContext context;
    @Mock
    private JsonWebToken jwt;
    @Mock
    private Principal nonJwtPrincipal;

    private LatticeRolesAugmentor augmentor;

    @BeforeEach
    void setUp() {
        augmentor = new LatticeRolesAugmentor(identityUtils);
    }

    @Nested
    @DisplayName("resolveRole")
    class ResolveRole {

        @Test
        @DisplayName("returns platform_admin for internal user")
        void returnsPlatformAdmin_forInternalUser() {
            when(identityUtils.isInternalUser(jwt)).thenReturn(true);

            assertEquals("platform_admin", augmentor.resolveRole(jwt));
        }

        @ParameterizedTest(name = "returns {1} for {0} role claim")
        @CsvSource({
                "integrator_admin, integrator_admin",
                "integrator_readonly, integrator_readonly",
                "merchant_admin, merchant_admin",
                "merchant_readonly, merchant_readonly"
        })
        @DisplayName("returns mapped role for known role claim (external, non-WIF)")
        void returnsMappedRole_forKnownRoleClaim(String claimRole, String expectedRole) {
            when(identityUtils.isInternalUser(jwt)).thenReturn(false);
            when(identityUtils.isWifToken(jwt)).thenReturn(false);
            when(identityUtils.getRole(jwt)).thenReturn(Optional.of(claimRole));

            assertEquals(expectedRole, augmentor.resolveRole(jwt));
        }

        @Test
        @DisplayName("returns null for unknown role claim (fail-closed)")
        void returnsNull_forUnknownRole() {
            when(identityUtils.isInternalUser(jwt)).thenReturn(false);
            when(identityUtils.isWifToken(jwt)).thenReturn(false);
            when(identityUtils.getRole(jwt)).thenReturn(Optional.of("unknown_role"));

            assertNull(augmentor.resolveRole(jwt));
        }

        @Test
        @DisplayName("returns null for external user without role claim")
        void returnsNull_forExternalUserWithoutRole() {
            when(identityUtils.isInternalUser(jwt)).thenReturn(false);
            when(identityUtils.isWifToken(jwt)).thenReturn(false);
            when(identityUtils.getRole(jwt)).thenReturn(Optional.empty());

            assertNull(augmentor.resolveRole(jwt));
        }
    }

    @Nested
    @DisplayName("WIF role resolution")
    class WifResolveRole {

        @Test
        @DisplayName("resolves role from attribute-mapped claim for WIF token")
        void resolvesRole_fromAttributeMappedClaim_forWifToken() {
            when(identityUtils.isInternalUser(jwt)).thenReturn(false);
            when(identityUtils.isWifToken(jwt)).thenReturn(true);
            when(identityUtils.getRole(jwt)).thenReturn(Optional.of("integrator_admin"));

            assertEquals("integrator_admin", augmentor.resolveRole(jwt));
        }

        @Test
        @DisplayName("returns null for WIF token without role claim (fail-closed)")
        void returnsNull_forWifTokenWithoutRole() {
            when(identityUtils.isInternalUser(jwt)).thenReturn(false);
            when(identityUtils.isWifToken(jwt)).thenReturn(true);
            when(identityUtils.getRole(jwt)).thenReturn(Optional.empty());

            assertNull(augmentor.resolveRole(jwt));
        }

        @Test
        @DisplayName("returns null for WIF token with unknown role (fail-closed)")
        void returnsNull_forWifTokenWithUnknownRole() {
            when(identityUtils.isInternalUser(jwt)).thenReturn(false);
            when(identityUtils.isWifToken(jwt)).thenReturn(true);
            when(identityUtils.getRole(jwt)).thenReturn(Optional.of("unknown_wif_role"));

            assertNull(augmentor.resolveRole(jwt));
        }
    }

    @Nested
    @DisplayName("mapClaimToRole")
    class MapClaimToRole {

        @Test
        @DisplayName("passes through known fine-grained roles")
        void passesThroughKnownRoles() {
            assertEquals("integrator_admin", LatticeRolesAugmentor.mapClaimToRole("integrator_admin"));
            assertEquals("integrator_readonly", LatticeRolesAugmentor.mapClaimToRole("integrator_readonly"));
            assertEquals("merchant_admin", LatticeRolesAugmentor.mapClaimToRole("merchant_admin"));
            assertEquals("merchant_readonly", LatticeRolesAugmentor.mapClaimToRole("merchant_readonly"));
        }

        @Test
        @DisplayName("returns null for unknown roles")
        void returnsNullForUnknown() {
            assertNull(LatticeRolesAugmentor.mapClaimToRole("unknown"));
            assertNull(LatticeRolesAugmentor.mapClaimToRole("integrator"));
            assertNull(LatticeRolesAugmentor.mapClaimToRole("merchant"));
            assertNull(LatticeRolesAugmentor.mapClaimToRole(null));
        }
    }

    @Nested
    @DisplayName("augment")
    class Augment {

        @Test
        @DisplayName("passes through anonymous identity")
        void passesThrough_anonymousIdentity() {
            when(identity.isAnonymous()).thenReturn(true);

            SecurityIdentity result = augmentor.augment(identity, context).await().indefinitely();

            assertSame(identity, result);
        }

        @Test
        @DisplayName("passes through non-JWT principal")
        void passesThrough_nonJwtPrincipal() {
            when(identity.isAnonymous()).thenReturn(false);
            when(identity.getPrincipal()).thenReturn(nonJwtPrincipal);

            SecurityIdentity result = augmentor.augment(identity, context).await().indefinitely();

            assertSame(identity, result);
        }

        @Test
        @DisplayName("adds platform_admin and admin roles for internal user")
        void addsPlatformAdminAndAdminRoles_forInternalUser() {
            when(identity.isAnonymous()).thenReturn(false);
            when(identity.getPrincipal()).thenReturn(jwt);
            when(identityUtils.isInternalUser(jwt)).thenReturn(true);
            when(identityUtils.getPermissions(jwt)).thenReturn(List.of());

            SecurityIdentity result = augmentor.augment(identity, context).await().indefinitely();

            assertTrue(result.getRoles().contains("platform_admin"));
            assertTrue(result.getRoles().contains("admin"));
        }

        @Test
        @DisplayName("adds integrator_admin and integrator roles for integrator_admin claim")
        void addsIntegratorAdminAndIntegratorRoles_forIntegratorAdmin() {
            when(identity.isAnonymous()).thenReturn(false);
            when(identity.getPrincipal()).thenReturn(jwt);
            when(identityUtils.isInternalUser(jwt)).thenReturn(false);
            when(identityUtils.isWifToken(jwt)).thenReturn(false);
            when(identityUtils.getRole(jwt)).thenReturn(Optional.of("integrator_admin"));
            when(identityUtils.getPermissions(jwt)).thenReturn(List.of("merchants:read", "merchants:write"));

            SecurityIdentity result = augmentor.augment(identity, context).await().indefinitely();

            assertTrue(result.getRoles().contains("integrator_admin"));
            assertTrue(result.getRoles().contains("integrator"));
            assertTrue(result.getRoles().contains("merchants:read"));
            assertTrue(result.getRoles().contains("merchants:write"));
        }

        @Test
        @DisplayName("passes through identity when no role can be resolved")
        void passesThrough_whenNoRoleResolved() {
            when(identity.isAnonymous()).thenReturn(false);
            when(identity.getPrincipal()).thenReturn(jwt);
            when(identityUtils.isInternalUser(jwt)).thenReturn(false);
            when(identityUtils.isWifToken(jwt)).thenReturn(false);
            when(identityUtils.getRole(jwt)).thenReturn(Optional.empty());

            SecurityIdentity result = augmentor.augment(identity, context).await().indefinitely();

            assertSame(identity, result);
        }

        @Test
        @DisplayName("augments WIF token with attribute-mapped role and permissions")
        void augmentsWifToken_withAttributeMappedRole() {
            when(identity.isAnonymous()).thenReturn(false);
            when(identity.getPrincipal()).thenReturn(jwt);
            when(identityUtils.isInternalUser(jwt)).thenReturn(false);
            when(identityUtils.isWifToken(jwt)).thenReturn(true);
            when(identityUtils.getRole(jwt)).thenReturn(Optional.of("integrator_admin"));
            when(identityUtils.getPermissions(jwt)).thenReturn(List.of("merchants:read"));

            SecurityIdentity result = augmentor.augment(identity, context).await().indefinitely();

            assertTrue(result.getRoles().contains("integrator_admin"));
            assertTrue(result.getRoles().contains("integrator"));
            assertTrue(result.getRoles().contains("merchants:read"));
        }
    }
}
