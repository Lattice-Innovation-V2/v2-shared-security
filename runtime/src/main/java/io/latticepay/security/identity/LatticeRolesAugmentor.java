package io.latticepay.security.identity;

import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.SecurityIdentityAugmentor;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.jwt.JsonWebToken;

import java.util.Set;

/**
 * Quarkus {@link SecurityIdentityAugmentor} that populates authorization roles
 * on the {@link SecurityIdentity} from JWT claims.
 *
 * **Role resolution:**
 * - IAP internal user ({@literal @}latticepay.io email) → `platform_admin`
 * - WIF token (`iss=https://sts.googleapis.com`) → reads role from attribute-mapped claims
 * - GCIP/Firebase token → reads role from `role` claim
 *
 * Permission claims are also mapped to roles for fine-grained `@RolesAllowed` checks.
 */
@ApplicationScoped
public class LatticeRolesAugmentor implements SecurityIdentityAugmentor {

    private static final String ROLE_PLATFORM_ADMIN = "platform_admin";
    private static final String ROLE_ADMIN = "admin";
    private static final String ROLE_INTEGRATOR = "integrator";
    private static final String ROLE_MERCHANT = "merchant";
    private static final String PREFIX_INTEGRATOR = "integrator_";
    private static final String PREFIX_MERCHANT = "merchant_";

    private static final Set<String> KNOWN_ROLES = Set.of(
            "integrator_admin", "integrator_readonly",
            "merchant_admin", "merchant_readonly"
    );

    private final IdentityUtils identityUtils;

    public LatticeRolesAugmentor(IdentityUtils identityUtils) {
        this.identityUtils = identityUtils;
    }

    @Override
    public Uni<SecurityIdentity> augment(SecurityIdentity identity,
            AuthenticationRequestContext context) {
        if (identity.isAnonymous()) {
            return Uni.createFrom().item(identity);
        }
        if (!(identity.getPrincipal() instanceof JsonWebToken jwt)) {
            return Uni.createFrom().item(identity);
        }
        String role = resolveRole(jwt);
        if (role == null) {
            return Uni.createFrom().item(identity);
        }
        var builder = QuarkusSecurityIdentity.builder(identity).addRole(role);
        addCoarseRoles(builder, role);
        addPermissionRoles(builder, jwt);
        return Uni.createFrom().item(builder.build());
    }

    /**
     * Adds coarse-grained roles for `@RolesAllowed` checks (e.g. `admin`, `integrator`, `merchant`).
     */
    private void addCoarseRoles(QuarkusSecurityIdentity.Builder builder, String role) {
        if (ROLE_PLATFORM_ADMIN.equals(role)) {
            builder.addRole(ROLE_ADMIN);
        } else if (role.startsWith(PREFIX_INTEGRATOR)) {
            builder.addRole(ROLE_INTEGRATOR);
        } else if (role.startsWith(PREFIX_MERCHANT)) {
            builder.addRole(ROLE_MERCHANT);
        }
    }

    /**
     * Maps permission claims to roles for fine-grained `@RolesAllowed("merchants:read")` checks.
     */
    private void addPermissionRoles(QuarkusSecurityIdentity.Builder builder, JsonWebToken jwt) {
        for (String permission : identityUtils.getPermissions(jwt)) {
            builder.addRole(permission);
        }
    }

    /**
     * Resolves the application role from JWT claims.
     *
     * - IAP internal user → {@value #ROLE_PLATFORM_ADMIN}
     * - WIF token → reads role from attribute-mapped claims (fail-closed if absent)
     * - GCIP → reads role from `role` claim
     *
     * @param jwt the JWT token (may be null)
     * @return the resolved role, or null if not determinable (fail-closed)
     */
    String resolveRole(JsonWebToken jwt) {
        if (identityUtils.isInternalUser(jwt)) {
            return ROLE_PLATFORM_ADMIN;
        }
        if (identityUtils.isWifToken(jwt)) {
            return identityUtils.getRole(jwt)
                    .map(LatticeRolesAugmentor::mapClaimToRole)
                    .orElse(null);
        }
        return identityUtils.getRole(jwt)
                .map(LatticeRolesAugmentor::mapClaimToRole)
                .orElse(null);
    }

    /**
     * Maps the raw role claim value to an application role.
     * Only known fine-grained roles are accepted; unknown values return null (fail-closed).
     *
     * @param claimRole the raw claim value (may be null)
     * @return the normalized role if known, otherwise null
     */
    static String mapClaimToRole(String claimRole) {
        if (claimRole == null) {
            return null;
        }
        return KNOWN_ROLES.contains(claimRole) ? claimRole : null;
    }
}
