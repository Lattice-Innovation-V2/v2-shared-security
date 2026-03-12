package io.latticepay.security.it;

import io.latticepay.security.gcp.GcpIamClientFilter;
import io.latticepay.security.gcp.GcpTokenProvider;
import io.latticepay.security.identity.HierarchyResolver;
import io.latticepay.security.identity.IdentityUtils;
import io.latticepay.security.identity.LatticeRolesAugmentor;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import jakarta.ws.rs.client.ClientRequestContext;
import jakarta.ws.rs.core.MultivaluedHashMap;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("Latticepay Security Integration Test")
@QuarkusTest
@Execution(ExecutionMode.SAME_THREAD)
class LatticeSecurityIT {

    @Inject
    IdentityUtils identityUtils;

    @Inject
    GcpIamClientFilter gcpIamClientFilter;

    @Inject
    GcpTokenProvider gcpTokenProvider;

    @Inject
    LatticeRolesAugmentor latticeRolesAugmentor;

    @Inject
    HierarchyResolver hierarchyResolver;

    @Test
    @DisplayName("should inject IdentityUtils bean")
    void shouldInjectIdentityUtilsBean() {
        assertNotNull(identityUtils, "IdentityUtils should be injected by CDI");
    }

    @Test
    @DisplayName("should be discovered by CDI container")
    void shouldBeDiscoveredByCdiContainer() {
        assertNotNull(gcpIamClientFilter, "GcpIamClientFilter should be injected by CDI");
        assertNotNull(gcpTokenProvider, "GcpTokenProvider should be injected by CDI");
    }

    @Test
    @DisplayName("should inject LatticeRolesAugmentor bean")
    void shouldInjectLatticeRolesAugmentorBean() {
        assertNotNull(latticeRolesAugmentor, "LatticeRolesAugmentor should be injected by CDI");
    }

    @Test
    @DisplayName("should inject HierarchyResolver bean")
    void shouldInjectHierarchyResolverBean() {
        assertNotNull(hierarchyResolver, "HierarchyResolver should be injected by CDI");
    }

    @Test
    @DisplayName("should execute filter without error in test profile")
    void shouldExecuteFilterWithoutError() throws Exception {
        var headers = new MultivaluedHashMap<String, Object>();
        var requestContext = mock(ClientRequestContext.class);
        when(requestContext.getHeaders()).thenReturn(headers);

        // In test profile, GCP IAM auth is typically disabled, so filter should return early
        // without throwing (even if GCP credentials are not available)
        gcpIamClientFilter.filter(requestContext);

        assertNotNull(gcpIamClientFilter);
    }
}
