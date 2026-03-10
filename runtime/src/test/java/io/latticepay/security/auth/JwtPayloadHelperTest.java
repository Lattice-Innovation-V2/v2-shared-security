package io.latticepay.security.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("JwtPayloadHelper")
class JwtPayloadHelperTest {

    @Nested
    @DisplayName("getIssuerFromBearerToken")
    class GetIssuerTests {

        @Test
        @DisplayName("returns iss when token has valid payload")
        void returnsIssuerWhenValidPayload() {
            String token = TestJwtFactory.minimalJwtWithIss("https://dev.issuer.local");
            Optional<String> result = JwtPayloadHelper.getIssuerFromBearerToken(token);
            assertTrue(result.isPresent());
            assertEquals("https://dev.issuer.local", result.get());
        }

        @Test
        @DisplayName("returns different issuer when payload has different iss")
        void returnsDifferentIssuer() {
            String token = TestJwtFactory.minimalJwtWithIss("https://securetoken.google.com/my-project");
            Optional<String> result = JwtPayloadHelper.getIssuerFromBearerToken(token);
            assertTrue(result.isPresent());
            assertEquals("https://securetoken.google.com/my-project", result.get());
        }

        @Test
        @DisplayName("returns empty when token is null")
        void returnsEmptyWhenNull() {
            assertEquals(Optional.empty(), JwtPayloadHelper.getIssuerFromBearerToken(null));
        }

        @Test
        @DisplayName("returns empty when token is blank")
        void returnsEmptyWhenBlank() {
            assertEquals(Optional.empty(), JwtPayloadHelper.getIssuerFromBearerToken(""));
            assertEquals(Optional.empty(), JwtPayloadHelper.getIssuerFromBearerToken("   "));
        }

        @Test
        @DisplayName("returns empty when token has fewer than 3 segments")
        void returnsEmptyWhenNotThreeParts() {
            assertEquals(Optional.empty(), JwtPayloadHelper.getIssuerFromBearerToken("a"));
            assertEquals(Optional.empty(), JwtPayloadHelper.getIssuerFromBearerToken("a.b"));
        }

        @Test
        @DisplayName("returns empty when token has more than 3 segments")
        void returnsEmptyWhenMoreThanThreeParts() {
            assertEquals(Optional.empty(), JwtPayloadHelper.getIssuerFromBearerToken("a.b.c.d"));
        }

        @Test
        @DisplayName("returns empty when payload is not valid Base64URL")
        void returnsEmptyWhenInvalidBase64() {
            assertEquals(Optional.empty(), JwtPayloadHelper.getIssuerFromBearerToken("a.b!!!.c"));
        }

        @Test
        @DisplayName("returns empty when payload segment is empty")
        void returnsEmptyWhenPayloadSegmentEmpty() {
            String header = TestJwtFactory.base64UrlEncode("{\"alg\":\"RS256\"}");
            String sig = TestJwtFactory.base64UrlEncode("x");
            String token = header + ".." + sig;
            assertEquals(Optional.empty(), JwtPayloadHelper.getIssuerFromBearerToken(token));
        }

        @Test
        @DisplayName("returns empty when payload JSON has no iss claim")
        void returnsEmptyWhenNoIssClaim() {
            String payload = TestJwtFactory.base64UrlEncode("{\"sub\":\"test\"}");
            String token = TestJwtFactory.base64UrlEncode("{}") + "." + payload + "." + TestJwtFactory.base64UrlEncode("x");
            assertEquals(Optional.empty(), JwtPayloadHelper.getIssuerFromBearerToken(token));
        }

        @Test
        @DisplayName("returns empty when iss is a nested object not a string")
        void returnsEmptyWhenIssIsNestedObject() {
            String payload = TestJwtFactory.base64UrlEncode("{\"iss\":{\"url\":\"https://issuer.local\"},\"sub\":\"test\"}");
            String token = TestJwtFactory.base64UrlEncode("{\"alg\":\"RS256\"}") + "." + payload + "." + TestJwtFactory.base64UrlEncode("x");
            assertEquals(Optional.empty(), JwtPayloadHelper.getIssuerFromBearerToken(token));
        }

        @Test
        @DisplayName("returns first segment when iss value contains escaped double-quote")
        void returnsFirstSegmentWhenIssContainsEscapedQuote() {
            String payload = TestJwtFactory.base64UrlEncode("{\"iss\":\"https://a\\\"b.local\",\"sub\":\"test\"}");
            String token = TestJwtFactory.base64UrlEncode("{\"alg\":\"RS256\"}") + "." + payload + "." + TestJwtFactory.base64UrlEncode("x");
            Optional<String> result = JwtPayloadHelper.getIssuerFromBearerToken(token);
            assertTrue(result.isPresent());
            assertEquals("https://a\\", result.get());
        }
    }
}
