package com.spendwise.gateway.filter;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.security.Key;
import java.util.Date;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class JwtAuthenticationFilterTest {

    private static final String TEST_KEY = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";
    private static final String INTERNAL_KEY = "test-internal-gateway-key";

    private JwtAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        filter = new JwtAuthenticationFilter();
        ReflectionTestUtils.setField(filter, "secretKey", TEST_KEY);
        ReflectionTestUtils.setField(filter, "internalGatewayKey", INTERNAL_KEY);
    }

    private String createToken(Long userId, String username, long ttlMillis, String secret) {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        Key key = Keys.hmacShaKeyFor(keyBytes);
        return Jwts.builder()
                .claim("userId", userId)
                .claim("role", "ROLE_USER")
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + ttlMillis))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    @Test
    @DisplayName("Public path should bypass auth and strip forged identity headers")
    void testPublicPathStripsHeadersAndAllows() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/auth/login")
                .header("X-User-Id", "999")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        AtomicReference<ServerWebExchange> passedExchange = new AtomicReference<>();
        GatewayFilterChain chain = ex -> {
            passedExchange.set(ex);
            return Mono.empty();
        };

        filter.filter(exchange, chain).block();

        assertNotNull(passedExchange.get());
        assertNull(passedExchange.get().getRequest().getHeaders().getFirst("X-User-Id"));
        assertEquals(INTERNAL_KEY, passedExchange.get().getRequest().getHeaders().getFirst("X-Internal-Gateway-Key"));
    }

    @Test
    @DisplayName("Protected path without token returns 401 Unauthorized")
    void testProtectedPathMissingTokenReturns401() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/transactions").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        AtomicBoolean chainCalled = new AtomicBoolean(false);
        GatewayFilterChain chain = ex -> {
            chainCalled.set(true);
            return Mono.empty();
        };

        filter.filter(exchange, chain).block();

        assertFalse(chainCalled.get(), "Downstream chain should NOT be called");
        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
    }

    @Test
    @DisplayName("Protected path with expired token returns 401 Unauthorized")
    void testExpiredTokenReturns401() {
        String expiredToken = createToken(10L, "testuser", -5000L, TEST_KEY);

        MockServerHttpRequest request = MockServerHttpRequest.get("/api/transactions")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + expiredToken)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        AtomicBoolean chainCalled = new AtomicBoolean(false);
        GatewayFilterChain chain = ex -> {
            chainCalled.set(true);
            return Mono.empty();
        };

        filter.filter(exchange, chain).block();

        assertFalse(chainCalled.get());
        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
    }

    @Test
    @DisplayName("Protected path with invalid signature returns 401 Unauthorized")
    void testInvalidSignatureReturns401() {
        String wrongSecret = "YW5vdGhlci1kaWZmZXJlbnQtMjU2LWJpdC1zZWNyZXQta2V5LTEyMw==";
        String forgedToken = createToken(10L, "testuser", 3600000L, wrongSecret);

        MockServerHttpRequest request = MockServerHttpRequest.get("/api/transactions")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + forgedToken)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        AtomicBoolean chainCalled = new AtomicBoolean(false);
        GatewayFilterChain chain = ex -> {
            chainCalled.set(true);
            return Mono.empty();
        };

        filter.filter(exchange, chain).block();

        assertFalse(chainCalled.get());
        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
    }

    @Test
    @DisplayName("Protected path with valid token strips forged X-User-Id and injects verified identity")
    void testValidTokenStripsForgedHeaderAndInjectsVerifiedIdentity() {
        String validToken = createToken(42L, "verifieduser", 3600000L, TEST_KEY);

        MockServerHttpRequest request = MockServerHttpRequest.get("/api/transactions")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + validToken)
                .header("X-User-Id", "999") // Attacker attempting to spoof user 999
                .header("X-Internal-Gateway-Key", "forged-internal-key")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        AtomicReference<ServerWebExchange> passedExchange = new AtomicReference<>();
        GatewayFilterChain chain = ex -> {
            passedExchange.set(ex);
            return Mono.empty();
        };

        filter.filter(exchange, chain).block();

        assertNotNull(passedExchange.get());
        assertEquals("42", passedExchange.get().getRequest().getHeaders().getFirst("X-User-Id"));
        assertEquals("verifieduser", passedExchange.get().getRequest().getHeaders().getFirst("X-Auth-Username"));
        assertEquals(INTERNAL_KEY, passedExchange.get().getRequest().getHeaders().getFirst("X-Internal-Gateway-Key"));
    }
}

