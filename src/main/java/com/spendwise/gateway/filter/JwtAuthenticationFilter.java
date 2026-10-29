package com.spendwise.gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.List;

/**
 * Reactive Spring Cloud Gateway Global Authentication Filter.
 *
 * Responsibilities:
 * 1. Sanitizes incoming requests by stripping client-supplied 'X-User-Id' and 'X-Internal-Gateway-Key' headers.
 * 2. Permits public routes (health check, actuator, auth-service endpoints) and CORS OPTIONS preflights.
 * 3. Enforces cryptographic HMAC-SHA256 signature verification and expiration checks on protected business routes.
 * 4. Extracts the verified 'userId' from the JWT and injects a trusted 'X-User-Id' downstream along with 'X-Internal-Gateway-Key'.
 */
@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    @Value("${jwt.secret:${JWT_SECRET:}}")
    private String secretKey;

    @Value("${fintrack.internal.gateway-key:${INTERNAL_GATEWAY_KEY:}}")
    private String internalGatewayKey;

    private static final List<String> PUBLIC_PATH_PREFIXES = List.of(
            "/api/auth/",
            "/actuator/",
            "/eureka/"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        // 1. Allow CORS preflight requests without authentication
        if (request.getMethod() == HttpMethod.OPTIONS) {
            return chain.filter(exchange);
        }

        // 2. Allow root status and public endpoints
        if ("/".equals(path) || isPublicPath(path)) {
            // Strip any forged X-User-Id or X-Internal-Gateway-Key headers before passing request downstream
            ServerHttpRequest sanitized = request.mutate()
                    .headers(h -> {
                        h.remove("X-User-Id");
                        h.remove("X-Internal-Gateway-Key");
                        if (internalGatewayKey != null && !internalGatewayKey.isBlank()) {
                            h.set("X-Internal-Gateway-Key", internalGatewayKey.trim());
                        }
                    })
                    .build();
            return chain.filter(exchange.mutate().request(sanitized).build());
        }

        // 3. Protected route: Extract Authorization Bearer token
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("Unauthorized access blocked at gateway: missing Bearer token for path '{}'", path);
            return writeErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Missing or malformed Authorization header");
        }

        String token = authHeader.substring(7).trim();
        if (token.isEmpty()) {
            return writeErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Empty authentication token");
        }

        // 4. Validate JWT signature, expiration, and claims
        try {
            Key key = getSigningKey();
            if (key == null) {
                log.error("Gateway security error: JWT secret key is not configured.");
                return writeErrorResponse(exchange, HttpStatus.INTERNAL_SERVER_ERROR, "Authentication service configuration error");
            }

            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            // Check token expiration explicitly
            if (claims.getExpiration() != null && claims.getExpiration().before(new Date())) {
                log.warn("Unauthorized access blocked at gateway: token expired for user '{}'", claims.getSubject());
                return writeErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Token has expired");
            }

            Object userIdClaim = claims.get("userId");
            if (userIdClaim == null) {
                log.warn("Unauthorized access blocked at gateway: token missing 'userId' claim");
                return writeErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Invalid token claims: missing user identity");
            }

            String verifiedUserId = String.valueOf(userIdClaim).trim();
            String username = claims.getSubject() != null ? claims.getSubject() : "";
            String role = claims.get("role") != null ? String.valueOf(claims.get("role")) : "ROLE_USER";

            // 5. Strip any incoming forged headers and inject verified identity and internal gateway key
            ServerHttpRequest mutatedRequest = request.mutate()
                    .headers(h -> {
                        h.remove("X-User-Id");
                        h.remove("X-Internal-Gateway-Key");
                        h.set("X-User-Id", verifiedUserId);
                        h.set("X-Auth-Username", username);
                        h.set("X-Auth-Role", role);
                        if (internalGatewayKey != null && !internalGatewayKey.isBlank()) {
                            h.set("X-Internal-Gateway-Key", internalGatewayKey.trim());
                        }
                    })
                    .build();

            return chain.filter(exchange.mutate().request(mutatedRequest).build());

        } catch (ExpiredJwtException ex) {
            log.warn("Gateway rejected expired token for path '{}': {}", path, ex.getMessage());
            return writeErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Token has expired");
        } catch (JwtException | IllegalArgumentException ex) {
            log.warn("Gateway rejected invalid token for path '{}': {}", path, ex.getMessage());
            return writeErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Invalid authentication token");
        }
    }

    private boolean isPublicPath(String path) {
        if (path == null) return false;
        for (String prefix : PUBLIC_PATH_PREFIXES) {
            if (path.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private Key getSigningKey() {
        if (secretKey == null || secretKey.isBlank()) {
            return null;
        }
        byte[] keyBytes = Decoders.BASE64.decode(secretKey.trim());
        if (keyBytes.length < 32) {
            log.error("Gateway security error: JWT secret key has insufficient length (<256 bits).");
            return null;
        }
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private Mono<Void> writeErrorResponse(ServerWebExchange exchange, HttpStatus status, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String json = String.format("{\"error\":\"%s\",\"message\":\"%s\",\"status\":%d}",
                status.getReasonPhrase(), escapeJson(message), status.value());
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        DataBuffer buffer = response.bufferFactory().wrap(bytes);
        return response.writeWith(Mono.just(buffer));
    }

    private String escapeJson(String text) {
        if (text == null) return "";
        return text.replace("\"", "\\\"").replace("\n", " ").replace("\r", "");
    }

    @Override
    public int getOrder() {
        return -100;
    }
}
