package com.example.board.global.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.Map;

@Component
public class JwtTokenProvider {

    private final JwtProperties props;
    private final Key key;

    public JwtTokenProvider(JwtProperties props) {
        this.props = props;
        this.key = Keys.hmacShaKeyFor(props.secret().getBytes(StandardCharsets.UTF_8));
    }

    public String createAccessToken(Long userId, String role) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .setSubject(String.valueOf(userId))
                .addClaims(Map.of("role", role, "type", "access"))
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + props.accessTokenExpireMs()))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public String createRefreshToken(Long userId, String role) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .setSubject(String.valueOf(userId))
                .addClaims(Map.of("role", role, "type", "refresh"))
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + props.refreshTokenExpireMs()))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean validate(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public AuthUser getAuthUser(String token) {
        Claims claims = parseClaims(token);
        Long userId = Long.valueOf(claims.getSubject());
        String role = String.valueOf(claims.get("role"));
        return new AuthUser(userId, role);
    }

    public boolean isAccessToken(String token) {
        try {
            Claims claims = parseClaims(token);
            return "access".equals(String.valueOf(claims.get("type")));
        } catch (Exception e) {
            return false;
        }
    }

    public boolean isRefreshToken(String token) {
        try {
            Claims claims = parseClaims(token);
            return "refresh".equals(String.valueOf(claims.get("type")));
        } catch (Exception e) {
            return false;
        }
    }
}