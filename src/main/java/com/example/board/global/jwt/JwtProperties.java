package com.example.board.global.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "jwt")
public record JwtProperties(
        String secret,
        Long accessTokenExpireMs,
        Long refreshTokenExpireMs
) {
}
