package com.example.board.global.jwt;

import java.util.List;

public record AuthUser(
        Long userId,
        String role
) {
    public List<String> authorities() {
        return List.of("ROLE_" + role);
    }
}
