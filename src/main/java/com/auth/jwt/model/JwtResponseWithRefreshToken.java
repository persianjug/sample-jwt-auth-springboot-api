package com.auth.jwt.model;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class JwtResponseWithRefreshToken {
  private String jwtToken;
  private String refreshToken;
}
