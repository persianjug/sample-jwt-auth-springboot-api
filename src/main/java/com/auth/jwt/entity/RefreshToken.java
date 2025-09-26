package com.auth.jwt.entity;

import java.time.Instant;

import lombok.Data;

@Data
public class RefreshToken {
  private Long id;
  private Long accountId;
  private String token;
  private Instant expiryDate;
}
