package com.auth.jwt.entity;

import lombok.Data;

@Data
public class Account {
  private Long id;
  private String username;
  private String password;
}
