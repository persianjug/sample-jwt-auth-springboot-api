package com.auth.jwt.model;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

/**
 * JWTトークンをリフレッシュするためのリクエストボディを表すクラスです。
 * クライアントは、このモデルを使用してリフレッシュトークンをサーバーに送信します。
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class RefreshTokenRequest {
  private String refreshToken;
}