package com.auth.jwt.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

/**
 * JWT（JSON Web Token）を扱うためのユーティリティクラス。
 * トークンの生成、解析、検証といった一連の処理を提供します。
 */
@Component
public class JwtTokenUtil {
  @Value("${jwt.secret}")
  private String secret;

  @Value("${jwt.expiration}")
  private long expiration;

  /**
   * トークンからユーザー名（サブジェクト）を取得します。
   *
   * @param token JWTトークン
   * @return ユーザー名
   */
  public String getUsernameFromToken(String token) {
    return getClaimFromToken(token, Claims::getSubject);
  }

  /**
   * トークンから有効期限を取得します。
   *
   * @param token JWTトークン
   * @return 有効期限（Dateオブジェクト）
   */
  public Date getExpirationDateFromToken(String token) {
    return getClaimFromToken(token, Claims::getExpiration);
  }

  /**
   * トークンから特定のクレーム（トークン内に含まれる認証情報など）を取得します。
   *
   * @param <T>            クレームの型
   * @param token          JWTトークン
   * @param claimsResolver 取得したいクレームを指定する関数
   * @return 指定されたクレームの値
   */
  public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
    final Claims claims = getAllClaimsFromToken(token);
    return claimsResolver.apply(claims);
  }

  /**
   * トークンからすべてのクレーム（トークン内に含まれる認証情報など）を取得します。
   *
   * @param token JWTトークン
   * @return すべてのクレームを含むClaimsオブジェクト
   */
  private Claims getAllClaimsFromToken(String token) {
    return Jwts
        .parser()
        .verifyWith(getSigningKey())
        .build()
        .parseSignedClaims(token)
        .getPayload();
  }

  /**
   * トークンが有効期限切れかどうかをチェックします。
   *
   * @param token JWTトークン
   * @return 有効期限切れの場合にtrue、そうでなければfalse
   */
  private Boolean isTokenExpired(String token) {
    final Date expiration = getExpirationDateFromToken(token);
    return expiration.before(new Date());
  }

  /**
   * ユーザー情報に基づいてJWTトークンを生成します。
   *
   * @param userDetails 認証済みのUserDetails（Spring Securityの認証で使用する情報）オブジェクト
   * @return 生成されたJWTトークン
   */
  public String generateToken(UserDetails userDetails) {
    Map<String, Object> claims = new HashMap<>();
    return doGenerateToken(claims, userDetails.getUsername());
  }

  /**
   * クレームとサブジェクトに基づいて、実際にJWTを生成します。
   *
   * @param claims  ペイロード（認証情報やその他のデータ）に含めるクレーム
   * @param subject トークンのサブジェクト（通常はユーザー名）
   * @return 生成されたJWTトークン
   */
  private String doGenerateToken(Map<String, Object> claims, String subject) {
    return Jwts.builder()
        .setClaims(claims)
        .setSubject(subject)
        .setIssuedAt(new Date(System.currentTimeMillis()))
        .setExpiration(new Date(System.currentTimeMillis() + expiration))
        .signWith(getSigningKey())
        .compact();
  }

  /**
   * トークンの有効性を検証します。
   *
   * @param token       JWTトークン
   * @param userDetails 認証済みのUserDetailsオブジェクト
   * @return トークンが有効な場合にtrue、そうでなければfalse
   */
  public Boolean validateToken(String token, UserDetails userDetails) {
    final String username = getUsernameFromToken(token);
    return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
  }

  /**
   * 署名に使用するSecretKeyを取得します。
   *
   * @return 署名用のSecretKey
   */
  private SecretKey getSigningKey() {
    byte[] keyBytes = Decoders.BASE64.decode(this.secret);
    return Keys.hmacShaKeyFor(keyBytes);
  }
}
