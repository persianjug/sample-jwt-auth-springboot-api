package com.auth.jwt.service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.auth.jwt.entity.Account;
import com.auth.jwt.entity.RefreshToken;
import com.auth.jwt.mapper.RefreshTokenMapper;
import com.auth.jwt.model.JwtResponseWithRefreshToken;
import com.auth.jwt.util.JwtTokenUtil;

/**
 * リフレッシュトークンに関連するビジネスロジックを管理するサービスです。
 * トークンの生成、データベースへの保存、有効期限の検証、およびJWTの再発行処理を行います。
 */
@Service
public class RefreshTokenService {
  @Value("${jwt.refresh-expiration}")
  private long refreshExpiration;

  private final RefreshTokenMapper refreshTokenMapper;
  private final AccountService accountService;
  private final AccountUserDetailsService accountUserDetailsService;
  private final JwtTokenUtil jwtTokenUtil;

  /**
   * RefreshTokenServiceの新しいインスタンスを生成します。
   *
   * @param refreshTokenMapper        リフレッシュトークンデータへのアクセスを提供するマッパー
   * @param accountService            アカウント関連のサービス
   * @param accountUserDetailsService ユーザー詳細情報をロードするサービス
   * @param jwtTokenUtil              JWTを扱うためのユーティリティ
   */
  public RefreshTokenService(
      RefreshTokenMapper refreshTokenMapper,
      AccountService accountService,
      AccountUserDetailsService accountUserDetailsService,
      JwtTokenUtil jwtTokenUtil) {
    this.refreshTokenMapper = refreshTokenMapper;
    this.accountService = accountService;
    this.accountUserDetailsService = accountUserDetailsService;
    this.jwtTokenUtil = jwtTokenUtil;
  }

  /**
   * 新しいリフレッシュトークンを生成し、データベースに保存します。
   * トークン値はUUIDで、有効期限はプロパティ設定に基づき決定されます。
   *
   * @param accountId トークンを発行するアカウントのID
   * @return 生成されデータベースに保存されたリフレッシュトークン
   */
  public RefreshToken createRefreshToken(Long accountId) {
    RefreshToken refreshToken = new RefreshToken();
    refreshToken.setAccountId(accountId);
    refreshToken.setToken(UUID.randomUUID().toString());
    refreshToken.setExpiryDate(Instant.now().plusMillis(refreshExpiration));
    refreshTokenMapper.save(refreshToken);
    return refreshToken;
  }

  /**
   * トークン文字列に基づいてリフレッシュトークンをデータベースから検索します。
   *
   * @param token 検索するリフレッシュトークン文字列
   * @return リフレッシュトークンが見つかった場合は{@link Optional}にラップされて返されます。見つからない場合は{@link Optional#empty()}。
   */
  public Optional<RefreshToken> findByToken(String token) {
    return refreshTokenMapper.findByToken(token);
  }

  /**
   * リフレッシュトークンの有効期限を検証します。
   * 期限切れの場合、データベースからトークンを削除し、{@link RuntimeException}をスローします。
   *
   * @param token 検証するリフレッシュトークン
   * @throws RuntimeException トークンが期限切れの場合
   */
  public void verifyExpiration(RefreshToken token) {
    if (token.getExpiryDate().isBefore(Instant.now())) {
      refreshTokenMapper.deleteByAccountId(token.getAccountId());
      throw new RuntimeException(token.getToken() + " Refresh token was expired. Please make a new signin request");
    }
  }

  /**
   * リフレッシュトークンを検証し、新しいJWTトークンを生成します。
   * 
   * @param requestRefreshToken クライアントから提供されたリフレッシュトークン文字列
   * @return 新しいJWTとリフレッシュトークンを含むレスポンスデータモデル
   * @throws RuntimeException トークンが無効（データベースに見つからない）または期限切れの場合
   */
  public JwtResponseWithRefreshToken refreshAccessToken(String requestRefreshToken) throws RuntimeException {

    return refreshTokenMapper.findByToken(requestRefreshToken) // findByTokenがOptionalを返す前提
        .map(refreshToken -> {
          // 有効期限の検証
          verifyExpiration(refreshToken);

          // アカウント情報の取得
          Account account = accountService.findById(refreshToken.getAccountId());
          UserDetails userDetails = accountUserDetailsService.loadUserByUsername(account.getUsername());

          // 新しいJWTトークンを生成
          String jwtToken = jwtTokenUtil.generateToken(userDetails);

          // レスポンスモデルを返却
          return new JwtResponseWithRefreshToken(jwtToken, refreshToken.getToken());
        })
        .orElseThrow(() -> new RuntimeException("Refresh token is not in database!"));
  }

  /**
   * アカウントIDに基づいてリフレッシュトークンをデータベースから削除します。
   * このメソッドはログアウト処理に使用されます。
   *
   * @param accountId ログアウトするアカウントのID
   */
  public void deleteByAccountId(Long accountId) {
    refreshTokenMapper.deleteByAccountId(accountId);
  }
}
