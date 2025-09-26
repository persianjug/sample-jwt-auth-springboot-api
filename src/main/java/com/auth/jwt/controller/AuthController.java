package com.auth.jwt.controller;

import com.auth.jwt.model.JwtRequest;
import com.auth.jwt.model.JwtResponseWithRefreshToken;
import com.auth.jwt.model.RefreshTokenRequest;
import com.auth.jwt.entity.Account;
import com.auth.jwt.entity.RefreshToken;
import com.auth.jwt.model.AccountRequest;
import com.auth.jwt.service.AccountService;
import com.auth.jwt.service.RefreshTokenService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 認証関連のAPIエンドポイントを提供するRESTコントローラーです。
 * アカウントの登録、ログイン、トークンのリフレッシュといった認証フローを管理します。
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

  private AccountService accountService;
  private RefreshTokenService refreshTokenService;

  /**
   * AuthControllerの新しいインスタンスを生成します。
   *
   * @param accountService      アカウント関連のビジネスロジックを処理するサービス
   * @param refreshTokenService リフレッシュトークン関連のビジネスロジックを処理するサービス
   */
  public AuthController(AccountService accountService, RefreshTokenService refreshTokenService) {
    this.accountService = accountService;
    this.refreshTokenService = refreshTokenService;
  }

  /**
   * 新しいアカウントを登録します。
   *
   * @param accountRequest 登録するアカウント情報を含むリクエストボディ
   * @return 登録が成功した場合はHTTPステータス200 OKと成功メッセージを返します。
   *         ユーザー名がすでに存在する場合など、登録に失敗した場合はHTTPステータス400 Bad Requestとエラーメッセージを返します。
   */
  @PostMapping("/register")
  public ResponseEntity<?> registerUser(@RequestBody AccountRequest accountRequest) {
    try {
      accountService.registerNewAccount(accountRequest.getUsername(), accountRequest.getPassword());
      return ResponseEntity.ok("ユーザー登録が完了しました。");
    } catch (IllegalArgumentException e) {
      return ResponseEntity.badRequest().body(e.getMessage());
    }
  }

  /**
   * ユーザーのログインを処理し、認証が成功した場合はJWTトークンを返します。
   *
   * @param authenticationRequest ログイン情報（ユーザー名とパスワード）を含むリクエストボディ
   * @return 認証が成功した場合はHTTPステータス200 OKとJWTトークンを返します。
   *         認証情報が無効な場合（ユーザー名が存在しない、パスワードが間違っている、ユーザーが無効など）は、
   *         HTTPステータス401 Unauthorizedとエラーメッセージを返します。
   */
  @PostMapping("/login")
  public ResponseEntity<?> createAuthenticationToken(@RequestBody JwtRequest authenticationRequest) {
    try {
      final String username = authenticationRequest.getUsername();
      final String password = authenticationRequest.getPassword();
      final String jwtToken = accountService.login(username, password);

      // リフレッシュトークンを生成
      Account account = accountService.findByUsername(username);
      RefreshToken refreshToken = refreshTokenService.createRefreshToken(account.getId());
      return ResponseEntity.ok(new JwtResponseWithRefreshToken(jwtToken, refreshToken.getToken()));
    } catch (DisabledException | BadCredentialsException | UsernameNotFoundException e) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
    }
  }

  /**
   * リフレッシュトークンを使用して、新しいJWT（アクセストークン）を取得します。
   * リフレッシュトークンが有効であれば、新しいJWTと既存のリフレッシュトークンを返します。
   *
   * @param request リフレッシュトークンを含むリクエストボディ
   * @return 新しいJWTとリフレッシュトークンを含むHTTPステータス200 OKレスポンス。
   *         トークンが無効または期限切れの場合はHTTPステータス401 Unauthorizedとエラーメッセージ。
   */
  @PostMapping("/refreshToken")
  public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest request) {
    String requestRefreshToken = request.getRefreshToken();

    try {
      // サービスを呼び出し、レスポンスに必要なデータモデルを取得
      JwtResponseWithRefreshToken responseModel = refreshTokenService.refreshAccessToken(requestRefreshToken);

      // データをHTTPレスポンスに変換
      return ResponseEntity.ok(responseModel);

    } catch (RuntimeException e) {
      // サービス層からスローされた例外を捕捉し、HTTPステータスに変換
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
    }
  }

  /**
   * 現在認証されているユーザーのリフレッシュトークンを無効化し、ログアウトさせます。
   *
   * @param authentication Spring Securityによって提供される認証情報
   * @return 成功メッセージとHTTPステータス200 OKレスポンス
   */
  @PostMapping("/logout")
  public ResponseEntity<?> logout(Authentication authentication) {
    // 1. ユーザー名からアカウントIDを取得
    // UserDetailsはAuthenticationから取得可能（AccountUserDetailsServiceの実装に依存）
    String username = authentication.getName();

    // データベースからアカウントエンティティを取得
    Account account = accountService.findByUsername(username);

    if (account == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User not found.");
    }

    // 2. リフレッシュトークンを削除（無効化）
    refreshTokenService.deleteByAccountId(account.getId());

    return ResponseEntity.ok("Logout successful. Refresh token revoked.");
  }

}
