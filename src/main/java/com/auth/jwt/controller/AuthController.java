package com.auth.jwt.controller;

import com.auth.jwt.model.JwtRequest;
import com.auth.jwt.model.JwtResponse;
import com.auth.jwt.model.AccountRequest;
import com.auth.jwt.service.AccountService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 認証関連のAPIエンドポイントを提供するRESTコントローラーです。
 * アカウントの登録やログインといった認証フローを管理します。
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

  private AccountService accountService;

  /**
   * AuthControllerの新しいインスタンスを生成します。
   *
   * @param accountService アカウント関連のビジネスロジックを処理するサービス
   */
  public AuthController(AccountService accountService) {
    this.accountService = accountService;
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
      final String token = accountService.login(
          authenticationRequest.getUsername(),
          authenticationRequest.getPassword());
      return ResponseEntity.ok(new JwtResponse(token));
    } catch (DisabledException | BadCredentialsException | UsernameNotFoundException e) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
    }
  }
}
