package com.auth.jwt.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth.jwt.entity.Account;
import com.auth.jwt.service.AccountService;

@RestController
@RequestMapping("/api/users")
public class AccountController {
  private final AccountService accountService;

  /**
   * AccountControllerの新しいインスタンスを生成します。
   *
   * @param accountService アカウント関連のビジネスロジックを処理するサービス
   */
  public AccountController(AccountService accountService) {
    this.accountService = accountService;
  }

  /**
   * 認証済みユーザー自身の詳細情報を返します。
   * 
   * @param authentication Spring Securityの認証情報
   * @return ユーザーのID、ユーザー名、メールアドレスなどを含むレスポンス
   */
  @GetMapping("/me")
  public ResponseEntity<?> getAuthenticatedUserInfo(Authentication authentication) {
    String username = authentication.getName();

    Account account = accountService.findByUsername(username);

    if (account == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User not found.");
    }

    return ResponseEntity.ok(account);
  }
}
