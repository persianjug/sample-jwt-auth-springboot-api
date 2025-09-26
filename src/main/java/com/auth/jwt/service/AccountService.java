package com.auth.jwt.service;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.auth.jwt.entity.Account;
import com.auth.jwt.mapper.AccountMapper;
import com.auth.jwt.util.JwtTokenUtil;

/**
 * アカウントに関連するビジネスロジックを管理するサービスです。
 * アカウントの登録やログインといった認証フロー、およびアカウント情報の取得を処理します。
 */
@Service
public class AccountService {
  private final AccountMapper accountMapper;
  private final PasswordEncoder passwordEncoder;
  private final AuthenticationManager authenticationManager;
  private final JwtTokenUtil jwtTokenUtil;
  private final AccountUserDetailsService accountUserDetailsService;

  /**
   * AccountServiceの新しいインスタンスを生成します。
   *
   * @param accountMapper             アカウントデータへのアクセスを提供するマッパー
   * @param passwordEncoder           パスワードのハッシュ化を行うエンコーダー
   * @param authenticationManager     認証処理を管理するマネージャー
   * @param jwtTokenUtil              JWTを扱うためのユーティリティ
   * @param accountUserDetailsService ユーザー詳細情報をロードするサービス
   */
  public AccountService(
      AccountMapper accountMapper,
      PasswordEncoder passwordEncoder,
      AuthenticationManager authenticationManager,
      JwtTokenUtil jwtTokenUtil,
      AccountUserDetailsService accountUserDetailsService) {
    this.accountMapper = accountMapper;
    this.passwordEncoder = passwordEncoder;
    this.authenticationManager = authenticationManager;
    this.jwtTokenUtil = jwtTokenUtil;
    this.accountUserDetailsService = accountUserDetailsService;
  }

  /**
   * 新しいアカウントを登録します。
   *
   * @param username 登録するユーザー名
   * @param password 登録するパスワード
   * @throws IllegalArgumentException ユーザー名がすでに存在する場合
   */
  public void registerNewAccount(String username, String password) throws IllegalArgumentException {
    if (accountMapper.findByUsername(username) != null) {
      throw new IllegalArgumentException("ユーザー名が既に存在します。");
    }
    accountMapper.save(createAccount(username, password));
  }

  /**
   * アカウント情報を作成します。
   * パスワードはハッシュ化されます。
   *
   * @param username ユーザー名
   * @param password パスワード
   * @return 作成されたアカウントエンティティ
   */
  private Account createAccount(String username, String password) {
    Account account = new Account();
    account.setUsername(username);
    account.setPassword(passwordEncoder.encode(password));
    return account;
  }

  /**
   * ユーザーのログインを試み、成功した場合はJWTトークンを返します。
   *
   * @param username ユーザー名
   * @param password パスワード
   * @return 認証成功時に生成されたJWTトークン
   * @throws DisabledException         ユーザーアカウントが無効な場合
   * @throws BadCredentialsException   パスワードが間違っている場合
   * @throws UsernameNotFoundException ユーザー名が見つからない場合
   */
  public String login(String username, String password)
      throws DisabledException, BadCredentialsException, UsernameNotFoundException {
    // 認証
    authenticate(username, password);

    // アカウント情報を取得
    final UserDetails userDetails = accountUserDetailsService.loadUserByUsername(username);

    // トークン発行
    return jwtTokenUtil.generateToken(userDetails);
  }

  /**
   * ユーザーの認証を行います。
   *
   * @param username ユーザー名
   * @param password パスワード
   * @throws DisabledException       ユーザーアカウントが無効な場合
   * @throws BadCredentialsException パスワードが間違っている場合
   */
  private void authenticate(String username, String password) throws DisabledException, BadCredentialsException {
    try {
      authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
    } catch (DisabledException | BadCredentialsException e) {
      throw e;
    }
  }

  /**
   * ユーザー名に基づいてアカウント情報を取得します。
   *
   * @param username 検索するユーザー名
   * @return ユーザー名に一致するアカウントエンティティ
   */
  public Account findByUsername(String username) {
    return accountMapper.findByUsername(username);
  }

  /**
   * アカウントIDに基づいてアカウント情報を取得します。
   *
   * @param id 検索するアカウントID
   * @return アカウントIDに一致するアカウントエンティティ
   */
  public Account findById(Long id) {
    return accountMapper.findById(id);
  }
}
