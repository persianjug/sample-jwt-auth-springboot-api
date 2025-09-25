package com.auth.jwt.service;

import com.auth.jwt.entity.Account;
import com.auth.jwt.mapper.AccountMapper;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

/**
 * Spring Securityの認証プロセスにおいて、アカウント情報を取得するサービスです。
 * {@link UserDetailsService} インターフェースを実装しており、ユーザー名に基づいて
 * {@link UserDetails} オブジェクトをロードする役割を担います。
 */
@Service
public class AccountUserDetailsService implements UserDetailsService {

  private AccountMapper accountMapper;

  /**
   * AccountUserDetailsServiceの新しいインスタンスを生成します。
   *
   * @param accountMapper アカウントデータへのアクセスを提供するマッパー
   */
  public AccountUserDetailsService(AccountMapper accountMapper) {
    this.accountMapper = accountMapper;
  }

  /**
   * ユーザー名に基づいてアカウント情報をロードし、{@link UserDetails} オブジェクトとして返します。
   * このメソッドは、認証プロセス中にSpring Securityによって呼び出されます。
   *
   * @param username ログイン時に提供されたユーザー名
   * @return ユーザー名に一致するアカウント情報を含む{@link UserDetails}
   * @throws UsernameNotFoundException 指定されたユーザー名のアカウントが見つからない場合
   */
  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    // アカウント情報を取得
    Account user = accountMapper.findByUsername(username);

    // アカウントが見つからない場合はスロー
    if (user == null) {
      throw new UsernameNotFoundException("Account not found with username: " + username);
    }

    // Spring SecurityのUserDetailsを実装したオブジェクトを返す
    return new User(
        user.getUsername(),
        user.getPassword(),
        new ArrayList<>() // 役割（ロール）は後で実装
    );
  }
}