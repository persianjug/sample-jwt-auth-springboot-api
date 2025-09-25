package com.auth.jwt.filter;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth.jwt.service.AccountUserDetailsService;
import com.auth.jwt.util.JwtTokenUtil;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * 認証ヘッダー内のJWTを検証し、Spring Securityの認証コンテキストを更新するためのフィルターです。
 * このフィルターは、リクエストごとに一度だけ実行されます。
 * ※認証コンテキスト：ユーザーの認証状態を保存する
 */
@Component
public class JwtRequestFilter extends OncePerRequestFilter {

  private AccountUserDetailsService accountUserDetailsService;
  private JwtTokenUtil jwtTokenUtil;

  /**
   * JwtRequestFilterの新しいインスタンスを生成します。
   *
   * @param accountUserDetailsService ユーザー情報を取得するためのサービス
   * @param jwtTokenUtil              JWTを扱うためのユーティリティ
   */
  public JwtRequestFilter(AccountUserDetailsService accountUserDetailsService, JwtTokenUtil jwtTokenUtil) {
    this.accountUserDetailsService = accountUserDetailsService;
    this.jwtTokenUtil = jwtTokenUtil;
  }

  /**
   * 各HTTPリクエストに対するフィルター処理を実行します。
   * リクエストヘッダーからJWTを抽出し、その有効性を検証後、認証コンテキストに設定します。
   *
   * @param request     HTTPリクエスト
   * @param response    HTTPレスポンス
   * @param filterChain フィルターチェーン
   * @throws ServletException サーブレットの例外
   * @throws IOException      I/Oの例外
   */
  @Override
  protected void doFilterInternal(
      HttpServletRequest request,
      HttpServletResponse response,
      FilterChain filterChain)
      throws ServletException, IOException {

    // トークン取得
    final String jwtToken = extractJwtToken(request);

    // トークンからアカウント名を取得
    String username = null;
    if (jwtToken != null) {
      try {
        username = jwtTokenUtil.getUsernameFromToken(jwtToken);
      } catch (Exception e) {
        logger.warn("JWT Token has expired or is invalid");
      }
    }

    // 認証情報をセット
    setupAuthentication(request, username, jwtToken);

    // フィルター設定
    filterChain.doFilter(request, response);
  }

  /**
   * HTTPリクエストからJWTトークンを抽出します。
   * "Authorization: Bearer <token>" 形式のヘッダーから、"Bearer "を除いたトークンを返します。
   *
   * @param request HTTPリクエスト
   * @return 抽出されたトークン。形式が正しくない場合は{@code null}を返します。
   */
  private String extractJwtToken(HttpServletRequest request) {
    // Authorizationのヘッダー取得
    final String requestTokenHeader = request.getHeader("Authorization");

    // JWTがBearerトークン形式で送られてきた場合、トークンを返却
    if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
      return requestTokenHeader.substring(7);
    }

    // JWTがBearerトークン形式でなければnullを返却
    logger.warn("JWT Token does not begin with Bearer String");
    return null;
  }

  /**
   * 認証情報が設定されていない場合、認証情報をセットアップします。
   * ユーザー名とJWTトークンの有効性を検証し、有効であればSpring Securityの認証コンテキストに設定します。
   *
   * @param request  HTTPリクエスト
   * @param username ユーザー名
   * @param jwtToken JWTトークン
   */
  private void setupAuthentication(HttpServletRequest request, String username, String jwtToken) {
    // 認証がまだ行われていないか、ユーザー名が有効な場合にのみ処理を実行
    if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
      // アカウント情報を取得
      UserDetails userDetails = this.accountUserDetailsService.loadUserByUsername(username);
      // トークンの有効性を検証
      if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
            userDetails, null, userDetails.getAuthorities());
        authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
      }
    }
  }
}
