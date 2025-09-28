package com.auth.jwt.config;

import java.util.Arrays;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.auth.jwt.filter.JwtRequestFilter;
import com.auth.jwt.service.AccountUserDetailsService;

/**
 * Spring Securityの主要な設定を行うクラスです。
 * このクラスは、パスワードのエンコード、認証管理、そしてHTTPリクエストのセキュリティルールを定義します。
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

  private AccountUserDetailsService userDetailsService;
  private JwtRequestFilter jwtRequestFilter;

  /**
   * SecurityConfigの新しいインスタンスを生成します。
   *
   * @param userDetailsService ユーザー詳細情報を取得するためのサービス
   * @param jwtRequestFilter   JWTトークンを検証するためのカスタムフィルター
   */
  public SecurityConfig(AccountUserDetailsService userDetailsService, JwtRequestFilter jwtRequestFilter) {
    this.userDetailsService = userDetailsService;
    this.jwtRequestFilter = jwtRequestFilter;
  }

  /**
   * パスワードのハッシュ化と検証に使用するPasswordEncoderのBeanを定義します。
   * BCryptアルゴリズムを使用します。
   *
   * @return BCryptPasswordEncoderのインスタンス
   */
  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  /**
   * 認証プロセスを管理するAuthenticationManagerのBeanを定義します。
   * {@link DaoAuthenticationProvider} を使用して、データベースに保存されたユーザー情報とパスワードを検証します。
   *
   * @param passwordEncoder パスワードエンコーダー
   * @return AuthenticationManagerのインスタンス
   */
  @Bean
  public AuthenticationManager authenticationManager(PasswordEncoder passwordEncoder) {
    DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
    authenticationProvider.setUserDetailsService(userDetailsService);
    authenticationProvider.setPasswordEncoder(passwordEncoder);
    return new ProviderManager(authenticationProvider);
  }

  /**
   * HTTPリクエストに対するセキュリティフィルターチェーンを定義します。
   * この設定により、CSRF無効化、ステートレスセッション、認証ルールの定義、カスタムJWTフィルターの追加が行われます。
   *
   * @param http HttpSecurityオブジェクト
   * @return 設定されたSecurityFilterChainのインスタンス
   * @throws Exception 設定中に例外が発生した場合
   */
  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .cors(cors -> cors.configurationSource(corsConfigurationSource()))
        .csrf(csrf -> csrf.disable())
        .authorizeHttpRequests(authorize -> authorize
            // 認証エンドポイントとH2コンソールへのアクセスを許可
            .requestMatchers("/api/auth/**", "/h2-console/**").permitAll()
            // その他のすべてのリクエストには認証を要求
            .anyRequest().authenticated())
        // セッション管理をステートレスに設定
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        // JWTフィルターをUsernamePasswordAuthenticationFilterの前に実行
        .addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

    // H2コンソールがフレーム内で表示できるように設定
    http.headers(headers -> headers.frameOptions(frameOptions -> frameOptions.sameOrigin()));

    return http.build();
  }

  /**
   * CORS (Cross-Origin Resource Sharing) の設定情報を提供するBeanを定義します。
   * Next.jsアプリケーション (http://localhost:3000) からのクロスオリジンリクエストを許可し、
   * JWT認証に必要なヘッダーやメソッドを有効にします。
   * 
   * @return CORS設定を保持するCorsConfigurationSourceのインスタンス
   */
  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();

    // Next.js のオリジンを許可
    configuration.setAllowedOrigins(List.of("http://localhost:3000", "http://127.0.0.1:3000"));

    // プリフライトリクエスト (OPTIONS) を含め、すべての HTTP メソッドを許可
    configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));

    // 認証情報（Cookie, Authorization ヘッダーなど）の送信を許可
    configuration.setAllowCredentials(true);

    // すべてのカスタムヘッダーを許可 (JWT トークンを含む Authorization ヘッダーも含む)
    configuration.setAllowedHeaders(List.of("*"));

    // /api/** のパスにこの CORS 設定を適用
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/api/**", configuration);
    return source;
  }

}
