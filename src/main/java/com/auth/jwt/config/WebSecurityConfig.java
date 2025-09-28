package com.auth.jwt.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebSecurityConfig implements WebMvcConfigurer {
  @Override
  public void addCorsMappings(CorsRegistry registry) {
    registry.addMapping("/api/**") // CORSを適用するパスパターン
        .allowedOrigins("http://localhost:3000", "http://127.0.0.1:3000") // Next.jsのオリジン
        .allowedMethods("GET", "POST", "PUT", "DELETE") // 許可するHTTPメソッド
        .allowCredentials(true) // 認証情報（Cookieなど）の送信を許可する場合
        .maxAge(3600); // プリフライトリクエストのキャッシュ時間 (秒) }
  }
}
