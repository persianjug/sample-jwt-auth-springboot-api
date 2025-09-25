package com.auth.jwt.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/secured")
public class SecuredController {
  @GetMapping("/hello")
  public ResponseEntity<String> getHello(@AuthenticationPrincipal UserDetails userDetails) {
    String username = userDetails.getUsername();
    return ResponseEntity.ok("Hello, " + username + "! This is a secured endpoint.");
  }
}
