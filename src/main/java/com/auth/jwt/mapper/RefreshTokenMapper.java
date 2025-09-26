package com.auth.jwt.mapper;

import java.util.Optional;

import org.apache.ibatis.annotations.Mapper;

import com.auth.jwt.entity.RefreshToken;

@Mapper
public interface RefreshTokenMapper {
  Optional<RefreshToken> findByToken(String token);

  void save(RefreshToken refreshToken);

  Long deleteByAccountId(Long accountId);
}