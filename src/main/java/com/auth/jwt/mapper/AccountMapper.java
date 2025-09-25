package com.auth.jwt.mapper;

import org.apache.ibatis.annotations.Mapper;
import com.auth.jwt.entity.Account;

@Mapper
public interface AccountMapper {
  Account findByUsername(String username);

  void save(Account account);
}
