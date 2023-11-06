package com.nextg.register.service;

import com.nextg.register.model.Account;

import javax.security.auth.login.AccountException;

public interface AccountService {
    public Account findByPhone(String phone);
    public Account findByEmail(String email);
    boolean checkStatusAccount(int status);
    public Account findAccountById(Long id) throws AccountException;
    public Account findUserProfileByJwt(String jwt) throws AccountException;
}
