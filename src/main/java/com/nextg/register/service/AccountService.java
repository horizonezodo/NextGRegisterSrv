package com.nextg.register.service;

import com.nextg.register.model.Account;

public interface AccountService {
    public Account findByPhone(String phone);
    public Account findByEmail(String email);
    boolean checkStatusAccount(int status);
}
