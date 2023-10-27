package com.nextg.register.service;

import com.nextg.register.entity.Account;
import com.nextg.register.exception.AccountException;

import java.util.List;

public interface AccountService {
    Account findById(Long id) throws AccountException;
    List<Account> findAll();
    Account saveAccount(Account acc);
    void deleteAccount(Long id);
}
