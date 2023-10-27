package com.nextg.register.service.Impl;

import com.nextg.register.entity.Account;
import com.nextg.register.exception.AccountException;
import com.nextg.register.repository.AccountRepository;
import com.nextg.register.service.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;


import java.util.List;
import java.util.Optional;

@Service
public class AccountServiceImpl implements AccountService {

    @Autowired
    AccountRepository repo;


    @Override
    public Account findById(Long id) throws AccountException {
        Optional<Account> acc = repo.findById(id);
        return acc.get();
    }

    @Override
    public List<Account> findAll() {
        return repo.findAll();
    }

    @Override
    public Account saveAccount(Account acc) {
        
        return null;
    }

    @Override
    public void deleteAccount(Long id) {
        repo.deleteById(id);
    }
}
