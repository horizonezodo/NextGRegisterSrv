package com.nextg.register.service;

import com.nextg.register.model.Account;
import com.nextg.register.repo.AccountRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AccountServiceImpl implements AccountService{

    @Autowired
    private AccountRepository accRepo;

    @Override
    public Account findByPhone(String phone) {
        return accRepo.findByPhone(phone).get();
    }

    @Override
    public Account findByEmail(String email) {
         return accRepo.findByEmail(email).get();
    }

    @Override
    public boolean checkStatusAccount(int status) {
        if(status == 1){
            return true;
        }
        return false;
    }
}
