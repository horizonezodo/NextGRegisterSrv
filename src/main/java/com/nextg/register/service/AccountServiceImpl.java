package com.nextg.register.service;

import com.nextg.register.jwt.JwtUtils;
import com.nextg.register.model.Account;
import com.nextg.register.repo.AccountRepository;
import org.apache.catalina.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.security.auth.login.AccountException;
import java.util.Optional;

@Service
public class AccountServiceImpl implements AccountService{

    @Autowired
    private AccountRepository accRepo;

    @Autowired
    private JwtUtils untils;

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

    @Override
    public Account findAccountById(Long id) throws AccountException {
        Optional<Account> acc = accRepo.findById(id);
        if(acc.isPresent()){
            return acc.get();
        }
        throw new AccountException("820");
    }

    @Override
    public Account findUserProfileByJwt(String jwt) throws AccountException {
        String email = untils.getEmailFromJwtToken(jwt);
        String phoneNumber = untils.getPhoneFromJwtToken(jwt);
        Optional<Account> acc;
        if(email == null){
            acc = accRepo.findByPhone(phoneNumber);
        }
         else{acc = accRepo.findByEmail(email);}

        if(acc.isPresent()){
            return acc.get();

        }
        throw new AccountException("819");
    }
}
