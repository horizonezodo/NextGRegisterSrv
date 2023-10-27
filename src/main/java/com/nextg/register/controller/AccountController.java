package com.nextg.register.controller;

import com.nextg.register.entity.Account;
import com.nextg.register.exception.AccountException;
import com.nextg.register.repository.AccountRepository;
import com.nextg.register.service.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@CrossOrigin("*")
public class AccountController {
    @Autowired
    private AccountService accountService;

    @Autowired
    private AccountRepository repo;

    @GetMapping("/accounts")
    public ResponseEntity<List<Account>> getAllAccounts() {
        List<Account> accounts = accountService.findAll();
        if(accounts.isEmpty()){
            return new ResponseEntity<>(HttpStatus.NO_CONTENT);
        }

        return new ResponseEntity<>(accounts, HttpStatus.OK);
    }

    @GetMapping("/profile/{id}")
    public ResponseEntity<Account> findById(@PathVariable Long id) throws AccountException {
        Account account = accountService.findById(id);
        if(account != null){
            return new ResponseEntity<>(account, HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }

    @PostMapping("/createdAccount")
    public ResponseEntity<?> createAccount(@RequestBody Account account){
        return new ResponseEntity<>(accountService.saveAccount(account), HttpStatus.CREATED);
    }

    @PutMapping("/account/{id}")
    public ResponseEntity<?> updateAccount(@PathVariable Long id, @RequestBody Account acc){
        Account account = repo.findById(id).get();
        if(account == null){
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        Account updateAccount = new Account();
        updateAccount.setUsername(account.getUsername());
        return new ResponseEntity<>(repo.save(updateAccount),HttpStatus.OK);
    }

    @DeleteMapping("/account/{id}")
    public ResponseEntity<?> deleteAccount(@PathVariable Long id){
        Account account = repo.findById(id).get();
        if(account == null){
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        accountService.deleteAccount(account.getId());
        return new ResponseEntity<>(account, HttpStatus.OK);
    }
}
