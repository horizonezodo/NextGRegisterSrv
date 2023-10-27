package com.nextg.register.service.Impl;

import com.nextg.register.entity.Account;
import com.nextg.register.repository.AccountRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
@Service
public class AccountDetailsServiceImpl implements UserDetailsService {
    @Autowired
    AccountRepository repo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account acc = repo.findByEmail(username);
        if(acc == null){
            throw new UsernameNotFoundException("Account not found with email " + username);
        }

        List<GrantedAuthority> authorities = new ArrayList<>();
        return new org.springframework.security.core.userdetails.User(
               acc.getEmail(),
               acc.getPassword(),
               authorities
        );
    }
}
