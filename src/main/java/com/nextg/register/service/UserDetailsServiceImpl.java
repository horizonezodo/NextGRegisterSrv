package com.nextg.register.service;

import com.nextg.register.model.Account;
import com.nextg.register.repo.AccountRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    AccountRepository repo;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Account user = repo.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Email not found " + email));

        return AccountDetailsImpl.buid(user);
    }
}
