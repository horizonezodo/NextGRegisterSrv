package com.nextg.register.service;

import com.nextg.register.model.Account;
import com.nextg.register.repo.AccountRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class AccountDetailsServiceImpl implements UserDetailsService {
    @Autowired
    AccountRepository repo;

    @Override
    public UserDetails loadUserByUsername(String phone) throws UsernameNotFoundException {
        Account user = repo.findByPhone(phone)
                .orElseThrow(() -> new UsernameNotFoundException("Phone Number not found " + phone));

        return AccountDetailsImpl.buid(user);
    }
}
