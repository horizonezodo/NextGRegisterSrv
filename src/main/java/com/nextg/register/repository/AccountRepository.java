package com.nextg.register.repository;

import com.nextg.register.entity.Account;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


public interface AccountRepository extends JpaRepository<Account,Long> {
    public Account findByEmail(String email);
    public Account findByMobile(String mobile);
}
