package com.nextg.register.repo;

import com.nextg.register.model.Account;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AccountRepository extends JpaRepository<Account,Long> {
    Optional<Account> findByEmail(String email);
    boolean existsByEmail(String email);
    Account findByUsername(String username);
}