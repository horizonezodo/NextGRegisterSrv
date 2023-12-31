package com.nextg.register.repo;

import com.nextg.register.model.Account;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AccountRepository extends JpaRepository<Account,Long> {
    Optional<Account> findByEmail(String email);
    boolean existsByEmail(String email);
    Optional<Account> findByUsername(String username);

    Optional<Account> findByPhone(String phone);
    boolean existsByPhone(String phone);

    boolean existsByStatus(int status);
}
