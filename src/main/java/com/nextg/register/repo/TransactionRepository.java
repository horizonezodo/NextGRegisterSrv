package com.nextg.register.repo;

import com.nextg.register.model.Transaction;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;

@Repository
public interface TransactionRepository extends JpaRepository<Transaction,Long> {
    Transaction findByIdAndAccountIdAndStatus(Long id, Long accId,String status);
    //Transaction findByDatePaymentAndStatus(LocalDateTime startTime,LocalDateTime endTime,String status);
}
