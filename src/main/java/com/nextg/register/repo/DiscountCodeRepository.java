package com.nextg.register.repo;

import com.nextg.register.model.DiscountCode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface DiscountCodeRepository extends JpaRepository<DiscountCode,Long> {
    Optional<DiscountCode> findByCode(String code);
}
