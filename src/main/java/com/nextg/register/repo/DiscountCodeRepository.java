package com.nextg.register.repo;

import com.nextg.register.model.DiscountCode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface DiscountCodeRepository extends JpaRepository<DiscountCode,Long> {
    DiscountCode findByCode(String code);
}
