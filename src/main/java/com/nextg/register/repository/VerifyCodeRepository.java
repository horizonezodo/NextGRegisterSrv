package com.nextg.register.repository;

import com.nextg.register.entity.VerifyCode;
import org.springframework.data.jpa.repository.JpaRepository;

public interface VerifyCodeRepository extends JpaRepository<VerifyCode,Long> {
}
