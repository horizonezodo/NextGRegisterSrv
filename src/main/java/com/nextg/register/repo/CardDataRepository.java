package com.nextg.register.repo;

import com.nextg.register.model.CardData;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CardDataRepository extends JpaRepository<CardData,Long> {
    Optional<CardData> findByUserId(Long userId);
}
