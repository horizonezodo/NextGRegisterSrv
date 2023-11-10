package com.nextg.register.repo;

import com.nextg.register.model.RankDescription;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RankDescriptionRepository extends JpaRepository<RankDescription,Long> {
}
