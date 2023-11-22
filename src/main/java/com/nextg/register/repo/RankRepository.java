package com.nextg.register.repo;

import com.nextg.register.model.Rank;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RankRepository extends JpaRepository<Rank,Long> {

    @Query("SELECT DISTINCT r.id, r.rankName, r.rankTotal ,rd.description as descriptionName, rd.title as title FROM ranks r LEFT JOIN RankDescription rd ON CONCAT(',',r.rankDesId,',') like concat('%,',rd.id,',%') ")
    List<Object[]> getRanksWithDescriptions();
}
