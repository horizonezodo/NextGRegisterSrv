package com.nextg.register.controller;


import com.nextg.register.model.Rank;
import com.nextg.register.model.RankDescription;
import com.nextg.register.repo.RankDescriptionRepository;
import com.nextg.register.repo.RankRepository;
import com.nextg.register.response.AllRankDescriptionResponse;
import com.nextg.register.response.AllRankResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.*;

@RestController
@RequestMapping("/admin-rank")
public class AdminRankController {

    @Autowired
    RankRepository rankRepo;

    @Autowired
    RankDescriptionRepository rankDesRepo;

    @GetMapping("/all-rank")
    public ResponseEntity<?> getAllRank(){
        return new ResponseEntity<>(rankRepo.findAll(), HttpStatus.OK);
    }
    @GetMapping("/all-rank-des")
    public ResponseEntity<?> getAllRankDescriptions(){
        return new ResponseEntity<>(rankDesRepo.findAll(), HttpStatus.OK);
    }
}
