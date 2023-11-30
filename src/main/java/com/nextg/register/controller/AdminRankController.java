package com.nextg.register.controller;


import com.nextg.register.model.Rank;
import com.nextg.register.model.RankDescription;
import com.nextg.register.repo.RankDescriptionRepository;
import com.nextg.register.repo.RankRepository;
import com.nextg.register.response.ErrorCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/admin-rank")
@Slf4j
public class AdminRankController {

    @Autowired
    RankRepository rankRepo;

    @Autowired
    RankDescriptionRepository rankDesRepo;

    @GetMapping("/all-rank")
    public ResponseEntity<?> getAllRank(){
        log.info("Get all rank Success : " );
        return new ResponseEntity<>(rankRepo.findAll(), HttpStatus.OK);
    }

    @GetMapping("/all-rank-des")
    public ResponseEntity<?> getAllRankDescriptions(){
        log.info("Get all rank description Success : " );
        return new ResponseEntity<>(rankDesRepo.findAllByStatus(true), HttpStatus.OK);
    }

    @GetMapping("/rank")
    public ResponseEntity<?> getRank(@RequestParam("id")Long id){
        log.info("Get rank Success : " + id);
        return new ResponseEntity<>(rankRepo.findById(id), HttpStatus.OK);
    }

    @GetMapping("/rank-des")
    public ResponseEntity<?> getRankDescriptions(@RequestParam("id")Long id){
        log.info("Get rank description Success : " + id);
        return new ResponseEntity<>(rankDesRepo.findById(id), HttpStatus.OK);
    }

    @PostMapping("/add-rank")
    public ResponseEntity<?> addRank(@RequestBody Rank reqeust){
        log.info("add rank Success : " );
        return new ResponseEntity<>(rankRepo.save(reqeust), HttpStatus.OK);
    }

    @PostMapping("/add-rank-des")
    public ResponseEntity<?> addRankDescriptions(@RequestBody RankDescription request){
        log.info("add rank description Success : " );
        return new ResponseEntity<>(rankDesRepo.save(request), HttpStatus.OK);
    }

    @PutMapping("/update-rank")
    public ResponseEntity<?> updateRank(@RequestBody Rank request, @RequestParam("id") Long id){
        Optional<Rank> otp = rankRepo.findById(id);
        if(otp.isPresent()){
            Rank tmpRank = otp.get();
            tmpRank.setRankTotal(request.getRankTotal());
            tmpRank.setRankDesId(request.getRankDesId());
            tmpRank.setRankName(request.getRankName());
            log.info("update rank Success : " + id );
            return new ResponseEntity<>(rankRepo.save(tmpRank), HttpStatus.OK);
        }
        log.info("update rank failure : " + id);
        return new ResponseEntity<>(new ErrorCode("825"), HttpStatus.BAD_REQUEST);
    }

    @PutMapping("/update-rank-des")
    public ResponseEntity<?> updateRankDescription(@RequestBody RankDescription request, @RequestParam("id") Long id){
        Optional<RankDescription> otp = rankDesRepo.findById(id);
        if(otp.isPresent()){
            RankDescription tmpRankDes = otp.get();
            tmpRankDes.setDescription(request.getDescription());
            tmpRankDes.setStatus(request.isStatus());
            tmpRankDes.setTitle(request.getTitle());
            log.info("update rank description Success : " + id );
            return new ResponseEntity<>(rankDesRepo.save(tmpRankDes), HttpStatus.OK);
        }
        log.info("update rank description failure : " +id);
        return new ResponseEntity<>(new ErrorCode("826"), HttpStatus.BAD_REQUEST);
    }

    @DeleteMapping("/delete-rank")
    public ResponseEntity<?> deleteRank(@RequestParam("id")Long id){
        Optional<Rank> otp = rankRepo.findById(id);
        if(otp.isPresent()){
            Rank tmpRank = otp.get();
            rankRepo.delete(tmpRank);
            log.info("delete rank Success : " + id);
            return new ResponseEntity<>(HttpStatus.OK);
        }
        log.info("delete rank  failure : " + id);
        return new ResponseEntity<>(new ErrorCode("827"),HttpStatus.BAD_REQUEST);
    }

    @DeleteMapping("/delete-rank-des")
    public ResponseEntity<?> deleteRankDescription(@RequestParam("id")Long id){
        Optional<RankDescription> otp = rankDesRepo.findById(id);
        if(otp.isPresent()){
            RankDescription tmpRankDes = otp.get();
            rankDesRepo.delete(tmpRankDes);
            log.info("delete rank description Success : " + id );
            return new ResponseEntity<>(HttpStatus.OK);
        }
        log.info("delete rank description failure : " + id );
        return new ResponseEntity<>(new ErrorCode("828"),HttpStatus.BAD_REQUEST);
    }

    @GetMapping("/allRanks")
    public ResponseEntity<?> getAllRanks(){
        List<Rank> li = rankRepo.findAll();
        List<Object> obj = new ArrayList<>();
        for (Rank r : li){
            Map json = new HashMap<>();
            json.put("id", r.getId());
            json.put("name",r.getRankName());
            json.put("total",r.getRankTotal());
            String liId = r.getRankDesId();
            List<String> idList = new ArrayList<>(Arrays.asList(liId.split(",")));
            List<Object> desObj = new ArrayList<>();
            if(r.getRankName().equalsIgnoreCase("normal")){
                json.put("description",null);
            }else {
                List<RankDescription> otp = rankDesRepo.findAll();
                for (RankDescription d : otp){
                    Map desc = new HashMap();
                    desc.put("description", d.getDescription());
                    desc.put("title", d.getTitle());

                    desObj.add(desc);
                    boolean check = false;
                    for (String i: idList){
                        if(i.equals(d.getId().toString())){
                            check = true;
                        }
                    }
                    if(check){
                        desc.put("status",d.isStatus());
                    }else{
                        desc.put("status",false);
                    }
                }

                json.put("description", desObj);
            }
            obj.add(json);
        }
        System.out.println(obj);
        log.info("Get all rank with description Success : " );
        return ResponseEntity.ok(obj);
    }

}
