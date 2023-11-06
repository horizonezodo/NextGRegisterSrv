package com.nextg.register.controller;

import com.nextg.register.model.Account;
import com.nextg.register.repo.AccountRepository;
import com.nextg.register.response.UserInfoResponse;
import com.nextg.register.service.AccountServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.security.auth.login.AccountException;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/account")
public class UserController {

    @Autowired
    AccountServiceImpl accService;

    @GetMapping("/info")
    private ResponseEntity<?> getAccountInfor(@RequestHeader("Authorization")String jwt) throws AccountException {
        if (StringUtils.hasText(jwt) && jwt.startsWith("Bearer ")) {
            String token=  jwt.substring(7, jwt.length());
            Account acc = accService.findUserProfileByJwt(token);
            UserInfoResponse info = new UserInfoResponse();
            info.setEmail(acc.getEmail());
            info.setId(acc.getId());
            info.setUsername(acc.getUsername());
            List<String> tmpRole = new ArrayList<String>();
            tmpRole.add("ROLE_USER");
            info.setRoles(tmpRole);
            info.setPhone(acc.getPhone());
            info.setRefreshToken("Hi HI ");
            info.setToken(jwt);
            return new ResponseEntity<>(info, HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }
}
