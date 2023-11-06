package com.nextg.register.controller;

import com.nextg.register.model.Account;
import com.nextg.register.repo.AccountRepository;
import com.nextg.register.request.ChangePasswordRequest;
import com.nextg.register.request.PaypalRequest;
import com.nextg.register.request.UpdateAccountInfoRequest;
import com.nextg.register.response.AccountInfoResponse;
import com.nextg.register.response.MessageResponse;
import com.nextg.register.response.UserInfoResponse;
import com.nextg.register.service.AccountServiceImpl;
import com.nextg.register.service.PaymentService;
import com.paypal.api.payments.Links;
import com.paypal.api.payments.Payment;
import com.paypal.base.rest.PayPalRESTException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import javax.security.auth.login.AccountException;
import java.util.ArrayList;
import java.util.List;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/account")
public class UserController {

    @Autowired
    AccountServiceImpl accService;

    @Autowired
    AccountRepository accRepo;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    PaymentService service;

    public static final String SUCCESS_URL = "pay/success";
    public static final String CANCEL_URL = "pay/cancel";

    @Value("${app.client.url}")
    private String portUrl;

    @GetMapping("/info")
    private ResponseEntity<?> getAccountInfor(@RequestHeader("Authorization")String jwt) throws AccountException {
        if (StringUtils.hasText(jwt) && jwt.startsWith("Bearer ")) {
            String token=  jwt.substring(7, jwt.length());
            Account acc = accService.findUserProfileByJwt(token);
            AccountInfoResponse info = new AccountInfoResponse();
            info.setEmail(acc.getEmail());
            info.setEmailVerifired(acc.isEmailVerifired());
            info.setPhoneVerifired(acc.isPhoneVerifired());
            info.setName(acc.getFirstName());
            info.setPhoneNumber(acc.getPhone());
            info.setImageUrl(acc.getImageUrl());
            return new ResponseEntity<>(info, HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/changePass")
    private ResponseEntity<?> changePass(@RequestHeader("Authorization")String jwt, @RequestBody ChangePasswordRequest request) throws AccountException {
        if (StringUtils.hasText(jwt) && jwt.startsWith("Bearer ")) {
            String token=  jwt.substring(7, jwt.length());
            Account acc = accService.findUserProfileByJwt(token);
            if(encoder.matches(request.getOldPass(), acc.getPassword())) {
                acc.setPassword(encoder.encode(request.getNewPass()));
                accRepo.save(acc);
                return new ResponseEntity<>(HttpStatus.OK);
            }
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

    @PutMapping("/update-info")
    private ResponseEntity<?> updateAccountInformation(@RequestHeader("Authorization")String jwt,@RequestBody UpdateAccountInfoRequest request) throws AccountException {
        if (StringUtils.hasText(jwt) && jwt.startsWith("Bearer ")) {
            String token=  jwt.substring(7, jwt.length());
            Account acc = accService.findUserProfileByJwt(token);
            acc.setBio(request.getBio());
            acc.setImageUrl(request.getImageUrl());
            acc.setFirstName(request.getName());
            if(!acc.isEmailVerifired()){
                acc.setPhone(request.getEmail());
                acc.setEmailVerifired(true);
            }
            if(!acc.isPhoneVerifired()){
                acc.setPhone(request.getPhoneNumber());
                acc.setPhoneVerifired(true);
            }
            accRepo.save(acc);
            return new ResponseEntity<>(HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }


    @PostMapping("/pay")
    public String payment(@RequestBody PaypalRequest request) {
        try {
            Payment payment = service.createPayment(request.getTotal(), "USD", "paypal",
                    "sale", request.getDescription(), portUrl + CANCEL_URL,
                    portUrl + SUCCESS_URL);
            for(Links link:payment.getLinks()) {
                if(link.getRel().equals("approval_url")) {
                    return "redirect:"+link.getHref();
                }
            }

        } catch (PayPalRESTException e) {

            e.printStackTrace();
        }
        return "redirect:/";
    }

    @GetMapping(value = CANCEL_URL)
    public String cancelPay() {
        return "cancel";
    }

    @GetMapping(value = SUCCESS_URL)
    public String successPay(@RequestParam("paymentId") String paymentId, @RequestParam("PayerID") String payerId) {
        try {
            Payment payment = service.executePayment(paymentId, payerId);
            System.out.println(payment.toJSON());
            if (payment.getState().equals("approved")) {
                return "success";
            }
        } catch (PayPalRESTException e) {
            System.out.println(e.getMessage());
        }
        return "redirect:/";
    }

}
