package com.nextg.register.controller;

import com.nextg.register.config.PaypalConfig;
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
import com.paypal.base.rest.APIContext;
import com.paypal.base.rest.PayPalRESTException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import javax.security.auth.login.AccountException;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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

    @Autowired
    PaypalConfig config;

    public static final String SUCCESS_URL = "pay/success";
    public static final String CANCEL_URL = "pay/cancel";

    @Value("${app.client.url}")
    private String portUrl;

    @Value("${paypal.client.id}")
    private String clientId;
    @Value("${paypal.client.secret}")
    private String clientSecret;

    @Autowired
    private APIContext apiContext;

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
            info.setBio(acc.getBio());
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
            accRepo.save(acc);
            return new ResponseEntity<>(HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }


    @PostMapping("/pay")
    public String paymentWithPayPal(@RequestBody PaypalRequest request) {
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

    @PostMapping("/pay-card")
    public String checkout(@RequestHeader("Authorization")String jwt) throws Exception {
        try {
            String paypalApiUrl = "https://api-m.sandbox.paypal.com/v2/checkout/orders";

            RestTemplate restTemplate = new RestTemplate();

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.set("Authorization", apiContext.getAccessToken());
//            headers.setBasicAuth(clientId, clientSecret);

            HttpEntity<String> requestEntity = new HttpEntity<>("{ \"intent\": \"CAPTURE\", \"purchase_units\": [ { \"reference_id\": \"d9f80740-38f0-11e8-b467-0ed5f89f718b\",\"description\": \"Buy member\", \"amount\": { \"currency_code\": \"USD\", \"value\": \"100.00\" } } ], \"payment_source\": { \"card\": { \"name\": \"Nguyen Hiep Duc\" \"number\": \"4032034096357945\", \"security_code\": \"668\", \"expiry\": \"05/2025\", \"return_url\": \""+portUrl + SUCCESS_URL+"\", \"cancel_url\": \""+portUrl + CANCEL_URL+"\" } } }", headers);

            ResponseEntity<String> responseEntity = restTemplate.postForEntity(paypalApiUrl, requestEntity, String.class);

            // Lấy phản hồi từ ResponseEntity
            String response = responseEntity.getBody();

            // In phản hồi ra màn hình
            System.out.println(response);

            return response;
        } catch (Exception e) {
            e.printStackTrace();
            return "Error occurred: " + e.getMessage();
        }
    }

}
