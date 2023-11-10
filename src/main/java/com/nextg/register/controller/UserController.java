package com.nextg.register.controller;

import com.nextg.register.config.PaypalConfig;
import com.nextg.register.model.Account;
import com.nextg.register.model.DiscountCode;
import com.nextg.register.model.Transaction;
import com.nextg.register.repo.AccountRepository;
import com.nextg.register.repo.DiscountCodeRepository;
import com.nextg.register.repo.TransactionRepository;
import com.nextg.register.request.*;
import com.nextg.register.response.AccountInfoResponse;
import com.nextg.register.response.MessageResponse;
import com.nextg.register.response.UserInfoResponse;
import com.nextg.register.service.AccountServiceImpl;
import com.nextg.register.service.PayPalCardPayment;
import com.nextg.register.service.PaymentService;
import com.paypal.api.payments.Links;
import com.paypal.api.payments.Payment;
import com.paypal.base.rest.APIContext;
import com.paypal.base.rest.PayPalRESTException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import javax.security.auth.login.AccountException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.LocalDate;

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

    @Autowired
    DiscountCodeRepository discountCodeRepository;

    @Autowired
    TransactionRepository tranRepo;

    public static final String SUCCESS_URL = "account/pay/success";
    public static final String CANCEL_URL = "account/pay/cancel";

    @Value("${server.url}")
    private String portUrl;

    @Value("${paypal.client.id}")
    private String clientId;
    @Value("${paypal.client.secret}")
    private String clientSecret;

    @Autowired
    private APIContext apiContext;
    @Autowired
    PayPalCardPayment payment;

    @GetMapping("/info")
    private ResponseEntity<?> getAccountInfor(@RequestHeader("Authorization")String jwt) throws AccountException {
        if (StringUtils.hasText(jwt) && jwt.startsWith("Bearer ")) {
            String token=  jwt.substring(7, jwt.length());
            Account acc = accService.findUserProfileByJwt(token);
            AccountInfoResponse info = new AccountInfoResponse();
            info.setEmail(acc.getEmail());
            info.setEmailVerifired(acc.isEmailVerifired());
            info.setPhoneVerifired(acc.isPhoneVerifired());
            info.setFirstName(acc.getFirstName());
            info.setLastName(acc.getLastName());
            info.setPhoneNumber(acc.getPhone());
            info.setImageUrl(acc.getImageUrl());
            info.setRankId(acc.getRank_account());
            info.setExpiredDate(acc.getExpiredRankDate());
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
            acc.setFirstName(request.getFirstName());
            acc.setLastName(request.getLastName());
            accRepo.save(acc);
            return new ResponseEntity<>(HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }


    @PostMapping("/pay")
    public String paymentWithPayPal(@RequestBody PaypalRequest request) {
        try {
            Payment payment = service.createPayment(request.getTotal(), request.getCurrency(), "paypal",
                    "sale", request.getDescription(), portUrl + CANCEL_URL,
                    portUrl + SUCCESS_URL + "/userId=" + request.getUserId() + "&rankId=" + request.getRankId());
            for(Links link:payment.getLinks()) {
                if(link.getRel().equals("approval_url")) {
                    Transaction tran = new Transaction();
                    tran.setPaymentType("paypal");
                    tran.setAmount(request.getTotal());
                    tran.setTax(request.getTax());
                    tran.setDiscount(request.getDiscount());
                    tran.setPaymentDate(request.getDayPayment());
                    tranRepo.save(tran);
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
    public ResponseEntity<?> checkout(@RequestBody CardPaymentRequest cardRequest) throws Exception {
            String paypalApiUrl = "https://api-m.sandbox.paypal.com/v2/checkout/orders";
            String jsonBody = "{ \"intent\": \"CAPTURE\", \"purchase_units\": [ \"description\": \""+cardRequest.getDescription()+"\", \"amount\": { \"currency_code\": \""+cardRequest.getCurrency()+"\", \"value\": \""+cardRequest.getAmount()+"\" } } ], \"payment_source\": { \"card\": { \"name\": \""+cardRequest.getCardHolderName()+"\", \"number\": \""+cardRequest.getCardNumber()+"\", \"security_code\": \""+cardRequest.getCvc()+"\", \"expiry\": \""+cardRequest.getDayExpired()+"\", \"return_url\": \"" + portUrl + SUCCESS_URL + "\", \"cancel_url\": \"" + portUrl + CANCEL_URL + "\" } } }";
            String paymentStatus="";
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(paypalApiUrl))
                    .header("Content-Type", "application/json")
                    .header("PayPal-Request-Id","7b92603e-77ed-4896-8e78-5dea2050476a")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                    .header("Authorization","Bearer " + service.getAccessToken())
                    .build();
            HttpClient httpClient = HttpClient.newHttpClient();
            Transaction tran = new Transaction();
            tran.setDiscount(cardRequest.getDiscount());
            tran.setAmount(cardRequest.getAmount());
            tran.setPaymentDate(cardRequest.getDayPayment());
            tran.setCurrency_code(cardRequest.getCurrency());
            tran.setAccount_id((long) cardRequest.getUserId());
            tran.setPaymentType(cardRequest.getPaymentType());
            tran.setTax(cardRequest.getTax());
           try{
            HttpResponse<String> response = httpClient.send(request,HttpResponse.BodyHandlers.ofString());
            String res = response.body();
            JSONObject jsonObject = new JSONObject(res);
            paymentStatus = jsonObject.getString("status");
            if(paymentStatus.equalsIgnoreCase("COMPLETED"))
            {
                Account account = accService.findAccountById((long) cardRequest.getUserId());
                account.setRank_account(cardRequest.getRankId());
                account.setExpiredRankDate(cardRequest.getRank_expired_date());
                accRepo.save(account);
                tran.setStatus("Success");
                tranRepo.save(tran);
                return new ResponseEntity<>(HttpStatus.OK);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        tran.setStatus("Failure");
        tranRepo.save(tran);
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

    @GetMapping("/getDiscountPercent")
    public ResponseEntity<?> getDiscountPercent(@RequestBody getDiscountCodeRequest request){
        DiscountCode discount = discountCodeRepository.findByCode(request.getDiscountCode());
        LocalDate nowDate = LocalDate.now();
        String expiredDate = discount.getDateExpired();
        LocalDate dateExpired = LocalDate.parse(expiredDate);
        if(dateExpired.isBefore(nowDate)) {
            double percent = discount.getDiscountPercent();
            return new ResponseEntity<>(percent,HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

}
