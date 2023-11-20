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
import com.nextg.register.response.ErrorCode;
import com.nextg.register.service.AccountServiceImpl;
import com.nextg.register.service.VNPayService;
import com.nextg.register.service.PaymentService;
import com.paypal.api.payments.Links;
import com.paypal.api.payments.Payment;
import com.paypal.base.rest.PayPalRESTException;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.security.auth.login.AccountException;
import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

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

    public static final String SUCCESS_URL = "NextGRegisterSrc/account/pay/success";

    public static final String CANCEL_URL = "NextGRegisterSrc/account/pay/cancel";

    @Value("${server.url}")
    private String portUrl;

    @Autowired
    VNPayService payment;

    @Autowired
    VNPayService vnService;

    @GetMapping("/info")
    private ResponseEntity<?> getAccountInfor(@RequestHeader("Authorization")String jwt) throws AccountException {
        if (StringUtils.hasText(jwt) && jwt.startsWith("Bearer ")) {
            String token=  jwt.substring(7, jwt.length());
            Account acc = new Account();
            try{
                acc =accService.findUserProfileByJwt(token);
            }catch (AccountException e){
                return new ResponseEntity<>(new ErrorCode("819"),HttpStatus.BAD_REQUEST);
            }
            AccountInfoResponse info = new AccountInfoResponse();
            info.setEmail(acc.getEmail());
            info.setEmailVerifired(acc.isEmailVerifired());
            info.setPhoneVerifired(acc.isPhoneVerifired());
            info.setFirstName(acc.getFirstName());
            info.setLastName(acc.getLastName());
            info.setPhoneNumber(acc.getPhone());
            info.setImageUrl(acc.getImageUrl());


            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH-mm");
            String currentDate = LocalDateTime.now().format(formatter);
            LocalDateTime nowDate = LocalDateTime.parse(currentDate,formatter);

            if(acc.getExpiredRankDate() != null) {
                LocalDateTime dateExpired = LocalDateTime.parse(acc.getExpiredRankDate(),formatter);
                int comparison = dateExpired.compareTo(nowDate);
                if (comparison >= 0) {
                    info.setRankId(acc.getRank_account());
                    info.setExpiredDate(acc.getExpiredRankDate());
                } else {
                    info.setRankId(1);
                    info.setExpiredDate(null);
                }
            }else{
                info.setRankId(1);
                info.setExpiredDate(null);
                acc.setRank_account(1);
                acc.setExpiredRankDate(null);
                accRepo.save(acc);
            }
            info.setBio(acc.getBio());
            return new ResponseEntity<>(info, HttpStatus.OK);
        }
        return new ResponseEntity<>(new ErrorCode("812"),HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/changePass")
    private ResponseEntity<?> changePass(@RequestHeader("Authorization")String jwt, @RequestBody ChangePasswordRequest request) throws AccountException {
        if (StringUtils.hasText(jwt) && jwt.startsWith("Bearer ")) {
            String token=  jwt.substring(7, jwt.length());
            Account acc = new Account();
            try{
                acc =accService.findUserProfileByJwt(token);
            }catch (AccountException e){
                return new ResponseEntity<>(new ErrorCode("819"), HttpStatus.BAD_REQUEST);
            }
            if(encoder.matches(request.getOldPass(), acc.getPassword())) {
                acc.setPassword(encoder.encode(request.getNewPass()));
                accRepo.save(acc);
                return new ResponseEntity<>(HttpStatus.OK);
            }
            return new ResponseEntity<>(new ErrorCode("814"),HttpStatus.BAD_REQUEST);
        }
        return new ResponseEntity<>(new ErrorCode("813"),HttpStatus.BAD_REQUEST);
    }

    @PutMapping("/update-info")
    private ResponseEntity<?> updateAccountInformation(@RequestHeader("Authorization")String jwt,@RequestBody UpdateAccountInfoRequest request) throws AccountException {
        if (StringUtils.hasText(jwt) && jwt.startsWith("Bearer ")) {
            String token=  jwt.substring(7, jwt.length());
            Account acc = new Account();
            try{
                acc =accService.findUserProfileByJwt(token);
            }catch (AccountException e){
                return new ResponseEntity<>(new ErrorCode("819"),HttpStatus.BAD_REQUEST);
            }
            acc.setBio(request.getBio());
            acc.setImageUrl(request.getImageUrl());
            acc.setFirstName(request.getFirstName());
            acc.setLastName(request.getLastName());
            accRepo.save(acc);
            return new ResponseEntity<>(HttpStatus.OK);
        }
        return new ResponseEntity<>(new ErrorCode("815"),HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/pay")
    public ResponseEntity<?> paymentWithPayPal(@RequestBody PaypalRequest request) {
        String errorCode = "";
        LocalDateTime currentDate = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH-mm");
        String date = currentDate.format(formatter);
        Transaction tran = new Transaction();
        tran.setPaymentType("paypal");
        tran.setAmount(request.getTotal());
        tran.setTax(request.getTax());
        tran.setDiscount(request.getDiscount());
        tran.setCurrency_code(request.getCurrency());
        tran.setAccountId((long) request.getUserId());
        tran.setDatePayment(LocalDateTime.parse(date, formatter));
        tranRepo.save(tran);
        try {
            Payment payment = service.createPayment(request.getTotal(), request.getCurrency(), "paypal",
                    "sale", request.getDescription(), portUrl + CANCEL_URL +"?userId=" + request.getUserId() + "&transactionId=" + tran.getId(),
                    portUrl + SUCCESS_URL+"?userId=" + request.getUserId() + "&rankId=" + request.getRankId() + "&discountCode=" + request.getDiscountCode() + "&transactionId=" + tran.getId()  );
            for(Links link:payment.getLinks()) {
                if(link.getRel().equals("approval_url")) {
                    System.out.println(link.getHref());
                    java.net.URI location = ServletUriComponentsBuilder.fromUriString(link.getHref()).build().toUri();
                    return ResponseEntity.status(HttpStatus.FOUND).location(location).build();
                }
            }
        } catch (PayPalRESTException e) {
            errorCode = e.getMessage();
            e.printStackTrace();
        }
        return new ResponseEntity<>(errorCode,HttpStatus.BAD_REQUEST);
    }

    @GetMapping(value = "pay/cancel")
    public ResponseEntity<?> cancelPay(@RequestParam("token")String token,@RequestParam("userId")int userId, @RequestParam("transactionId") String id) {
        Transaction tran = tranRepo.findByIdAndAccountIdAndStatus(Long.parseLong(id), (long) userId,null);
        tran.setStatus("Cancelled");
        tranRepo.save(tran);
        return new ResponseEntity<>(new ErrorCode("816"),HttpStatus.BAD_REQUEST);
    }

    @GetMapping(value = "pay/success")
    public ResponseEntity<?> successPay(@RequestParam("userId") String userId, @RequestParam("rankId")String rankId,@RequestParam("discountCode")String discountCode,@RequestParam("transactionId")String id, @RequestParam("paymentId") String paymentId,@RequestParam("token") String token, @RequestParam("PayerID") String payerId)   {
        String errorCode="";
        try {
            Payment payment = service.executePayment(paymentId, payerId);
            Account acc = accService.findAccountById(Long.parseLong(userId));
            acc.setRank_account(Integer.parseInt(rankId));
            LocalDateTime currentDate = LocalDateTime.now();
            LocalDateTime futureDate = currentDate.plusMonths(1);
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH-mm");
            String dateString = futureDate.format(formatter);
            acc.setExpiredRankDate(dateString);
            accRepo.save(acc);
            Transaction tran = tranRepo.findByIdAndAccountIdAndStatus(Long.parseLong(id),acc.getId(), null);

            tran.setStatus("Success");
            tranRepo.save(tran);
            deleteAccountUseDiscount(discountCode, Long.parseLong(userId));
            System.out.println(payment.toJSON());
            if (payment.getState().equals("approved")) {
                return new ResponseEntity<>(HttpStatus.OK);
            }
        } catch (PayPalRESTException | AccountException e) {
            System.out.println(e.getMessage());
            Transaction tran = tranRepo.findByIdAndAccountIdAndStatus(Long.parseLong(id),Long.parseLong(userId), null);
            tran.setStatus("Cancelled");
            tranRepo.save(tran);
            errorCode = e.getMessage();
        }
        return new ResponseEntity<>(errorCode,HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/pay-card")
    public ResponseEntity<?> checkout(@RequestBody CardPaymentRequest cardRequest) throws Exception {
            String errorCode="";
            Transaction tran = new Transaction();
            tran.setDiscount(cardRequest.getDiscount());
            tran.setAmount(cardRequest.getAmount());
            tran.setCurrency_code(cardRequest.getCurrency());
            tran.setAccountId((long) cardRequest.getUserId());
            tran.setPaymentType(cardRequest.getPaymentType());
            tran.setTax(cardRequest.getTax());
            LocalDateTime currentDate = LocalDateTime.now();
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH-mm");
            String dateString = currentDate.format(formatter);
            tran.setDatePayment(LocalDateTime.parse(dateString, formatter));


            String paypalApiUrl = "https://api-m.sandbox.paypal.com/v2/checkout/orders";
            //String jsonBody = "{ \"intent\": \"CAPTURE\", \"purchase_units\": [ { \"description\": \""+cardRequest.getDescription()+"\", \"amount\": { \"currency_code\": \""+cardRequest.getCurrency()+"\", \"value\": \""+cardRequest.getAmount()+"\" } } ], \"payment_source\": { \"card\": { \"name\": \""+cardRequest.getCardHolderName()+"\", \"number\": \""+cardRequest.getCardNumber()+"\", \"security_code\": \""+cardRequest.getCvc()+"\",\"expiry\": \""+cardRequest.getDayExpired()+"\",\"return_url\": \""+ portUrl + SUCCESS_URL+"\", \"cancel_url\": \""+portUrl + CANCEL_URL+"\"  } } }";
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("intent","CAPTURE");

            JSONArray purchaseUnitsArray = new JSONArray();
            JSONObject purchaseUnitsObject = new JSONObject();
            purchaseUnitsObject.put("description", cardRequest.getDescription());

            JSONObject amountObject = new JSONObject();
            amountObject.put("value", cardRequest.getAmount());
            amountObject.put("currency_code", cardRequest.getCurrency());

            purchaseUnitsObject.put("amount", amountObject);
            purchaseUnitsArray.put(purchaseUnitsObject);

            JSONObject paymentSourceObject = new JSONObject();
            JSONObject cardObject = new JSONObject();
            JSONObject expirienceContextObject = new JSONObject();

            cardObject.put("name", cardRequest.getCardHolderName());
            cardObject.put("number", cardRequest.getCardNumber());
            cardObject.put("security_code", cardRequest.getCvc());
            cardObject.put("expiry", cardRequest.getDayExpired());

            expirienceContextObject.put("return_url",portUrl + SUCCESS_URL);
            expirienceContextObject.put("cancel_url", portUrl + CANCEL_URL);

            cardObject.put("experience_context",expirienceContextObject);
            paymentSourceObject.put("card",cardObject);

            jsonObject.put("purchase_units",purchaseUnitsArray);
            jsonObject.put("payment_source",paymentSourceObject);

        HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(paypalApiUrl))
                    .header("Content-Type", "application/json")
                    .header("PayPal-Request-Id", tran.getId() + "")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonObject.toString()))
                    .header("Authorization","Bearer " + service.getAccessToken())
                    .build();
            System.out.println("request :" + jsonObject);
            HttpClient httpClient = HttpClient.newHttpClient();
           try{
            HttpResponse<String> response = httpClient.send(request,HttpResponse.BodyHandlers.ofString());
            String res = response.body();
            JSONObject jsonObject1 = new JSONObject(res);
            System.out.println(jsonObject1);
            String paymentStatus = jsonObject1.getString("status");
            if(paymentStatus.equalsIgnoreCase("COMPLETED"))
            {
                Account account = accService.findAccountById((long) cardRequest.getUserId());
                account.setRank_account(cardRequest.getRankId());
                account.setExpiredRankDate(String.valueOf(LocalDate.now().plusMonths(1)));
                accRepo.save(account);
                tran.setStatus("Success");
                tranRepo.save(tran);
                deleteAccountUseDiscount(cardRequest.getDiscountCode(),account.getId());
                return new ResponseEntity<>(HttpStatus.OK);
            }
        } catch (Exception e) {
            e.printStackTrace();
            errorCode = e.getMessage();
        }
        tran.setStatus("Failure");
        tranRepo.save(tran);
        return new ResponseEntity<>(errorCode,HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/getDiscountPercent")
    public ResponseEntity<?> getDiscountPercent(@RequestBody getDiscountCodeRequest request){
        Optional<DiscountCode> otp = discountCodeRepository.findByCode(request.getDiscountCode());
        DiscountCode discount = new DiscountCode();
        if(otp.isPresent()){
            discount = otp.get();
        }else{
            return new ResponseEntity<>(new ErrorCode("824"), HttpStatus.BAD_REQUEST);
        }
        LocalDate nowDate = LocalDate.now();
        String expiredDate = discount.getDateExpired();
        LocalDate dateExpired = LocalDate.parse(expiredDate);
        List<String> idList = new ArrayList<>(Arrays.asList(discount.getUserId().split(",")));
        int comparison = dateExpired.compareTo(nowDate);
        if(comparison >=0 &&  (idList.contains(request.getUserId()))) {
            double percent = discount.getDiscountPercent();
            return new ResponseEntity<>(percent,HttpStatus.OK);
        }
        return new ResponseEntity<>(new ErrorCode("817"),HttpStatus.BAD_REQUEST);
    }

    public void deleteAccountUseDiscount(String discountCode, Long accountId){
        DiscountCode discount = discountCodeRepository.findByCode(discountCode).get();
        String tmpAccountId =  discount.getUserId();
        List<String> myList = new ArrayList<String>(Arrays.asList(tmpAccountId.split(",")));
        if(myList.contains(Long.toString(accountId))){
            myList.remove(Long.toString(accountId));
            String afterId = String.join(",", myList);
            discount.setUserId(afterId);
            discountCodeRepository.save(discount);
        }
    }

    @PostMapping("/vnpay")
    public ResponseEntity<?> submitOrder(@RequestBody VnPayRequest request){
        String baseUrl = "http://localhost:8989";
        String vnpayUrl = vnService.createOrder(request.getAmount(), request.getOrderInfo(), baseUrl, request.getBankAccount(), request.getBankCode());
        System.out.println("VNPAY URL "+vnpayUrl);
        java.net.URI location = ServletUriComponentsBuilder.fromUriString(vnpayUrl).build().toUri();
        return ResponseEntity.status(HttpStatus.FOUND).location(location).build();
    }

    @GetMapping("/vnpay/return")
    public ResponseEntity<?> VnPayReturn(HttpServletRequest request){
        int paymentStatus = vnService.orderReturn(request);
        String orderInfo = request.getParameter("vnp_OrderInfo");
        String paymentTime = request.getParameter("vnp_PayDate");
        String transactionId = request.getParameter("vnp_TransactionNo");
        String totalPrice = request.getParameter("vnp_Amount");

        Map<String, Object> res = new HashMap<>();
        res.put("orderId", orderInfo);
        res.put("totalPrice", totalPrice);
        res.put("paymentTime", paymentTime);
        res.put("transactionId", transactionId);
        if(paymentStatus == 1) {
            return new ResponseEntity<>(res, HttpStatus.OK);
        }
        return new ResponseEntity<>(res, HttpStatus.BAD_REQUEST);
    }


}
