package com.nextg.register.controller;

import com.nextg.register.config.PaypalConfig;
import com.nextg.register.model.*;
import com.nextg.register.repo.*;
import com.nextg.register.request.*;
import com.nextg.register.response.AccountInfoResponse;
import com.nextg.register.response.AccountRankInfoResponse;
import com.nextg.register.response.ErrorCode;
import com.nextg.register.service.*;
import com.paypal.api.payments.Links;
import com.paypal.api.payments.Payment;
import com.paypal.base.rest.PayPalRESTException;
import lombok.extern.slf4j.Slf4j;
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
import java.text.DecimalFormat;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.*;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/account")
@Slf4j
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

    @Autowired
    RankRepository rankRepo;


    @Autowired
    DataCardService dataCardService;

    @Autowired
    CardDataRepository cardDataRepo;


    @GetMapping("/info")
    private ResponseEntity<?> getAccountInfor(@RequestHeader("Authorization")String jwt) throws AccountException {
        if (StringUtils.hasText(jwt) && jwt.startsWith("Bearer ")) {
            String token=  jwt.substring(7, jwt.length());
            Account acc = new Account();
            try{
                acc =accService.findUserProfileByJwt(token);
            }catch (AccountException e){
                log.error("Get info failure : " + acc.getFirstName());
                return new ResponseEntity<>(new ErrorCode("819"),HttpStatus.BAD_REQUEST);
            }
            AccountInfoResponse info = new AccountInfoResponse();
            info.setEmail(acc.getEmail());
            info.setUserId(acc.getId());
            info.setEmailVerifired(acc.isEmailVerifired());
            info.setPhoneVerifired(acc.isPhoneVerifired());
            info.setFirstName(acc.getFirstName());
            info.setLastName(acc.getLastName());
            info.setPhoneNumber(acc.getPhone());
            info.setImageUrl(acc.getImageUrl());
            info.setBio(acc.getBio());
            log.info("Get info Success : " + acc.getFirstName());
            return new ResponseEntity<>(info, HttpStatus.OK);
        }
        log.error("Can not find account info with token : " + jwt);
        return new ResponseEntity<>(new ErrorCode("812"),HttpStatus.BAD_REQUEST);
    }

    @GetMapping("/account-rank")
    private ResponseEntity<?> getAccountRankInfor(@RequestHeader("Authorization")String jwt) throws AccountException {
        if (StringUtils.hasText(jwt) && jwt.startsWith("Bearer ")) {
            String token=  jwt.substring(7, jwt.length());
            Account acc = new Account();
            try{
                acc =accService.findUserProfileByJwt(token);
            }catch (AccountException e){
                log.error("Get info failure : " + acc.getFirstName());
                return new ResponseEntity<>(new ErrorCode("819"),HttpStatus.BAD_REQUEST);
            }
            AccountRankInfoResponse info = new AccountRankInfoResponse();
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH-mm");
            String currentDate = LocalDateTime.now().format(formatter);
            LocalDateTime nowDate = LocalDateTime.parse(currentDate,formatter);

            if(acc.getExpiredRankDate() != null) {
                LocalDateTime dateExpired = LocalDateTime.parse(acc.getExpiredRankDate(),formatter);
                int comparison = dateExpired.compareTo(nowDate);
                if (comparison >= 0) {
                    Optional<Rank> otp = rankRepo.findById((long) acc.getRank_account());
                    if(otp.isEmpty()) return new ResponseEntity<>(new ErrorCode("830"),HttpStatus.BAD_REQUEST);
                    Rank r = otp.get();
                    info.setRankName(r.getRankName());
                    info.setRankId(acc.getRank_account());
                    info.setExpiredDate(acc.getExpiredRankDate());
                } else {
                    info.setRankName("normal");
                    info.setRankId(1);
                    info.setExpiredDate(null);
                }
            }else{
                info.setRankName("normal");
                info.setRankId(1);
                info.setExpiredDate(null);
                acc.setRank_account(1);
                acc.setExpiredRankDate(null);
                accRepo.save(acc);
            }
            log.info("Get info Success : " + acc.getFirstName());
            return new ResponseEntity<>(info, HttpStatus.OK);
        }
        log.error("Can not find account info with token : " + jwt);
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
                log.error("Get account failure : " + jwt);
                return new ResponseEntity<>(new ErrorCode("819"), HttpStatus.BAD_REQUEST);
            }
            if(encoder.matches(request.getOldPass(), acc.getPassword())) {
                acc.setPassword(encoder.encode(request.getNewPass()));
                accRepo.save(acc);
                log.info("Change pass Success : " + acc.getFirstName());
                return new ResponseEntity<>(HttpStatus.OK);
            }
            log.error("Old pass is not correctly: " + request.getOldPass());
            return new ResponseEntity<>(new ErrorCode("814"),HttpStatus.BAD_REQUEST);
        }
        log.error("Cannot change pass : ");
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
            log.info("Update info Success : " + acc.getFirstName());
            return new ResponseEntity<>(HttpStatus.OK);
        }
        log.error("Update info Failure : ");
        return new ResponseEntity<>(new ErrorCode("815"),HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/pay")
    public ResponseEntity<?> paymentWithPayPal(@RequestBody PaypalRequest request) throws AccountException {
        String errorCode = "";

        double discountPersent = 0;
        double tmpCost = 0;
        double tax;
        double discount;
        double total;
        boolean buyNew;

        Optional<Rank> otp = rankRepo.findById((long) request.getRankId());
        if(otp.isEmpty()){
            log.error("No rank found");
            return new ResponseEntity<>(new ErrorCode("830"),HttpStatus.BAD_REQUEST);
        }
        Rank tmpRank = otp.get();


        LocalDateTime currentDate = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH-mm");
        String dateString = currentDate.format(formatter);

        Account account = accService.findAccountById((long) request.getUserId());
        if(account.getRank_account() == 1){
            tmpCost= Double.parseDouble(tmpRank.getRankTotal());
            buyNew = true;
        }else{
            Optional<Rank> rankOtp = rankRepo.findById((long) account.getRank_account());
            if(otp.isEmpty()) {
                log.error("No discount code found");
                return new ResponseEntity<>(new ErrorCode("824"),HttpStatus.BAD_REQUEST);
            }
            Rank currentRankAccount = rankOtp.get();
            buyNew = false;

            double currentRankCost = Double.parseDouble(currentRankAccount.getRankTotal());
            double newRankCost = Double.parseDouble(tmpRank.getRankTotal());

            if(currentRankCost > newRankCost){
                account.setRank_account(request.getRankId());
                accRepo.save(account);
                log.info("Rank updated: " + request.getRankId());
                String url = portUrl + "NextGRegisterSrc/account/pay/OK";
                java.net.URI location = ServletUriComponentsBuilder.fromUriString(url).build().toUri();
                return ResponseEntity.status(HttpStatus.FOUND).location(location).build();
            }else if(currentRankCost < newRankCost){
                LocalDateTime ngayHetHan = LocalDateTime.parse(account.getExpiredRankDate(), formatter);
                LocalDateTime ngayHienTai = LocalDateTime.parse(dateString, formatter);
                long soNgay = ngayHienTai.until(ngayHetHan, java.time.temporal.ChronoUnit.DAYS);
                tmpCost = ((newRankCost - currentRankCost)/30) * soNgay;

            }else{
                tmpCost= Double.parseDouble(tmpRank.getRankTotal());
                buyNew = true;
            }
        }
        tax= tmpCost*0.1;
        Optional<DiscountCode> otp1 = discountCodeRepository.findByCode(request.getDiscountCode());
        if(otp1.isPresent()) {
            DiscountCode discountCode = otp1.get();
            discountPersent= discountCode.getDiscountPercent();
        }else{
            discountPersent = 0;
        }

        discount= tmpCost * (discountPersent/100);
        total= tmpCost - discount +tax;
        DecimalFormat decimalFormat = new DecimalFormat("#.##");
        total = Double.parseDouble(decimalFormat.format(total));

        String date = currentDate.format(formatter);
        Transaction tran = new Transaction();
        tran.setPaymentType("paypal");
        tran.setAmount(total);
        tran.setTax(tax);
        tran.setDiscount(discount);
        tran.setCurrency_code(request.getCurrency());
        tran.setAccountId((long) request.getUserId());
        tran.setDatePayment(LocalDateTime.parse(date, formatter));
        tranRepo.save(tran);
        try {
            Payment payment = service.createPayment(total, request.getCurrency(), "paypal",
                    "sale", request.getDescription(), portUrl + CANCEL_URL +"?userId=" + request.getUserId() + "&transactionId=" + tran.getId(),
                    portUrl + SUCCESS_URL+"?userId=" + request.getUserId() + "&rankId=" + request.getRankId() + "&discountCode=" + request.getDiscountCode() + "&transactionId=" + tran.getId()  + "&buyNew=" + buyNew  );
            for(Links link:payment.getLinks()) {
                if(link.getRel().equals("approval_url")) {
                    System.out.println(link.getHref());
                    java.net.URI location = ServletUriComponentsBuilder.fromUriString(link.getHref()).build().toUri();
                    log.info("Pay with paypal Success : " + request.getUserId());
                    //return ResponseEntity.status(HttpStatus.FOUND).location(location).build();
                    return new ResponseEntity<>(link.getHref(),HttpStatus.OK);
                }
            }
        } catch (PayPalRESTException e) {
            log.error("Pay with paypal get error : " + e.getMessage());
            errorCode = e.getMessage();
            e.printStackTrace();
        }
        log.error("Pay with paypal cancelled : ");
        return new ResponseEntity<>(errorCode,HttpStatus.BAD_REQUEST);
    }

    @GetMapping("/pay/OK")
    public ResponseEntity<?> paySuccess(){
        String frontEnd = "http://localhost:4200/payment";
        java.net.URI location = ServletUriComponentsBuilder.fromUriString(frontEnd).build().toUri();
        return ResponseEntity.status(HttpStatus.FOUND).location(location).build();
    }

    @GetMapping(value = "pay/cancel")
    public ResponseEntity<?> cancelPay(@RequestParam("token")String token,@RequestParam("userId")int userId, @RequestParam("transactionId") String id) {
        Transaction tran = tranRepo.findByIdAndAccountIdAndStatus(Long.parseLong(id), (long) userId,null);
        tran.setStatus("Cancelled");
        tranRepo.save(tran);
        log.info("Pay cancelled  : " + userId);

        String frontEnd = "http://localhost:4200/payment";
        java.net.URI location = ServletUriComponentsBuilder.fromUriString(frontEnd).build().toUri();
        return ResponseEntity.status(HttpStatus.FOUND).location(location).build();
    }

    @GetMapping(value = "pay/success")
    public ResponseEntity<?> successPay(@RequestParam("userId") String userId, @RequestParam("rankId")String rankId,@RequestParam("discountCode")String discountCode,@RequestParam("transactionId")String id,@RequestParam("buyNew")boolean buyNew, @RequestParam("paymentId") String paymentId,@RequestParam("token") String token, @RequestParam("PayerID") String payerId)   {
        String errorCode="";
        try {
            Payment payment = service.executePayment(paymentId, payerId);
            Account acc = accService.findAccountById(Long.parseLong(userId));
            acc.setRank_account(Integer.parseInt(rankId));
            if(buyNew){
                LocalDateTime currentDate = LocalDateTime.now();
                DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH-mm");
                LocalDateTime ngayHetHan = LocalDateTime.parse(acc.getExpiredRankDate(), formatter);
                LocalDateTime futureDate = ngayHetHan.plusDays(30);
                String dateString = futureDate.format(formatter);
                acc.setExpiredRankDate(dateString);
            }
            accRepo.save(acc);
            Transaction tran = tranRepo.findByIdAndAccountIdAndStatus(Long.parseLong(id),acc.getId(), null);

            tran.setStatus("Success");
            tranRepo.save(tran);
            if(discountCode.equalsIgnoreCase(null)){
               deleteAccountUseDiscount(discountCode, Long.parseLong(userId));
            }
            System.out.println(payment.toJSON());
            if (payment.getState().equals("approved")) {
                log.info("Payment Success : " + userId);
                String frontEnd = "http://localhost:4200/payment";
                java.net.URI location = ServletUriComponentsBuilder.fromUriString(frontEnd).build().toUri();
                return ResponseEntity.status(HttpStatus.FOUND).location(location).build();
            }
        } catch (PayPalRESTException | AccountException e) {
            System.out.println(e.getMessage());
            Transaction tran = tranRepo.findByIdAndAccountIdAndStatus(Long.parseLong(id),Long.parseLong(userId), null);
            tran.setStatus("Cancelled");
            tranRepo.save(tran);
            log.error("Payment get error : " + e.getMessage());
            errorCode = e.getMessage();
        }
        log.error("Payment get error : ");
        return new ResponseEntity<>(errorCode,HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/pay-card")
    public ResponseEntity<?> checkout(@RequestBody CardPaymentRequest cardRequest) throws Exception {
            String errorCode="";
            double discountPersent;
            double tmpCost = 0;
            double tax;
            double discount;
            double total;

            Optional<Rank> otp = rankRepo.findById((long) cardRequest.getRankId());
            if(otp.isEmpty()) {
                log.error("No rank found");
                return new ResponseEntity<>(new ErrorCode("830"),HttpStatus.BAD_REQUEST);
            }
            Rank tmpRank = otp.get();

            LocalDateTime currentDate = LocalDateTime.now();
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH-mm");
            String dateString = currentDate.format(formatter);

            Account account = accService.findAccountById((long) cardRequest.getUserId());
            int currentRank = account.getRank_account();
            if(account.getRank_account() == 1){
                account.setRank_account(cardRequest.getRankId());
                LocalDateTime ngayHetHan = LocalDateTime.parse(account.getExpiredRankDate(), formatter);
                LocalDateTime futureDate = ngayHetHan.plusDays(30);
                String futureString = futureDate.format(formatter);
                account.setExpiredRankDate(futureString);
                tmpCost= Double.parseDouble(tmpRank.getRankTotal());
            }else{
                Optional<Rank> rankOtp = rankRepo.findById((long) account.getRank_account());
                if(otp.isEmpty()) {
                    log.error("No discountcode found");
                    return new ResponseEntity<>(new ErrorCode("824"),HttpStatus.BAD_REQUEST);
                }
                Rank currentRankAccount = rankOtp.get();

                 double currentRankCost = Double.parseDouble(currentRankAccount.getRankTotal());
                 double newRankCost = Double.parseDouble(tmpRank.getRankTotal());
                LocalDateTime ngayHetHan = LocalDateTime.parse(account.getExpiredRankDate(), formatter);
                LocalDateTime ngayHienTai = LocalDateTime.parse(dateString, formatter);
                long soNgay = ngayHienTai.until(ngayHetHan, java.time.temporal.ChronoUnit.DAYS);

                 if(newRankCost < currentRankCost){
                     account.setRank_account(cardRequest.getRankId());
                     accRepo.save(account);
                     log.info("Rank updated: " + cardRequest.getRankId());
                     return new ResponseEntity<>(HttpStatus.OK);
                 }else if(newRankCost > currentRankCost){
                     tmpCost = ((newRankCost - currentRankCost)/30) * soNgay;
                     account.setRank_account(cardRequest.getRankId());

                 }else{
                     account.setRank_account(cardRequest.getRankId());
                     LocalDateTime futureDate = ngayHetHan.plusDays(30);
                     String futureString = futureDate.format(formatter);
                     account.setExpiredRankDate(futureString);
                     tmpCost= Double.parseDouble(tmpRank.getRankTotal());
                 }
            }
            Optional<DiscountCode> otp1 = discountCodeRepository.findByCode(cardRequest.getDiscountCode());
            if(otp1.isPresent()) {
                DiscountCode discountCode = otp1.get();
                discountPersent = discountCode.getDiscountPercent();
            }else {
                discountPersent = 0;
            }
            tax= tmpCost*0.1;
            discount= tmpCost * (discountPersent/100);
            total= tmpCost - discount +tax;
            DecimalFormat decimalFormat = new DecimalFormat("#.##");
            total = Double.parseDouble(decimalFormat.format(total));


            Transaction tran = new Transaction();
            tran.setDiscount(discount);
            tran.setAmount(total);
            tran.setCurrency_code(cardRequest.getCurrency());
            tran.setAccountId((long) cardRequest.getUserId());
            tran.setPaymentType(cardRequest.getPaymentType());
            tran.setTax(tax);

            tran.setDatePayment(LocalDateTime.parse(dateString, formatter));


            String paypalApiUrl = "https://api-m.sandbox.paypal.com/v2/checkout/orders";
            //String jsonBody = "{ \"intent\": \"CAPTURE\", \"purchase_units\": [ { \"description\": \""+cardRequest.getDescription()+"\", \"amount\": { \"currency_code\": \""+cardRequest.getCurrency()+"\", \"value\": \""+cardRequest.getAmount()+"\" } } ], \"payment_source\": { \"card\": { \"name\": \""+cardRequest.getCardHolderName()+"\", \"number\": \""+cardRequest.getCardNumber()+"\", \"security_code\": \""+cardRequest.getCvc()+"\",\"expiry\": \""+cardRequest.getDayExpired()+"\",\"return_url\": \""+ portUrl + SUCCESS_URL+"\", \"cancel_url\": \""+portUrl + CANCEL_URL+"\"  } } }";
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("intent","CAPTURE");

            JSONArray purchaseUnitsArray = new JSONArray();
            JSONObject purchaseUnitsObject = new JSONObject();
            purchaseUnitsObject.put("description", cardRequest.getDescription());

            JSONObject amountObject = new JSONObject();
            amountObject.put("value", total);
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

                accRepo.save(account);
                tran.setStatus("Success");
                tranRepo.save(tran);
                deleteAccountUseDiscount(cardRequest.getDiscountCode(),account.getId());
                log.info("Payment with card Success : " + cardRequest.getUserId());
                return new ResponseEntity<>(HttpStatus.OK);
            }
        } catch (Exception e) {
            log.error("Pay with card has been error : " + e.getMessage());
            e.printStackTrace();
            errorCode = e.getMessage();
        }
        tran.setStatus("Failure");
        tranRepo.save(tran);
        log.error("Can not pay with card : ");
        return new ResponseEntity<>(errorCode,HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/getDiscountPercent")
    public ResponseEntity<?> getDiscountPercent(@RequestBody getDiscountCodeRequest request){
        Optional<DiscountCode> otp = discountCodeRepository.findByCode(request.getDiscountCode());
        DiscountCode discount = new DiscountCode();
        if(otp.isPresent()){
            discount = otp.get();
        }else{
            log.error("Can not found discount code : " + request.getDiscountCode());
            return new ResponseEntity<>(new ErrorCode("824"), HttpStatus.BAD_REQUEST);
        }
        LocalDate nowDate = LocalDate.now();
        String expiredDate = discount.getDateExpired();
        LocalDate dateExpired = LocalDate.parse(expiredDate);
        List<String> idList = new ArrayList<>(Arrays.asList(discount.getUserId().split(",")));
        int comparison = dateExpired.compareTo(nowDate);
        if(comparison >=0 &&  (idList.contains(request.getUserId()))) {
            double percent = discount.getDiscountPercent();
            log.info("Get Discount Success : " + request.getUserId());
            return new ResponseEntity<>(percent,HttpStatus.OK);
        }
        log.error("Get Discount Failure : " + request.getUserId());
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

    @PostMapping("/save-data-card")
    public ResponseEntity<?> saveCardData(@RequestBody CardDataRequest request) throws Exception {
        String key = dataCardService.getKey();
        CardData saveCard = new CardData();
        saveCard.setCardNumber(dataCardService.encrypt(request.getCardNumber(),key));
        saveCard.setCardHolderName(dataCardService.encrypt(request.getCardHolderName(),key));
        saveCard.setCvc(dataCardService.encrypt(request.getCvc(),key));
        saveCard.setCurrency(dataCardService.encrypt(request.getCurrency(),key));
        saveCard.setCardType(dataCardService.encrypt(request.getCardType(),key));
        saveCard.setDayExpired(dataCardService.encrypt(request.getDayExpired(),key));
        String amount = String.valueOf(request.getAmount());
        saveCard.setAmount(dataCardService.encrypt(amount,key));
        saveCard.setRankId(request.getRankId());
        saveCard.setUserId(request.getUserId());
        saveCard.setDescription(request.getDescription());
        String tax = String.valueOf(request.getTax());
        saveCard.setTax(dataCardService.encrypt(tax,key));
        cardDataRepo.save(saveCard);
        return new ResponseEntity<>(HttpStatus.OK);
    }

    private CardData getCardData(Long userId) throws Exception {
        String key = dataCardService.getKey();
        Optional<CardData> uc = cardDataRepo.findByUserId(userId);
        if(uc.isPresent()){
            CardData tmpData = uc.get();
            CardData res = new CardData();
            res.setRankId(tmpData.getRankId());
            res.setUserId(tmpData.getUserId());
            res.setAmount(dataCardService.decrypt(tmpData.getAmount(),key));
            res.setCvc(dataCardService.decrypt(tmpData.getCvc(),key));
            res.setCardType(dataCardService.decrypt(tmpData.getCardType(),key));
            res.setCurrency(dataCardService.decrypt(tmpData.getCurrency(),key));
            res.setCardNumber(dataCardService.decrypt(tmpData.getCardNumber(),key));
            res.setCardHolderName(dataCardService.decrypt(tmpData.getCardHolderName(),key));
            res.setDayExpired(dataCardService.decrypt(tmpData.getDayExpired(),key));
            res.setDescription(dataCardService.decrypt(tmpData.getDescription(),key));
            res.setTax(dataCardService.decrypt(tmpData.getTax(),key));
            return res;
        }
        return null;
    }

    @PostMapping("/lower-rank")
    public ResponseEntity<?> lowerRank(@RequestBody LowerRankRequest request){
        Optional<Account> otp = accRepo.findById(request.getUserId());
        if(otp.isEmpty()) return new ResponseEntity<>(new ErrorCode("830"), HttpStatus.BAD_REQUEST);
        Account acc = otp.get();
        acc.setRank_account(request.getNewRank());
        accRepo.save(acc);
        return new ResponseEntity<>(HttpStatus.OK);
    }


////    @PostMapping("/vnpay")
////    public ResponseEntity<?> submitOrder(@RequestBody VnPayRequest request){
////        String baseUrl = "http://localhost:8989";
////        String vnpayUrl = vnService.createOrder(request.getAmount(), request.getOrderInfo(), baseUrl, request.getBankAccount(), request.getBankCode());
////        System.out.println("VNPAY URL "+vnpayUrl);
////        java.net.URI location = ServletUriComponentsBuilder.fromUriString(vnpayUrl).build().toUri();
////        return ResponseEntity.status(HttpStatus.FOUND).location(location).build();
////    }
////
////    @GetMapping("/vnpay/return")
////    public ResponseEntity<?> VnPayReturn(HttpServletRequest request){
////        int paymentStatus = vnService.orderReturn(request);
////        String orderInfo = request.getParameter("vnp_OrderInfo");
////        String paymentTime = request.getParameter("vnp_PayDate");
////        String transactionId = request.getParameter("vnp_TransactionNo");
////        String totalPrice = request.getParameter("vnp_Amount");
////
////        Map<String, Object> res = new HashMap<>();
////        res.put("orderId", orderInfo);
////        res.put("totalPrice", totalPrice);
////        res.put("paymentTime", paymentTime);
////        res.put("transactionId", transactionId);
////        if(paymentStatus == 1) {
////            return new ResponseEntity<>(res, HttpStatus.OK);
////        }
////        return new ResponseEntity<>(res, HttpStatus.BAD_REQUEST);
////    }


}
