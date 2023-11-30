package com.nextg.register.service;

import com.nextg.register.config.PaypalConfig;
import com.nextg.register.model.Account;
import com.nextg.register.model.Transaction;
import com.nextg.register.repo.AccountRepository;
import com.nextg.register.repo.DiscountCodeRepository;
import com.nextg.register.repo.TransactionRepository;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONArray;
import org.json.JSONObject;
import org.quartz.Job;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Slf4j
public class CardPaymentAutoService {

//    @Autowired
//    AccountServiceImpl accService;
//
//    @Autowired
//    AccountRepository accRepo;
//
//    @Autowired
//    PaypalConfig config;
//
//    @Autowired
//    TransactionRepository tranRepo;
//
//    @Override
//    public void execute(JobExecutionContext jobExecutionContext) throws JobExecutionException {
//        PaymentDataService details = (PaymentDataService) jobExecutionContext.getMergedJobDataMap().get("subscription");
//        autoRenew(details);
//    }
//
//    private void autoRenew(PaymentDataService service){
//
//        Transaction tran = new Transaction();
//
//        tran.setAmount(service.getAmount());
//        tran.setCurrency_code(service.getCurrency());
//        tran.setAccountId((long) service.getUserId());
//        tran.setPaymentType("card");
//        tran.setTax(service.getTax());
//        LocalDateTime currentDate = LocalDateTime.now();
//        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH-mm");
//        String dateString = currentDate.format(formatter);
//        tran.setDatePayment(LocalDateTime.parse(dateString, formatter));
//
//
//        String paypalApiUrl = "https://api-m.sandbox.paypal.com/v2/checkout/orders";
//        JSONObject jsonObject = new JSONObject();
//        jsonObject.put("intent","CAPTURE");
//
//        JSONArray purchaseUnitsArray = new JSONArray();
//        JSONObject purchaseUnitsObject = new JSONObject();
//        purchaseUnitsObject.put("description", service.getDescription());
//
//        JSONObject amountObject = new JSONObject();
//        amountObject.put("value", service.getAmount());
//        amountObject.put("currency_code", service.getCurrency());
//
//        purchaseUnitsObject.put("amount", amountObject);
//        purchaseUnitsArray.put(purchaseUnitsObject);
//
//        JSONObject paymentSourceObject = new JSONObject();
//        JSONObject cardObject = new JSONObject();
//        JSONObject expirienceContextObject = new JSONObject();
//
//        cardObject.put("name", service.getCardHolderName());
//        cardObject.put("number", service.getCardNumber());
//        cardObject.put("security_code", service.getCvc());
//        cardObject.put("expiry", service.getDayExpired());
//
//        expirienceContextObject.put("return_url",service.getSuccessPort());
//        expirienceContextObject.put("cancel_url", service.getCancelPort());
//
//        cardObject.put("experience_context",expirienceContextObject);
//        paymentSourceObject.put("card",cardObject);
//
//        jsonObject.put("purchase_units",purchaseUnitsArray);
//        jsonObject.put("payment_source",paymentSourceObject);
//
//        HttpRequest request = HttpRequest.newBuilder()
//                .uri(URI.create(paypalApiUrl))
//                .header("Content-Type", "application/json")
//                .header("PayPal-Request-Id", tran.getId() + "")
//                .POST(HttpRequest.BodyPublishers.ofString(jsonObject.toString()))
//                .header("Authorization","Bearer " + service.getAccessToken())
//                .build();
//        System.out.println("request :" + jsonObject);
//        HttpClient httpClient = HttpClient.newHttpClient();
//        try{
//            HttpResponse<String> response = httpClient.send(request,HttpResponse.BodyHandlers.ofString());
//            String res = response.body();
//            JSONObject jsonObject1 = new JSONObject(res);
//            System.out.println(jsonObject1);
//            String paymentStatus = jsonObject1.getString("status");
//            if(paymentStatus.equalsIgnoreCase("COMPLETED"))
//            {
//                Account account = accService.findAccountById((long) service.getUserId());
//                account.setRank_account(service.getRankId());
//                account.setExpiredRankDate(String.valueOf(LocalDate.now().plusMonths(1)));
//                accRepo.save(account);
//                tran.setStatus("Success");
//                tranRepo.save(tran);
//                log.info("Payment with card Success : " + service.getUserId());
//            }
//        } catch (Exception e) {
//            log.error("Pay with card has been error : " + e.getMessage());
//            e.printStackTrace();
//        }
//        tran.setStatus("Failure");
//        tranRepo.save(tran);
//        log.error("Can not pay with card : ");
//    }
}
