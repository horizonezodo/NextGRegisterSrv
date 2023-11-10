package com.nextg.register.service;

import com.fasterxml.jackson.databind.util.JSONPObject;
import com.google.gson.JsonObject;
import com.paypal.api.payments.*;
import com.paypal.base.rest.APIContext;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.web.JsonPath;
import org.springframework.stereotype.Service;

import com.paypal.base.rest.PayPalRESTException;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.*;


@Service
public class PaymentService {

    @Autowired
    private APIContext apiContext;

    @Value("${paypal.client.id}")
    private String clientId;
    @Value("${paypal.client.secret}")
    private String clientSecret;


    public Payment createPayment(
            Double total,
            String currency,
            String method,
            String intent,
            String description,
            String cancelUrl,
            String successUrl) throws PayPalRESTException{
        Amount amount = new Amount();
        amount.setCurrency(currency);
        total = new BigDecimal(total).setScale(2, RoundingMode.HALF_UP).doubleValue();
        amount.setTotal(String.format("%.2f", total));

        Transaction transaction = new Transaction();
        transaction.setDescription(description);
        transaction.setAmount(amount);

        List<Transaction> transactions = new ArrayList<>();
        transactions.add(transaction);

        Payer payer = new Payer();
        payer.setPaymentMethod(method.toString());

        Payment payment = new Payment();
        payment.setIntent(intent.toString());
        payment.setPayer(payer);
        payment.setTransactions(transactions);
        RedirectUrls redirectUrls = new RedirectUrls();
        redirectUrls.setCancelUrl(cancelUrl);
        redirectUrls.setReturnUrl(successUrl);
        payment.setRedirectUrls(redirectUrls);

        return payment.create(apiContext);
    }

    public Payment executePayment(String paymentId, String payerId) throws PayPalRESTException{
        Payment payment = new Payment();
        payment.setId(paymentId);
        PaymentExecution paymentExecute = new PaymentExecution();
        paymentExecute.setPayerId(payerId);
        return payment.execute(apiContext, paymentExecute);
    }

    public Payment createDebitCardPayment(String cardType,String amount,String curency,String cardNumber,String cvc,int expireMonth,int expireYear){
        CreditCard creditCard = new CreditCard();
        creditCard.setNumber(cardNumber);
        creditCard.setType(cardType);
        creditCard.setExpireMonth(expireMonth);
        creditCard.setExpireYear(expireYear);
        creditCard.setCvv2(cvc);

        FundingInstrument fundingInstrument = new FundingInstrument();
        fundingInstrument.setCreditCard(creditCard);

        Payer payer = new Payer();
        payer.setPaymentMethod("credit_card");
        payer.setFundingInstruments(Arrays.asList(fundingInstrument));

        Transaction transaction = new Transaction();
        Amount amountDetail = new Amount();
        amountDetail.setCurrency(curency);
        amountDetail.setTotal(amount);
        transaction.setAmount(amountDetail);
        transaction.setDescription("Buy Membership");

        List<Transaction> transactions = new ArrayList<>();
        transactions.add(transaction);

        Payment payment = new Payment();
        payment.setIntent("sale");
        payment.setPayer(payer);
        payment.setTransactions(transactions);

        try{
            Payment createdPayment = payment.create(apiContext);
            return createdPayment;
        } catch (PayPalRESTException e) {
            e.printStackTrace();
            return null;
        }
    }

    public String getAccessToken(){
        String accessToken ="";
        Map<String,String> formData = new HashMap<>();
        formData.put("grant_type","client_credentials");
        String url = "https://api-m.sandbox.paypal.com/v1/oauth2/token";
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(getFormDataAsString(formData)))
                .header("Authorization", "Basic " +
                        Base64.getEncoder().encodeToString((clientId+":"+clientSecret).getBytes()))
                .build();
        HttpClient httpClient = HttpClient.newHttpClient();
        try{
            HttpResponse<String> res = httpClient.send(request,  HttpResponse.BodyHandlers.ofString());
            String responseBody = res.body();
            JSONObject jsonObject = new JSONObject(responseBody);
            accessToken = jsonObject.getString("access_token");
            System.out.println("Phản hồi từ máy chủ: " + jsonObject);
            System.out.println("Access token: " + accessToken);
        } catch (Exception e) {
        e.printStackTrace();
        }
        return accessToken;
    }

    private static String getFormDataAsString(Map<String, String> formData) {
        StringBuilder formBodyBuilder = new StringBuilder();
        for (Map.Entry<String, String> singleEntry : formData.entrySet()) {
            if (formBodyBuilder.length() > 0) {
                formBodyBuilder.append("&");
            }
            formBodyBuilder.append(URLEncoder.encode(singleEntry.getKey(), StandardCharsets.UTF_8));
            formBodyBuilder.append("=");
            formBodyBuilder.append(URLEncoder.encode(singleEntry.getValue(), StandardCharsets.UTF_8));
        }
        return formBodyBuilder.toString();
    }


}
