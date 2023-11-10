package com.nextg.register.service;

import com.paypal.core.PayPalEnvironment;
import com.paypal.core.PayPalHttpClient;
import com.paypal.core.object.AccessToken;
import com.paypal.core.request.AccessTokenRequest;

import com.paypal.http.HttpResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;

@Service
public class PayPalCardPayment {

//    @Value("${paypal.client.id}")
//    private String clientId;
//    @Value("${paypal.client.secret}")
//    private String clientSecret;
//
//    public static final String SUCCESS_URL = "pay/success";
//    public static final String CANCEL_URL = "pay/cancel";
//
//    @Value("${app.client.url}")
//    private String portUrl;
//
//    PayPalHttpClient client;
//
//    public PayPalHttpClient getPayPalHttpClient() {
//        PayPalEnvironment environment = new PayPalEnvironment.Sandbox(clientId, clientSecret); // Use 'sandbox' for testing
//        return new PayPalHttpClient(environment);
//    }
//
//    public String getAccessToken() {
//        PayPalHttpClient client = getPayPalHttpClient();
//        AccessTokenRequest accessTokenRequest = new AccessTokenRequest();
//        accessTokenRequest.requestBody(new HashMap<>());
//        try {
//            HttpResponse<AccessToken> response = client.execute(accessTokenRequest);
//            return response.result().accessToken();
//        } catch (IOException e) {
//            e.printStackTrace();
//            return null;
//        }
//    }


}
