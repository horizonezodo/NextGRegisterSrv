package com.nextg.register.request;

import lombok.Data;

@Data
public class AutoPaymentRequest {
    double amount;
    double tax;
    String currency;
    String cardHolderName;
    String cardNumber;
    String cvc;
    String dayExpired;
    Long userId;
    int rankId;
    String successPort;
    String cancelPort;
    String transactionId;
    String accessToken;
    String description;
}
