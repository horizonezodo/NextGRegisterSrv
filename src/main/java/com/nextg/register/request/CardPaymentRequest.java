package com.nextg.register.request;

import lombok.Data;

@Data
public class CardPaymentRequest {
    String cardHolderName;
    String cardType;
    String description;
    double amount;
    String currency;
    String cardNumber;
    String cvc;
    String dayExpired;
    String paymentType;
    double tax;
    double discount;
    String dayPayment;
    int userId;
    int rankId;
    String rank_expired_date;

}
