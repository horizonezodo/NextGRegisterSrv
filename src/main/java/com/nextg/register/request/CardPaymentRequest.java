package com.nextg.register.request;

import lombok.Data;

@Data
public class CardPaymentRequest {
    String cardHolderName;
    String cardType;
    String description;
    String currency;
    String cardNumber;
    String cvc;
    String dayExpired;
    String paymentType;
    int userId;
    int rankId;
    String discountCode;
}
