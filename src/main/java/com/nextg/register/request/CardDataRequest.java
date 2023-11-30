package com.nextg.register.request;

import lombok.Data;

@Data
public class CardDataRequest {
    private double amount;
    private String currency;
    private String cardHolderName;
    private String cardType;
    private String cvc;
    private String dayExpired;
    private String cardNumber;
    private Long userId;
    private Long rankId;
    private String description;
    private double tax;
}
