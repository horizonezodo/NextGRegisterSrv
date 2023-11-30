package com.nextg.register.service;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@NoArgsConstructor
@AllArgsConstructor
@Data
public class PaymentDataService {
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
