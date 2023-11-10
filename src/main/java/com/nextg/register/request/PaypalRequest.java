package com.nextg.register.request;

import lombok.Data;

@Data
public class PaypalRequest {
    double total;
    String currency;
    String description;
    double tax;
    double discount;
    String dayPayment;
    int userId;
    int rankId;
    String dayExpired;


}
