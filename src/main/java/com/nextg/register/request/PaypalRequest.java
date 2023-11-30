package com.nextg.register.request;

import lombok.Data;

@Data
public class PaypalRequest {
    String currency;
    String description;
    //String dayPayment;
    int userId;
    int rankId;
    //String dayExpired;
    String discountCode;

}
