package com.nextg.register.request;

import lombok.Data;

@Data
public class VnPayRequest {
    int amount;
    String orderInfo;
    String bankAccount;
    String bankCode;
}
