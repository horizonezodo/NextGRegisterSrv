package com.nextg.register.request;

import lombok.Data;

@Data
public class getDiscountCodeRequest {
    private String discountCode;
    private String userId;
}
