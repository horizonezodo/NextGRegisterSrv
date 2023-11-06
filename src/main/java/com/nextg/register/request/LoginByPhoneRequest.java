package com.nextg.register.request;

import lombok.Data;

@Data
public class LoginByPhoneRequest {
    private String phone;
    private String otp;
}
