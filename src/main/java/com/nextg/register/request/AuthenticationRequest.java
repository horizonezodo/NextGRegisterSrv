package com.nextg.register.request;

import lombok.Data;

@Data
public class AuthenticationRequest {
    private String otp;
    private String phoneNo;
}
