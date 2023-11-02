package com.nextg.register.response;

import lombok.Data;

@Data
public class ValidateSuccessOtpResponse {
    String phoneNumber;
    String otp;

}
