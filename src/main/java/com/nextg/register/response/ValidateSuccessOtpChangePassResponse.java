package com.nextg.register.response;

import lombok.Data;

@Data
public class ValidateSuccessOtpChangePassResponse {
    String phoneNumber;
    String token;
}
