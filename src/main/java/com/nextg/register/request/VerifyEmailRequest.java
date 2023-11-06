package com.nextg.register.request;

import lombok.Data;

@Data
public class VerifyEmailRequest {
    String email;
    String token;
}
