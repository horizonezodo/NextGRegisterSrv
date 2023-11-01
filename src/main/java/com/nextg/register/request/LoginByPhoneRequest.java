package com.nextg.register.request;

import lombok.Data;

@Data
public class LoginByPhoneRequest {
    String phone;
    String password;
}
