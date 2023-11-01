package com.nextg.register.request;

import lombok.Data;

import java.util.Set;
@Data
public class RegisterByPhoneRequest {
    private String username;

    private String email;

    private String phone;

    private String password;

    private Set<String> roles;

    private String otp;

    private String firstName;

    private String lastName;

    private int status;
}
