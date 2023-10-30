package com.nextg.register.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Set;

@NoArgsConstructor
@AllArgsConstructor
@Setter
@Getter
public class RegisterRequest {

    private String username;


    private String email;


    private String phone;


    private String password;

    private Set<String> roles;
}
