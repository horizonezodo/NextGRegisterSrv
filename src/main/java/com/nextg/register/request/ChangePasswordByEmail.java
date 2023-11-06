package com.nextg.register.request;

import lombok.Data;

@Data
public class ChangePasswordByEmail {
    private String email;
    private String newPassword;
    private String tokenChangePass;
}
