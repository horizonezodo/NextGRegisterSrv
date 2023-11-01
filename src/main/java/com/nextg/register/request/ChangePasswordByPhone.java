package com.nextg.register.request;

import lombok.Data;

@Data
public class ChangePasswordByPhone {
    private String phoneNumber;
    private String newPassword;
    private String otpChangePass;
}
