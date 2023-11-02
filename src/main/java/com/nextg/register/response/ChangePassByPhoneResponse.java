package com.nextg.register.response;

import lombok.Data;

@Data
public class ChangePassByPhoneResponse {
    String phoneNumber;
    String newPass;
}
