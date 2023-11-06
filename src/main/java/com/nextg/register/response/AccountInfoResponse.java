package com.nextg.register.response;

import lombok.Data;

@Data
public class AccountInfoResponse {
    String name;
    String bio;
    boolean emailVerifired;
    boolean phoneVerifired;
    String imageUrl;
    String email;
    String phoneNumber;

}
