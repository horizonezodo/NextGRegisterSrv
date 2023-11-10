package com.nextg.register.response;

import lombok.Data;

@Data
public class AccountInfoResponse {
    String firstName;
    String lastName;
    String bio;
    boolean emailVerifired;
    boolean phoneVerifired;
    String imageUrl;
    String email;
    String phoneNumber;
    int rankId;
    String expiredDate;

}
