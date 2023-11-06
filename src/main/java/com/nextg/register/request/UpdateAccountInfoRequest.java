package com.nextg.register.request;

import lombok.Data;

@Data
public class UpdateAccountInfoRequest {
    private String imageUrl;
    private String name;
    private String phoneNumber;
    private String email;
    private String bio;
}
