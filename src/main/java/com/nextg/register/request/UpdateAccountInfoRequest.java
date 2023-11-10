package com.nextg.register.request;

import lombok.Data;

@Data
public class UpdateAccountInfoRequest {
    private String imageUrl;
    private String firstName;
    private String lastName;
    private String bio;
}
