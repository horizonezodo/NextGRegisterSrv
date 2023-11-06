package com.nextg.register.request;

import lombok.Data;

@Data
public class ChangePasswordRequest {
    String oldPass;
    String newPass;
}
