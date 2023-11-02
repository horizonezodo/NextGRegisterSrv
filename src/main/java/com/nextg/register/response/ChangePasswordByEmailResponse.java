package com.nextg.register.response;

import lombok.Data;

@Data
public class ChangePasswordByEmailResponse {
    String email;
    String newPass;
}
