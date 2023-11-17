package com.nextg.register.response;

import lombok.Data;

@Data
public class ErrorCode {
    String errorCode;

    public ErrorCode(String code) {
        this.errorCode = code;
    }
}
