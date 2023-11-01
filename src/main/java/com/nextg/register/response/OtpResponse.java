package com.nextg.register.response;

import com.nextg.register.model.OtpStatus;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class OtpResponse {
    private OtpStatus status;
    private String message;
}
