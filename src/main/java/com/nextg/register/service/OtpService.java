package com.nextg.register.service;


import com.twilio.exception.ApiException;
import com.twilio.rest.verify.v2.service.Verification;
import com.twilio.rest.verify.v2.service.VerificationCheck;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class OtpService {

    @Value("${twilio.accountSid}")
    String service_sid;

    public String sendOtp(String phone){
        try {
            Verification verification = Verification.creator(service_sid, phone, "sms").create();
            if("approved".equals(verification.getStatus()) || "pending".equals(verification.getStatus())) {
                return "OTP sent";
            }
            return "some problem";
        }
        catch (ApiException exception) {
            return exception.getMessage();
        }
    }
    public String verifyOTP(String phoneNumber, String otpCode) {

        try {
            VerificationCheck verification = VerificationCheck.creator(service_sid, otpCode).setTo(phoneNumber).create();
            if("approved".equals(verification.getStatus())) {
                return "Valid code";
            }
            return "Invalid code";
        }
        catch (ApiException exception) {
            return exception.getMessage();
        }

    }
}
