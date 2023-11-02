package com.nextg.register.service;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.nextg.register.config.TwilioConfig;
import com.nextg.register.model.OtpStatus;
import com.nextg.register.request.OtpRequest;
import com.nextg.register.request.OtpValidationRequest;
import com.nextg.register.response.OtpResponse;
import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.text.DecimalFormat;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Service
public class OtpService {
    @Autowired
    private TwilioConfig twilioConfig;
    Map<String, String> otpMap = new HashMap<>();


    public OtpResponse sendSMS(OtpRequest otpRequest) {
        Twilio.init(twilioConfig.getAccountSid(),twilioConfig.getAuthToken());
        OtpResponse otpResponseDto = null;
        try {
            PhoneNumber to = new PhoneNumber(otpRequest.getPhoneNumber());//to
            PhoneNumber from = new PhoneNumber(twilioConfig.getTrialNumber()); // from
            String otp = generateOTP();
            String otpMessage = "Dear Customer , Your OTP is  " + otp + " for sending sms through Spring boot application. Thank You.";
//            Message message = Message
//                    .creator(to, from,
//                            otpMessage)
//                    .create();
//            otpMap.put(otpRequest.getPhoneNumber(), otp);
            System.out.println(otp);
            otpResponseDto = new OtpResponse(OtpStatus.DELIVERED, otpMessage);
        } catch (Exception e) {
            e.printStackTrace();
            otpResponseDto = new OtpResponse(OtpStatus.FAILED, e.getMessage());
        }
        return otpResponseDto;
    }

    public boolean validateOtp(OtpValidationRequest otpValidationRequest) {
        Twilio.init(twilioConfig.getAccountSid(),twilioConfig.getAuthToken());
        Set<String> keys = otpMap.keySet();
        String tmpPhone = null;
        for(String key : keys)
            tmpPhone = key;
        if (otpValidationRequest.getPhoneNumber().equals(tmpPhone)) {
            otpMap.remove(tmpPhone,otpValidationRequest.getOtpNumber());
            return true;
        } else {
            return false;
        }
    }

    private String generateOTP() {
        return new DecimalFormat("000000")
                .format(new Random().nextInt(999999));
    }
}
