package com.nextg.register.config;

import com.twilio.Twilio;
import com.twilio.exception.AuthenticationException;
import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

@Configuration
@Data
@Component
public class TwilioConfig {
    @Value("${twilio.accountSid}")
    private String accountSid;
    @Value("${twilio.authToken}")
    private String authToken;
    @Value("${twilio.trialNumber}")
    private String trialNumber;

    @Bean
    @Primary
    public void setUp() throws AuthenticationException{
        Twilio.init(accountSid,authToken);
    }
}
