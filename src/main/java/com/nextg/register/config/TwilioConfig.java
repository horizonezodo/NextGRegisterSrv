package com.nextg.register.config;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

@Configuration
@ConfigurationProperties(prefix = "twilio")
@Data
@Component
public class TwilioConfig {
    private String accountSid;
    private String authToken;
    private String trialNumber;


}
