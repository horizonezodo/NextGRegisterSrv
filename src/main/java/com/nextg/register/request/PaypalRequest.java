package com.nextg.register.request;

import lombok.Data;

@Data
public class PaypalRequest {
    Double total;
    String currency;
    String description;
}
