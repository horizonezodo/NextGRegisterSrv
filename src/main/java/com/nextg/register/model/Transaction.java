package com.nextg.register.model;

import lombok.*;

import javax.persistence.*;
import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class Transaction {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    //private String paymentDate;
    private String paymentType;
    private Long accountId;
    private double amount;
    private double tax;
    private double discount;
    private String currency_code;
    private String status;
    private LocalDateTime datePayment;
}
