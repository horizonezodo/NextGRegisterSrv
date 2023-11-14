package com.nextg.register.model;

import lombok.*;

import javax.persistence.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class Transaction {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    private String paymentDate;
    private String paymentType;
    private Long account_id;
    private double amount;
    private double tax;
    private double discount;
    private String currency_code;
    private String status;
}
