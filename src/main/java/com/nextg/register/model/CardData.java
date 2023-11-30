package com.nextg.register.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Data
public class CardData {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String amount;
    private String currency;
    private String cardHolderName;
    private String cardType;
    private String cvc;
    private String dayExpired;
    private String cardNumber;
    private Long userId;
    private Long rankId;
    private String description;
    private String tax;
}
