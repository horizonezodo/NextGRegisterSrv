package com.nextg.register.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.HashSet;
import java.util.Set;

import javax.persistence.*;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Setter
@Getter
@Table(name = "accounts",
        uniqueConstraints = {
                @UniqueConstraint(columnNames = "phone"),
                @UniqueConstraint(columnNames = "email")
        })
public class Account {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;

    private String email;

    private String phone;

    private String password;

    private String lastName;

    private String firstName;

    private int  status;

    private int rank_account;

    private String expiredRankDate;

    private String imageUrl;

    private String bio;

    private boolean emailVerifired;

    private boolean phoneVerifired;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(	name = "account_roles",
            joinColumns = @JoinColumn(name = "accounts_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles = new HashSet<>();

    public Account(String username, String email, String password,String phone,String firstName,String lastName,int status) {
        this.username = username;
        this.email = email;
        this.password = password;
        this.phone = phone;
        this.firstName = firstName;
        this.lastName = lastName;
        this.status = status;
    }
}
