package com.nextg.register.service;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.nextg.register.model.Account;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class AccountDetailsImpl implements UserDetails {
    private static final long serialVersionUID =1L;

    private Long id;

    private String username;

    private String email;

    private String phone;


    @JsonIgnore
    private String password;

    private Collection<? extends GrantedAuthority> authorities;

    public static  AccountDetailsImpl buid(Account account){
        List<GrantedAuthority> authorities =
                account.getRoles().stream()
                        .map(role -> new SimpleGrantedAuthority(role.getName().name()))
                        .collect(Collectors.toList());
        return new AccountDetailsImpl(
                account.getId(),
                account.getUsername(),
                account.getEmail(),
                account.getPhone(),
                account.getPassword(),
                authorities
        );
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
