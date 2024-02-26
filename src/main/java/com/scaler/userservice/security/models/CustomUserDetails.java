package com.scaler.userservice.security.models;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.scaler.userservice.models.Role;
import com.scaler.userservice.models.User;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@JsonDeserialize
public class CustomUserDetails implements UserDetails {

//    private User user;
    private String password;
    private String username;
    private boolean accountNonExpired;
    private boolean accountNonLocked;
    private boolean credentialsNonExpired;
    private boolean enabled;
    private List<CustomGrantedAuthority> authorities;

    @Getter
    private Long userId;

    public CustomUserDetails(){}

    public CustomUserDetails(User user){
        this.username = user.getEmail();
        this.password = user.getHashedPassword();
        this.accountNonExpired = true;
        this.accountNonLocked = true;
        this.credentialsNonExpired = true;
        this.enabled = true;

        List<CustomGrantedAuthority> customGrantedAuthorities = new ArrayList<>();
        for(Role role: user.getRoles()){
            customGrantedAuthorities.add(new CustomGrantedAuthority(role));
        }
        this.authorities = customGrantedAuthorities;

        this.userId = user.getId();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
//        List<CustomGrantedAuthority> customGrantedAuthorities = new ArrayList<>();
//        for(Role role: user.getRoles()){
//            customGrantedAuthorities.add(new CustomGrantedAuthority(role));
//        }
//        return customGrantedAuthorities;
        return this.authorities;
    }

    @Override
    public String getPassword() {
//        return user.getHashedPassword();
        return password;
    }

    @Override
    public String getUsername() {
//        return user.getEmail();
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        // auto expiry of 3 months by google
//        return true;
        return accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        // sbi banking, too many attempts
//        return true;
        return accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        // creds or password locked by company
//        return true;
        return credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
//        return true;
        return enabled;
    }
}
