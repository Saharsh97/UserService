package com.scaler.userservice.security.models;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.scaler.userservice.models.Role;
import com.scaler.userservice.models.User;
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


    public CustomUserDetails(){}

    public CustomUserDetails(User user){
//        this.user = user;
        this.username = user.getEmail();
        this.password = user.getHashedPassword();
        this.accountNonLocked = true;
        this.accountNonExpired = true;
        this.credentialsNonExpired = true;
        this.enabled = true;

        List<CustomGrantedAuthority> authoritiesList = new ArrayList<>();
        for(Role role: user.getRoles()){
            CustomGrantedAuthority customGrantedAuthority = new CustomGrantedAuthority(role);
            authoritiesList.add(customGrantedAuthority);
        }
        this.authorities = authoritiesList;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // return a List<something which is like a GrantedAuthority>
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
        // google maintains your token for 3months.
        // after that, your account is expired.
        // it has login again, generate token again
        return accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        // banking websites, too many login attempts. locked out
        return accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        // creds or your password has expired.
        return credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        // deactivated or active.
        return enabled;
    }
}
