package com.scaler.userservice.security.models;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import org.springframework.security.core.GrantedAuthority;
import com.scaler.userservice.models.Role;

// 21.
@JsonDeserialize

// 22. now a new error:  (no Creators, like default constructor, exist):
// this is because, Jackson internally calls an empty constructor of This class.
// then it will internally call setters to set all the attributes one by one.
// is there any empty constructor here? no. just create one.
public class CustomGrantedAuthority implements GrantedAuthority {

    // 22.
    public CustomGrantedAuthority(){}

    // 7. what will I use to get GrantedAuthority running
    // Role

    // 8. notes. Spring framework pseudo code
    // class SpringFramework. login method(username, password)
    // UserDetails ud = UserDetailsService.getUerByName(username)
    // both are interfaces, my custom objects fits here.
    // if bcryptEncoder.matches(password, ud.getPassword) => allow.
    // for roles.
    // ud.getRoles() -> again my custom roles object

    // 24. Same is done for this class.

    // 25. now run the code.

    private Role role;
    private String authority;

    public CustomGrantedAuthority(Role role){
        this.authority = role.getName();
    }

    @Override
    public String getAuthority() {
        return authority;
    }
}
