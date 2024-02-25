package com.scaler.userservice.security.models;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.scaler.userservice.models.Role;
import com.scaler.userservice.models.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

// 21.
@JsonDeserialize
public class CustomUserDetails implements UserDetails {

    // 22.
    public CustomUserDetails(){}

    // 23. Jackson tries to get all the methods that start with get
    // dont put logic inside the getter methods.
    // rather use an attribute, and just return it in getter.
    // specify each attribute separately. now you dont need user.
    // attributes names should be exactly same!

    // 25. Now everything should run fine.
    // you will get a token after login.

    // 26. Now I want to add more info in my JWT!
    // after break!



    public List<CustomGrantedAuthority> getCustomGrantedAuthorities(User user){
        List<CustomGrantedAuthority> grantedAuthorities = new ArrayList<>();
        for(Role role: user.getRoles()){
            grantedAuthorities.add(new CustomGrantedAuthority(role));
        }

        // 10. now do I anymore need the hardcoded user in SecurityConfig
        return grantedAuthorities;
    }

    public CustomUserDetails(User user) {
        this.authorities = getCustomGrantedAuthorities(user);
        this.password = user.getHashedPassword();
        this.username = user.getEmail();
        this.accountNonExpired = true;
        this.accountNonLocked = true;
        this.credentialsNonExpired = true;
        this.enabled = true;
    }

    private List<CustomGrantedAuthority> authorities;
    private String password;
    private String username;
    private boolean accountNonExpired;
    private boolean accountNonLocked;
    private boolean credentialsNonExpired;
    private boolean enabled;

    // 5. how will I implement these methods.
    // I have an object of User.
    // 5.1 implement all the below methods.
//    private User user;

//    public CustomUserDetails(User user){
//        this.user = user;
//    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // 6. I have to return the roles.
        // It is asking me to return GrantedAuthority.
        // since I am getting This GrantedAuthority from Spring, this will be an? Interface

        // 9. code
//        List<CustomGrantedAuthority> grantedAuthorities = new ArrayList<>();
//        for(Role role: user.getRoles()){
//            grantedAuthorities.add(new CustomGrantedAuthority(role));
//        }
//
//        // 10. now do I anymore need the hardcoded user in SecurityConfig
//        return grantedAuthorities;

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
        // typically google expires inactive accounts in 3 months.
        // yahoo expires in 6 months.
        // for us, it is always valid.
        return accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        // have you seen account blocking in case of banks.
        // too many attempts, sbi
        return accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        // passwords of corporate companies users expire in 3 months etc.
        // for us, not the case
        return credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        // always enabled
        return enabled;
    }

    // in future, you can add these columns in User Table.
    // and answer these methods from the table columns.
}
