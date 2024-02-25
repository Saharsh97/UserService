package com.scaler.userservice.models;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.ManyToMany;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@Entity
public class User extends BaseModel{
    private String name;
    private String email;
    private String hashedPassword;
    // 19. change this to eager.
    // run app.
    // now will get to the next page. Consent page is loading.
    // this will not fix the errors. allowlist error

    // 20. Error: If you believe this class is safe to deserialize,
    // please provide an explicit mapping using Jackson.
    // for safety, specifically tell
    // add annotations @JsonDeserialize to CustomUserDetails and CustomGrantedAuthority
    @ManyToMany(fetch=FetchType.EAGER)
    private List<Role> roles;
    private boolean isEmailVerified;
}

// Cardinality of User and Role
// User : Role
// 1    : M
// M    : 1

// M : M