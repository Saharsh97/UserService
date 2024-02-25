package com.scaler.userservice.security.services;

import com.scaler.userservice.models.User;
import com.scaler.userservice.repositories.UserRepository;
import com.scaler.userservice.security.models.CustomUserDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private UserRepository userRepository;

    @Autowired
    public CustomUserDetailsService(UserRepository userRepository){
        this.userRepository = userRepository;
    }

    @Override
    // 1. in our UserService, we want to allow people to login via what? email
    // for us, this username is nothing but email
    // 2. add UserRepository dependency
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        // 3. load user by email
        Optional<User> userOptional = userRepository.findByEmail(email);
        if(userOptional.isEmpty()){
            throw new UsernameNotFoundException("email not found");
        }

        // 4. I have to return UserDetails.
        // this UserDetails is also an interface.
        // so we can return something that is like an UserDetails interface
        // go inside the interface and check methods.
        // create a CustomUserDetails class.

        // that is why, we dont have to check password here by ourself.
        // spring will automatically call the getPassword() method of CustomUserDetails,
        // get the password, match it, etc.

        //16. implement user details
        // run postman for this user. he should be able to login
        // then see an error page after login
        // Error: org.hibernate.LazyInitializationException: failed to lazily initialize a collection of role:
        // com.scaler.userservice.models.User.roles: could not initialize proxy - no Session

        UserDetails userDetails = new CustomUserDetails(userOptional.get());
        return userDetails;
    }

    // 17. Notes. After a user logs in, UserDetails is converted JSON for JWT,
    // using a library called Jackson
    // we got the error page, because our CustomUserDetails is not able to convert into jwt

    // 18. The error says, lazily loading collection. This is default behaviour.
    // We have to make roles loading as eager.
}
