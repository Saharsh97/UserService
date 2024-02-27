package com.scaler.userservice.security.services;

import com.scaler.userservice.models.User;
import com.scaler.userservice.repositories.UserRepository;
import com.scaler.userservice.security.models.CustomUserDetails;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository){
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> userOptional = userRepository.findByEmail(username);
        if(userOptional.isEmpty()){
            throw new UsernameNotFoundException("user with email : " + username + " does not exist");
        }

        User user = userOptional.get();
        UserDetails userDetails = new CustomUserDetails(user);
        return userDetails;
    }
}
