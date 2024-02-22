package com.scaler.userservice.controllers;

import com.scaler.userservice.dtos.LoginRequestDTO;
import com.scaler.userservice.dtos.LoginResponseDTO;
import com.scaler.userservice.dtos.SignupRequestDTO;
import com.scaler.userservice.exceptions.UserAlreadyExistsException;
import com.scaler.userservice.models.User;
import com.scaler.userservice.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
public class UserController {

    private UserService userService;

    @Autowired
    public UserController(UserService userService){
        this.userService = userService;
    }

    @PostMapping("/register")
    public User signup(@RequestBody SignupRequestDTO signupRequestDTO) throws UserAlreadyExistsException {
        return userService.signup(
                signupRequestDTO.getName(),
                signupRequestDTO.getEmail(),
                signupRequestDTO.getPassword()
        );
    }

    @PostMapping("/login")
    public LoginResponseDTO login(LoginRequestDTO requestDTO){
        return null;
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(){
        return null;
    }
}
