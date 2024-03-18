package com.scaler.userservice.controllers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.scaler.userservice.dtos.*;
import com.scaler.userservice.exceptions.InvalidPasswordException;
import com.scaler.userservice.exceptions.TokenInvalidOrExpiredException;
import com.scaler.userservice.exceptions.UserAlreadyExistsException;
import com.scaler.userservice.exceptions.UserNotFoundException;
import com.scaler.userservice.models.Token;
import com.scaler.userservice.models.User;
import com.scaler.userservice.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
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

    @GetMapping("/{id}")
    public User getUserById(@PathVariable("id") Long id) throws UserNotFoundException {
        System.out.println("Got request here at " + System.currentTimeMillis());
        User user = userService.findUserById(id);
        return user;
    }

    @PostMapping("/register")
    public User signup(@RequestBody SignupRequestDTO signupRequestDTO) throws UserAlreadyExistsException, JsonProcessingException {
        return userService.signup(
                signupRequestDTO.getName(),
                signupRequestDTO.getEmail(),
                signupRequestDTO.getPassword()
        );
    }

    @PostMapping("/login")
    public LoginResponseDTO login(@RequestBody LoginRequestDTO requestDTO) throws UserNotFoundException, InvalidPasswordException {
        LoginResponseDTO responseDTO = new LoginResponseDTO();
        Token token = userService.login(requestDTO.getEmail(), requestDTO.getPassword());
        responseDTO.setTokenValue(token.getValue());
        responseDTO.setMessage("SUCCESS");
        return responseDTO;
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody LogoutRequestDTO requestDTO) throws TokenInvalidOrExpiredException {
        Token token = userService.logout(requestDTO.getTokenValue());
        ResponseEntity<Void> responseEntity = new ResponseEntity<>(
               token.isDeleted() == true ? HttpStatus.OK : HttpStatus.INTERNAL_SERVER_ERROR
        );
        return responseEntity;
    }

    // user wants to execute, getAllProducts()
    // ProductService.
    // user will give a token, for the getAllProducts()
    // UserService can validate The Token.

    // ProductService will call the UserService to validate the token.

    @GetMapping("/validate/{tokenValue}")
    public UserDTO validateToken(@PathVariable(name = "tokenValue") String tokenValue){
        Token token = userService.validateToken(tokenValue);
        UserDTO userDTO = UserDTO.from(token.getUser());
        return userDTO;
    }
}
