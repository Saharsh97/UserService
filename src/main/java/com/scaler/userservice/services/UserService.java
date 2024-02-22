package com.scaler.userservice.services;

import com.scaler.userservice.exceptions.InvalidPasswordException;
import com.scaler.userservice.exceptions.TokenInvalidOrExpiredException;
import com.scaler.userservice.exceptions.UserAlreadyExistsException;
import com.scaler.userservice.exceptions.UserNotFoundException;
import com.scaler.userservice.models.Token;
import com.scaler.userservice.models.User;
import com.scaler.userservice.repositories.TokenRepository;
import com.scaler.userservice.repositories.UserRepository;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;


import java.util.Calendar;
import java.util.Date;
import java.util.Optional;

@Service
public class UserService {

    private UserRepository userRepository;
    private TokenRepository tokenRepository;
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    public UserService(UserRepository userRepository, TokenRepository tokenRepository, BCryptPasswordEncoder bCryptPasswordEncoder){
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    public User signup(String name, String email, String password) throws UserAlreadyExistsException {
        Optional<User> userOptional = userRepository.findByEmail(email);
        if(userOptional.isPresent()){
            throw new UserAlreadyExistsException("user already exists with the give email id");
        }

        User user = new User();
        user.setName(name);
        user.setEmail(email);
        user.setHashedPassword(bCryptPasswordEncoder.encode(password));

        User savedUser = userRepository.save(user);
        return savedUser;
    }

    public Token login(String email, String password) throws UserNotFoundException, InvalidPasswordException {
        Optional<User> userOptional = userRepository.findByEmail(email);
        if(userOptional.isEmpty()){
            throw new UserNotFoundException("user with this email does not exist. please signup up first");
        }

        User savedUser = userOptional.get();
        if(!bCryptPasswordEncoder.matches(password, savedUser.getHashedPassword())){
            throw new InvalidPasswordException("password is incorrect");
        }

        // both user and password are valid
        Token token = new Token();
        token.setUser(savedUser);

        // expiry is going be 30 days from now.
        Calendar calendar= Calendar.getInstance();
        calendar.add(Calendar.DATE, 30);
        Date datePlus30Days = calendar.getTime();
        token.setExpiryAt(datePlus30Days);

        // token value.
        // JWT token.
        // for now, I will create a alphanumeric string of 120 characters.
        String tokenValue = RandomStringUtils.randomAlphanumeric(120);
        token.setValue(tokenValue);

        Token savedToken = tokenRepository.save(token);
        return savedToken;
    }

    public Token logout(String tokenValue) throws TokenInvalidOrExpiredException {
        // if it was a JWT token, will I do a DB call to validate the token?
        // the token itself is enough to validate itself.
        Optional<Token> tokenOptional = tokenRepository.findTokenByValueAndExpiryAtGreaterThanAndDeleted(tokenValue, new Date(), false);
        if(tokenOptional.isEmpty()){
            throw new TokenInvalidOrExpiredException("token is either expired, or is invalid");
        }
        Token token = tokenOptional.get();
        token.setDeleted(true);
        Token savedToken = tokenRepository.save(token);
        return savedToken;
    }

    public Token validateToken(String tokenValue){
        Optional<Token> tokenOptional = tokenRepository.findTokenByValueAndExpiryAtGreaterThanAndDeleted(tokenValue, new Date(), false);
        if(tokenOptional.isEmpty()){
            return null;
        }
        return tokenOptional.get();
    }
}
