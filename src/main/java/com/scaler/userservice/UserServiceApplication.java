package com.scaler.userservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class UserServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(UserServiceApplication.class, args);
	}

}

// 1. I want to use my DB for maintaining users.
// Now we are able to create tokens, for only the registered Users in my table.

// 2. how we can Add Custom data to the JWT
// every field is a claim in Token.
// I have add my own custom claims in the tokens.
// use TokenCustomizer method, and user your CustomUserDetails.

// 3. I want ProductService to accept only Authenticated Request.
