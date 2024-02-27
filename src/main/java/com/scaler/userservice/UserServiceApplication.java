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

// 2. how we can Add Custom data to the JWT

// 3. I want ProductService to accept only Authenticated Request.
