//package com.scaler.userservice;
//
//import com.scaler.userservice.security.repository.JpaRegisteredClientRepository;
//import org.junit.jupiter.api.Test;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.context.SpringBootTest;
//import org.springframework.security.oauth2.core.AuthorizationGrantType;
//import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
//import org.springframework.security.oauth2.core.oidc.OidcScopes;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
//import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
//
//import java.util.UUID;
//
//@SpringBootTest
//class UserServiceApplicationTests {
//
//	@Autowired
//	JpaRegisteredClientRepository jpaRegisteredClientRepository;
//
//	@Test
//	void contextLoads() {
//	}
//
//	@Test
//	void registerPostManAsRegisteredClientToMyDB(){
//		RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
//				.clientId("postman-client")
//				.clientSecret("$2a$12$jh1eGc0rFXhANZY08.1pHu0nlAuskJ9Xbrbs69PxJ7VGHlQx5kAlK")
//				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//				.redirectUri("https://oauth.pstmn.io/v1/callback")
//				.postLogoutRedirectUri("https://oauth.pstmn.io/v1/callback")
//				.scope(OidcScopes.OPENID)
//				.scope(OidcScopes.PROFILE)
//				.scope("ADMIN")
//				.scope("STUDENT")
//				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
//				.build();
//		jpaRegisteredClientRepository.save(oidcClient);
//	}
//
//}
