package org.person.emman.oauth2demo.manager;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OAuthAccessTokenManagerFactory {
  @Bean public OAuthAccessTokenManager getOAuthAccessTokenManager(
    @Value("${oauth.tokenEndpoint}") String tokenEndpoint, @Value("${oauth.clientId}") String clientId,
    @Value("${oauth.clientSecret}") String clientSecret) {
    OAuthConfiguration configuration = new OAuthConfiguration();
    configuration.setTokenEndpoint(tokenEndpoint);
    configuration.setClientId(clientId);
    configuration.setClientSecret(clientSecret);
    return new OAuthAccessTokenManagerImpl(configuration);
  }
}
