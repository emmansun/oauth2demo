package org.person.emman.oauth2demo.manager;

public class OAuthConfiguration {
  private String tokenEndpoint;
  private String clientId;
  private String clientSecret;
  private int connectTimeout = 0;
  private int responseReadTimeout = 0;
  private long tokenTimeoutWindow = 300000L;

  public String getTokenEndpoint() {
    return tokenEndpoint;
  }

  public void setTokenEndpoint(String tokenEndpoint) {
    this.tokenEndpoint = tokenEndpoint;
  }

  public String getClientId() {
    return clientId;
  }

  public void setClientId(String clientId) {
    this.clientId = clientId;
  }

  public String getClientSecret() {
    return clientSecret;
  }

  public void setClientSecret(String clientSecret) {
    this.clientSecret = clientSecret;
  }

  public int getConnectTimeout() {
    return connectTimeout;
  }

  public void setConnectTimeout(int connectTimeout) {
    this.connectTimeout = connectTimeout;
  }

  public int getResponseReadTimeout() {
    return responseReadTimeout;
  }

  public void setResponseReadTimeout(int responseReadTimeout) {
    this.responseReadTimeout = responseReadTimeout;
  }

  public long getTokenTimeoutWindow() {
    return tokenTimeoutWindow;
  }

  public void setTokenTimeoutWindow(long tokenTimeoutWindow) {
    this.tokenTimeoutWindow = tokenTimeoutWindow;
  }
}
