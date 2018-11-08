package org.person.emman.oauth2demo.manager;

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.person.emman.oauth2demo.Oauth2demoApplication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class OAuthAccessTokenManagerImpl implements OAuthAccessTokenManager {
  public static final String EDGEMICRO_AUTH_TOKEN = "/edgemicro-auth/token";
  private static Logger LOGGER = LoggerFactory.getLogger(OAuthAccessTokenManagerImpl.class);
  private static final String NO_SCOPE = "[]";
  private OAuthConfiguration configuration;
  private ClientID clientId = null;
  private ClientAuthentication authType = null;
  private AuthorizationGrant grantType = null;
  private ConcurrentHashMap<String, AccessTokenHolder> accessTokenMap = new ConcurrentHashMap<>();
  private ConcurrentHashMap<String, Object> scopeLockMap = new ConcurrentHashMap<>();


  public OAuthAccessTokenManagerImpl(OAuthConfiguration configuration) {
    this.configuration = configuration;
    this.clientId = new ClientID(configuration.getClientId());
    this.authType =
      new ClientSecretBasic(this.clientId, new Secret(configuration.getClientSecret()));
    this.grantType = new ClientCredentialsGrant();

  }

  @Override public String getAccessToken(boolean requestNewToken) throws IOException {
    return getAccessToken(null, requestNewToken);
  }

  @Override public String getAccessToken() throws IOException {
    return getAccessToken(false);
  }

  @Override public String getAccessToken(List<String> scopes, boolean requestNewToken)
    throws IOException {
    return this.getToken(scopes, requestNewToken).getToken().getValue();
  }

  @Override public String getAccessToken(List<String> scopes) throws IOException {
    return getAccessToken(scopes, false);
  }

  @Override public String getAccessTokenHttpHeader(boolean requestNewToken) throws IOException {
    return getAccessTokenHttpHeader(null, requestNewToken);
  }

  @Override public String getAccessTokenHttpHeader() throws IOException {
    return getAccessTokenHttpHeader(false);
  }

  @Override public String getAccessTokenHttpHeader(List<String> scopes, boolean requestNewToken)
    throws IOException {
    return this.getToken(scopes, requestNewToken).getHttpHeader();
  }

  @Override public String getAccessTokenHttpHeader(List<String> scopes) throws IOException {
    return this.getAccessTokenHttpHeader(scopes, false);
  }

  @Override public synchronized void clearAccessTokens() {
    scopeLockMap.clear();
    accessTokenMap.clear();
  }

  private OAuthAccessTokenManagerImpl.AccessTokenHolder getToken(List<String> scopes,
    boolean requestNewToken) throws IOException {
    String scopeKey = "[]";
    String[] requestScopes = new String[0];
    if (scopes != null && !scopes.isEmpty()) {
      requestScopes = (String[]) scopes.toArray(new String[scopes.size()]);
      scopeKey = Arrays.toString(requestScopes);
    }
    OAuthAccessTokenManagerImpl.AccessTokenHolder token = null;
    if (requestNewToken) {
      LOGGER.debug("get token (no cache) for scopes: {}", scopeKey);
      token = this.toAccessTokenHolder(this.obtainAccessToken(requestScopes));
      accessTokenMap.put(scopeKey, token);
    } else {
      Object lock = this.getScopeLock(scopeKey);
      token = this.obtainCachedToken(requestScopes, lock, scopeKey);
    }
    return token;
  }

  private OAuthAccessTokenManagerImpl.AccessTokenHolder obtainCachedToken(String[] scopes,
    Object scopeLock, String scopeKey) throws IOException {
    OAuthAccessTokenManagerImpl.AccessTokenHolder token = null;
    synchronized (scopeLock) {
      token = (OAuthAccessTokenManagerImpl.AccessTokenHolder) accessTokenMap.get(scopeKey);
      if (token == null || token.isExpired(this.configuration.getTokenTimeoutWindow())) {
        token = this.toAccessTokenHolder(this.obtainAccessToken(scopes));
        accessTokenMap.put(scopeKey, token);
      }

      return token;
    }
  }

  private BearerAccessToken obtainAccessToken(String[] scopes) throws IOException {
    BearerAccessToken token = null;
    HTTPRequest request;
    boolean isEdgeMicroAuth = false;
    try {
      URI uri = new URI(this.configuration.getTokenEndpoint());
      LOGGER.debug("Obtaining access token from: {}", this.configuration.getTokenEndpoint());
      if (this.configuration.getTokenEndpoint().contains(EDGEMICRO_AUTH_TOKEN)) {
        request = new ApigeeMicroGatewayTokenRequest(uri, this.clientId, this.configuration.getClientSecret(), this.grantType, new Scope(scopes)).toHTTPRequest();
        isEdgeMicroAuth = true;
      } else {
        request = (new TokenRequest(uri, this.authType, this.grantType, new Scope(scopes))).toHTTPRequest();
      }
      if (this.configuration.getProxyHost() != null
        && this.configuration.getProxyHost().trim().length() > 0) {
        request = new ProxyHTTPRequest(request, this.configuration.getProxyHost().trim(),
          this.configuration.getProxyPort());
      }
    } catch (Exception e) {
      throw new IOException(e.getMessage(), e);
    }

    this.setRequestTimeouts(request);
    TokenResponse response;
    try {
      HTTPResponse httpResponse = request.send();
      if (!isEdgeMicroAuth && httpResponse.getContent() != null && !httpResponse.getContent().isEmpty()) {
        httpResponse.setContent(
          httpResponse.getContent().replaceAll("BearerToken", AccessTokenType.BEARER.getValue()));
      }
      if (isEdgeMicroAuth) {
        response = ApigeeMicroGatewayTokenRequest.parseResponse(httpResponse);
      } else {
        response = TokenResponse.parse(httpResponse);
      }
      if (!response.indicatesSuccess()) {
        LOGGER.error("Access token request failed, HTTP response: {}-{}", httpResponse.getContent(),
          httpResponse.getStatusCode());
        String errorText = null;
        String errorDesc = null;
        if (response instanceof TokenErrorResponse) {
          ErrorObject error = ((TokenErrorResponse) response).getErrorObject();
          if (error != null) {
            errorText = error.getCode();
            errorDesc = error.getDescription();
          }
        }

        String exceptionText =
          "OAuth Token Endpoint returned error: " + errorText + " - " + errorDesc;
        throw new IOException(exceptionText);
      }
    } catch (ParseException e) {
      throw new IOException(e.getMessage(), e);
    }

    if (response instanceof AccessTokenResponse) {
      AccessTokenResponse tokenResponse = (AccessTokenResponse) response;
      BearerAccessToken accessToken = tokenResponse.getTokens().getBearerAccessToken();
      if (accessToken == null) {
        throw new IOException("Bearer Access Token not returned from OAuth Token Endpoint!");
      }

      token = accessToken;
    }

    if (token == null) {
      throw new IOException("No Access Token Response from OAuth Token Endpoint!");
    } else {
      return token;
    }
  }

  private void setRequestTimeouts(HTTPRequest request) {
    if (this.configuration.getConnectTimeout() > 0) {
      request.setConnectTimeout(this.configuration.getConnectTimeout() * 1000);
    }

    if (this.configuration.getResponseReadTimeout() > 0) {
      request.setReadTimeout(this.configuration.getResponseReadTimeout() * 1000);
    }

  }

  private synchronized Object getScopeLock(String key) {
    Object scopeLock = this.scopeLockMap.get(key);
    if (scopeLock == null) {
      scopeLock = new Object();
      this.scopeLockMap.put(key, scopeLock);
    }

    return scopeLock;
  }

  private synchronized void removeScopeLocks(String keyPrefix) {
    Iterator iterator = this.scopeLockMap.keySet().iterator();

    while (iterator.hasNext()) {
      String key = (String) iterator.next();
      if (key != null && key.startsWith(keyPrefix)) {
        iterator.remove();
      }
    }

  }

  private OAuthAccessTokenManagerImpl.AccessTokenHolder toAccessTokenHolder(
    BearerAccessToken token) {
    if (token == null) {
      throw new IllegalStateException("OAuth Access Token must be supplied!");
    } else {
      return new OAuthAccessTokenManagerImpl.AccessTokenHolder(token,
        token.toAuthorizationHeader());
    }
  }

  private class AccessTokenHolder {
    private BearerAccessToken accessToken;
    private String httpHeaderAccessToken;
    private Date expires;

    private AccessTokenHolder(BearerAccessToken token, String headerToken) {
      this.expires = null;
      this.accessToken = token;
      this.httpHeaderAccessToken = headerToken;
      long lifetime = token.getLifetime();
      if (lifetime > 0L) {
        long expirationTime = System.currentTimeMillis() + lifetime * 1000L;
        this.expires = new Date(expirationTime);
      }

    }

    public boolean isExpired(long window) {
      if (this.expires == null) {
        return false;
      } else {
        Date now = new Date();
        Date timeExpires = new Date(this.expires.getTime() - window);
        return !now.before(timeExpires);
      }
    }

    public BearerAccessToken getToken() {
      return this.accessToken;
    }

    public String getHttpHeader() {
      return this.httpHeaderAccessToken;
    }
  }
}
