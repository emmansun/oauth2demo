package org.person.emman.oauth2demo.manager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public abstract class AbstractOAuthAccessTokenManager {
  public static final String EDGEMICRO_AUTH_TOKEN = "/edgemicro-auth/token";
  protected static final String NO_SCOPE = "[]";
  private Map<String, AccessTokenHolder> accessTokenMap = new ConcurrentHashMap<>();
  private Map<String, Object> scopeLockMap = new ConcurrentHashMap<>();
  protected OAuthConfiguration configuration;
  protected Logger logger = null;

  public AbstractOAuthAccessTokenManager(OAuthConfiguration configuration) {
    this.configuration = configuration;
    logger = LoggerFactory.getLogger(this.getClass());
  }

  protected abstract AccessTokenHolder obtainAccessToken(String[] scopes) throws IOException;

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

  private OAuthAccessTokenManagerImpl.AccessTokenHolder getToken(List<String> scopes,
    boolean requestNewToken) throws IOException {
    String scopeKey = NO_SCOPE;
    String[] requestScopes = new String[0];
    if (scopes != null && !scopes.isEmpty()) {
      requestScopes = (String[]) scopes.toArray(new String[scopes.size()]);
      scopeKey = Arrays.toString(requestScopes);
    }
    OAuthAccessTokenManagerImpl.AccessTokenHolder token = null;
    if (requestNewToken) {
      logger.debug("get token (no cache) for scopes: {}", scopeKey);
      token = obtainAccessToken(requestScopes);
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
        token = obtainAccessToken(scopes);
        accessTokenMap.put(scopeKey, token);
      }

      return token;
    }
  }

  public synchronized void clearAccessTokens() {
    scopeLockMap.clear();
    accessTokenMap.clear();
  }

  public String getAccessToken(boolean requestNewToken) throws IOException {
    return getAccessToken(null, requestNewToken);
  }

  public String getAccessToken() throws IOException {
    return getAccessToken(false);
  }

  public String getAccessToken(List<String> scopes, boolean requestNewToken)
    throws IOException {
    return getToken(scopes, requestNewToken).getToken();
  }

  public String getAccessToken(List<String> scopes) throws IOException {
    return getAccessToken(scopes, false);
  }

  public String getAccessTokenHttpHeader(boolean requestNewToken) throws IOException {
    return getAccessTokenHttpHeader(null, requestNewToken);
  }

  public String getAccessTokenHttpHeader() throws IOException {
    return getAccessTokenHttpHeader(false);
  }

  public String getAccessTokenHttpHeader(List<String> scopes, boolean requestNewToken)
    throws IOException {
    return getToken(scopes, requestNewToken).getHttpHeader();
  }

  public String getAccessTokenHttpHeader(List<String> scopes) throws IOException {
    return this.getAccessTokenHttpHeader(scopes, false);
  }

  protected class AccessTokenHolder {
    private String accessToken;
    private String httpHeaderAccessToken;
    private Date expires;

    protected AccessTokenHolder(String token, long tokenLifetime, String headerToken) {
      this.expires = null;
      this.accessToken = token;
      this.httpHeaderAccessToken = headerToken;
      if (tokenLifetime > 0L) {
        long expirationTime = System.currentTimeMillis() + tokenLifetime * 1000L;
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

    public String getToken() {
      return this.accessToken;
    }

    public String getHttpHeader() {
      return this.httpHeaderAccessToken;
    }
  }
}
