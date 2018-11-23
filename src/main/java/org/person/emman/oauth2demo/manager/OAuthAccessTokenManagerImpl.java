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
import org.springframework.cglib.proxy.Enhancer;

import java.io.IOException;
import java.net.URI;
import java.net.URL;

public class OAuthAccessTokenManagerImpl extends AbstractOAuthAccessTokenManager
  implements OAuthAccessTokenManager {
  private ClientID clientId = null;
  private ClientAuthentication authType = null;
  private AuthorizationGrant grantType = null;

  public OAuthAccessTokenManagerImpl(OAuthConfiguration configuration) {
    super(configuration);
    this.clientId = new ClientID(configuration.getClientId());
    this.authType =
      new ClientSecretBasic(this.clientId, new Secret(configuration.getClientSecret()));
    this.grantType = new ClientCredentialsGrant();
  }

  private HTTPRequest createProxy(HTTPRequest request) {
    if (this.configuration.getProxyHost() != null
      && this.configuration.getProxyHost().trim().length() > 0) {
      Enhancer enhancer = new Enhancer();
      enhancer.setSuperclass(HTTPRequest.class);
      enhancer.setCallback(new HttpRequestInterceptor(this.configuration.getProxyHost().trim(),
        this.configuration.getProxyPort()));

      return (HTTPRequest) enhancer.create(new Class[] {HTTPRequest.Method.class, URL.class},
        new Object[] {request.getMethod(), request.getURL()});
    }
    return request;
  }

  private void setRequestTimeouts(HTTPRequest request) {
    if (this.configuration.getConnectTimeout() > 0) {
      request.setConnectTimeout(this.configuration.getConnectTimeout() * 1000);
    }

    if (this.configuration.getResponseReadTimeout() > 0) {
      request.setReadTimeout(this.configuration.getResponseReadTimeout() * 1000);
    }
  }

  protected AccessTokenHolder obtainAccessToken(String[] scopes) throws IOException {
    BearerAccessToken token = null;
    HTTPRequest request;
    boolean isEdgeMicroAuth = false;
    try {
      URI uri = new URI(this.configuration.getTokenEndpoint());
      logger.debug("Obtaining access token from: {}", this.configuration.getTokenEndpoint());
      if (this.configuration.getTokenEndpoint().contains(EDGEMICRO_AUTH_TOKEN)) {
        request = new ApigeeMicroGatewayTokenRequest(uri, this.clientId,
          this.configuration.getClientSecret(), this.grantType, new Scope(scopes)).toHTTPRequest();
        isEdgeMicroAuth = true;
      } else {
        request =
          (new TokenRequest(uri, this.authType, this.grantType, new Scope(scopes))).toHTTPRequest();
      }
      request = createProxy(request);
    } catch (Exception e) {
      throw new IOException(e.getMessage(), e);
    }

    this.setRequestTimeouts(request);
    TokenResponse response;
    try {
      HTTPResponse httpResponse = request.send();
      if (!isEdgeMicroAuth && httpResponse.getContent() != null && !httpResponse.getContent()
        .isEmpty()) {
        httpResponse.setContent(
          httpResponse.getContent().replaceAll("BearerToken", AccessTokenType.BEARER.getValue()));
      }
      if (isEdgeMicroAuth) {
        response = ApigeeMicroGatewayTokenRequest.parseResponse(httpResponse);
      } else {
        response = TokenResponse.parse(httpResponse);
      }
      if (!response.indicatesSuccess()) {
        logger
          .error("Access token request failed, HTTP response: {}-{}", httpResponse.getStatusCode(),
            httpResponse.getContent());
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
      return toAccessTokenHolder(token);
    }
  }

  private OAuthAccessTokenManagerImpl.AccessTokenHolder toAccessTokenHolder(
    BearerAccessToken token) {
    if (token == null) {
      throw new IllegalStateException("OAuth Access Token must be supplied!");
    } else {
      return new OAuthAccessTokenManagerImpl.AccessTokenHolder(token.getValue(),
        token.getLifetime(), token.toAuthorizationHeader());
    }
  }

}
