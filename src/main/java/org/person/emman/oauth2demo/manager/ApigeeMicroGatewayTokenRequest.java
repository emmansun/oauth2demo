package org.person.emman.oauth2demo.manager;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import net.minidev.json.JSONObject;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Date;

public class ApigeeMicroGatewayTokenRequest extends AbstractOptionallyIdentifiedRequest {
  private AuthorizationGrant authzGrant;
  private Scope scope;
  private String clientSecret;

  public ApigeeMicroGatewayTokenRequest(URI uri, ClientID clientID, String clientSecret,
    AuthorizationGrant authzGrant, Scope scope) {
    super(uri, clientID);
    this.scope = scope;
    this.authzGrant = authzGrant;
    this.clientSecret = clientSecret;
  }

  @Override public HTTPRequest toHTTPRequest() {
    if (this.getEndpointURI() == null) {
      throw new SerializeException("The endpoint URI is not specified");
    } else {
      URL url;
      try {
        url = this.getEndpointURI().toURL();
      } catch (MalformedURLException var7) {
        throw new SerializeException(var7.getMessage(), var7);
      }

      HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, url);
      httpRequest.setContentType(CommonContentTypes.APPLICATION_JSON);
      if (this.getClientAuthentication() != null) {
        this.getClientAuthentication().applyTo(httpRequest);
      }

      JSONObject body = new JSONObject();
      body.put("grant_type", this.authzGrant.getType().getValue());
      if (this.scope != null && !this.scope.isEmpty()) {
        body.put("scope", this.scope.toString());
      }

      if (this.getClientID() != null) {
        body.put("client_id", this.getClientID().getValue());
      }
      body.put("client_secret", this.clientSecret);

      httpRequest.setQuery(body.toJSONString());
      return httpRequest;
    }
  }

  public static long getTokenLifeTime(String jwtToken) {
    try {
      DecodedJWT jwt = JWT.decode(jwtToken);
      Date expireAt = jwt.getExpiresAt();
      Date issueAt = jwt.getIssuedAt();
      if (expireAt != null && issueAt != null) {
        return (expireAt.getTime() - issueAt.getTime()) / 1000;
      }
    } catch (JWTDecodeException exception){
    }
    return 0L;
  }

  public static TokenResponse parseResponse(HTTPResponse httpResponse) throws ParseException {
    if (httpResponse.getStatusCode() == 200) {
      JSONObject jsonObject = httpResponse.getContentAsJSONObject();
      String jwtToken = jsonObject.getAsString("token");
      BearerAccessToken token = new BearerAccessToken(jwtToken, getTokenLifeTime(jwtToken), null);
      return new AccessTokenResponse(new Tokens(token, null));
    } else {
      return (TokenResponse)TokenErrorResponse.parse(httpResponse);
    }
  }
}
