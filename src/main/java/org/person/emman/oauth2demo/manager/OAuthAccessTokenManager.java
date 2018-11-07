package org.person.emman.oauth2demo.manager;

import java.io.IOException;
import java.util.List;

public interface OAuthAccessTokenManager {
  String getAccessToken(boolean requestNewToken) throws IOException;

  String getAccessToken() throws IOException;

  String getAccessToken(List<String> scopes, boolean requestNewToken) throws IOException;

  String getAccessToken(List<String> scopes) throws IOException;

  String getAccessTokenHttpHeader(boolean requestNewToken) throws IOException;

  String getAccessTokenHttpHeader() throws IOException;

  String getAccessTokenHttpHeader(List<String> scopes, boolean requestNewToken) throws IOException;

  String getAccessTokenHttpHeader(List<String> scopes) throws IOException;

  void clearAccessTokens();
}
