package org.person.emman.oauth2demo.manager;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;

import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.*;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class ProxyHTTPRequest extends HTTPRequest {
  private String proxyHost;
  private int proxyPort;

  public ProxyHTTPRequest(HTTPRequest request, String proxyHost, int proxyPort) {
    super(request.getMethod(), request.getURL());
    this.proxyHost = proxyHost;
    this.proxyPort = proxyPort;
    this.setConnectTimeout(request.getConnectTimeout());
    this.setQuery(request.getQuery());
    this.setReadTimeout(request.getReadTimeout());
    this.setAccept(request.getAccept());
    this.setAuthorization(request.getAuthorization());
    this.setClientIPAddress(request.getClientIPAddress());
    this.setClientX509Certificate(request.getClientX509Certificate());
    this.setClientX509CertificateRootDN(request.getClientX509CertificateRootDN());
    this.setClientX509CertificateSubjectDN(request.getClientX509CertificateSubjectDN());
    this.setFollowRedirects(request.getFollowRedirects());
    this.setFragment(request.getFragment());
    this.setSSLSocketFactory(request.getSSLSocketFactory());
    this.setHostnameVerifier(request.getHostnameVerifier());
  }

  @Override public HttpURLConnection toHttpURLConnection() throws IOException {
    if (this.proxyHost == null || this.proxyHost.trim().length() == 0) {
      return super.toHttpURLConnection();
    } else {
      Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyHost, proxyPort));
      URL finalURL = this.getURL();
      StringBuilder sb;
      if (this.getQuery() != null && (this.getMethod().equals(HTTPRequest.Method.GET) || this
        .getMethod().equals(HTTPRequest.Method.DELETE))) {
        sb = new StringBuilder(this.getURL().toString());
        sb.append('?');
        sb.append(this.getQuery());

        try {
          finalURL = new URL(sb.toString());
        } catch (MalformedURLException e) {
          throw new IOException("Couldn't append query string: " + e.getMessage(), e);
        }
      }

      if (this.getFragment() != null) {
        sb = new StringBuilder(finalURL.toString());
        sb.append('#');
        sb.append(this.getFragment());

        try {
          finalURL = new URL(sb.toString());
        } catch (MalformedURLException e) {
          throw new IOException("Couldn't append raw fragment: " + e.getMessage(), e);
        }
      }

      HttpURLConnection conn = (HttpURLConnection) finalURL.openConnection(proxy);
      if (conn instanceof HttpsURLConnection) {
        HttpsURLConnection sslConn = (HttpsURLConnection) conn;
        sslConn.setHostnameVerifier(this.getHostnameVerifier() != null ?
          this.getHostnameVerifier() :
          getDefaultHostnameVerifier());
        sslConn.setSSLSocketFactory(this.getSSLSocketFactory() != null ?
          this.getSSLSocketFactory() :
          getDefaultSSLSocketFactory());
      }

      Iterator var11 = this.getHeaderMap().entrySet().iterator();

      while (var11.hasNext()) {
        Map.Entry<String, List<String>> header = (Map.Entry) var11.next();
        Iterator iterator = ((List) header.getValue()).iterator();

        while (iterator.hasNext()) {
          String headerValue = (String) iterator.next();
          conn.addRequestProperty((String) header.getKey(), headerValue);
        }
      }

      conn.setRequestMethod(this.getMethod().name());
      conn.setConnectTimeout(this.getConnectTimeout());
      conn.setReadTimeout(this.getReadTimeout());
      conn.setInstanceFollowRedirects(this.getFollowRedirects());
      if (this.getMethod().equals(HTTPRequest.Method.POST) || this.getMethod()
        .equals(HTTPRequest.Method.PUT)) {
        conn.setDoOutput(true);
        if (this.getContentType() != null) {
          conn.setRequestProperty("Content-Type", this.getContentType().toString());
        }

        if (this.getQuery() != null) {
          try {
            OutputStreamWriter writer = new OutputStreamWriter(conn.getOutputStream());
            writer.write(this.getQuery());
            writer.close();
          } catch (IOException e) {
            closeStreams(conn);
            throw e;
          }
        }
      }

      return conn;
    }
  }

  private static void closeStreams(HttpURLConnection conn) {
    if (conn != null) {
      try {
        if (conn.getInputStream() != null) {
          conn.getInputStream().close();
        }
      } catch (Exception e) {
        ;
      }

      try {
        if (conn.getOutputStream() != null) {
          conn.getOutputStream().close();
        }
      } catch (Exception e) {
        ;
      }

      try {
        if (conn.getErrorStream() != null) {
          conn.getOutputStream().close();
        }
      } catch (Exception e) {
        ;
      }

    }
  }
}
