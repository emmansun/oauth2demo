package org.person.emman.oauth2demo.manager;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import org.springframework.cglib.proxy.MethodInterceptor;
import org.springframework.cglib.proxy.MethodProxy;

import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.lang.reflect.Method;
import java.net.*;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class HttpRequestInterceptor implements MethodInterceptor {
  private String proxyHost;
  private int proxyPort;

  public HttpRequestInterceptor(String proxyHost, int proxyPort) {
    this.proxyHost = proxyHost;
    this.proxyPort = proxyPort;
  }

  @Override
  public Object intercept(Object obj, Method method, Object[] args, MethodProxy methodProxy)
    throws Throwable {
    if (method.getName().equals("toHttpURLConnection") && method.getParameterCount() == 0) {
      return this.toHttpURLConnection((HTTPRequest)obj);
    } else {
      return methodProxy.invokeSuper(obj, args);
    }
  }

  public HttpURLConnection toHttpURLConnection(HTTPRequest requst) throws IOException {
    Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyHost, proxyPort));
    URL finalURL = requst.getURL();
    StringBuilder sb;
    if (requst.getQuery() != null && (requst.getMethod().equals(HTTPRequest.Method.GET) || requst
      .getMethod().equals(HTTPRequest.Method.DELETE))) {
      sb = new StringBuilder(requst.getURL().toString());
      sb.append('?');
      sb.append(requst.getQuery());

      try {
        finalURL = new URL(sb.toString());
      } catch (MalformedURLException e) {
        throw new IOException("Couldn't append query string: " + e.getMessage(), e);
      }
    }

    if (requst.getFragment() != null) {
      sb = new StringBuilder(finalURL.toString());
      sb.append('#');
      sb.append(requst.getFragment());

      try {
        finalURL = new URL(sb.toString());
      } catch (MalformedURLException e) {
        throw new IOException("Couldn't append raw fragment: " + e.getMessage(), e);
      }
    }

    HttpURLConnection conn = (HttpURLConnection) finalURL.openConnection(proxy);
    if (conn instanceof HttpsURLConnection) {
      HttpsURLConnection sslConn = (HttpsURLConnection) conn;
      sslConn.setHostnameVerifier(requst.getHostnameVerifier() != null ?
        requst.getHostnameVerifier() :
        requst.getDefaultHostnameVerifier());
      sslConn.setSSLSocketFactory(requst.getSSLSocketFactory() != null ?
        requst.getSSLSocketFactory() :
        requst.getDefaultSSLSocketFactory());
    }

    Iterator var11 = requst.getHeaderMap().entrySet().iterator();

    while (var11.hasNext()) {
      Map.Entry<String, List<String>> header = (Map.Entry) var11.next();
      Iterator iterator = ((List) header.getValue()).iterator();

      while (iterator.hasNext()) {
        String headerValue = (String) iterator.next();
        conn.addRequestProperty((String) header.getKey(), headerValue);
      }
    }

    conn.setRequestMethod(requst.getMethod().name());
    conn.setConnectTimeout(requst.getConnectTimeout());
    conn.setReadTimeout(requst.getReadTimeout());
    conn.setInstanceFollowRedirects(requst.getFollowRedirects());
    if (requst.getMethod().equals(HTTPRequest.Method.POST) || requst.getMethod()
      .equals(HTTPRequest.Method.PUT)) {
      conn.setDoOutput(true);
      if (requst.getContentType() != null) {
        conn.setRequestProperty("Content-Type", requst.getContentType().toString());
      }

      if (requst.getQuery() != null) {
        try {
          OutputStreamWriter writer = new OutputStreamWriter(conn.getOutputStream());
          writer.write(requst.getQuery());
          writer.close();
        } catch (IOException e) {
          closeStreams(conn);
          throw e;
        }
      }
    }

    return conn;
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
