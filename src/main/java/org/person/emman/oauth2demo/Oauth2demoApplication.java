package org.person.emman.oauth2demo;

import com.nimbusds.jose.util.IOUtils;
import org.person.emman.oauth2demo.manager.OAuthAccessTokenManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.nio.charset.Charset;

@SpringBootApplication public class Oauth2demoApplication implements CommandLineRunner {
  private static Logger LOGGER = LoggerFactory.getLogger(Oauth2demoApplication.class);

  @Value("${sample.api.uri}") private String sampleApiUri;

  @Autowired private OAuthAccessTokenManager oauthAccessTokenManager;

  private void accessApi(String authorization) throws IOException {
    URL url = new URL(sampleApiUri);
    HttpURLConnection con = null;
    try {
      con = (HttpURLConnection) url.openConnection();
      con.setRequestMethod("GET");
      if (authorization != null && !authorization.isEmpty()) {
        con.setRequestProperty("Authorization", authorization);
      }

      LOGGER.info("Response code {}, message {}", con.getResponseCode(), con.getResponseMessage());
      if (con.getResponseCode() == 200) {
        LOGGER.info("Content {}", IOUtils.readInputStreamToString(con.getInputStream(), Charset.forName("UTF-8")));
      }
    } finally {
      if (con != null) {
        con.disconnect();
      }
    }
  }

  public static void main(String[] args) {
    LOGGER.info("STARTING THE APPLICATION");
    SpringApplication.run(Oauth2demoApplication.class, args);
    LOGGER.info("APPLICATION FINISHED");
  }

  @Override public void run(String... args) throws Exception {
    LOGGER.info("EXECUTING : command line runner");

    for (int i = 0; i < args.length; ++i) {
      LOGGER.info("args[{}]: {}", i, args[i]);
    }
    LOGGER.info("Access token: {}", oauthAccessTokenManager.getAccessToken());
    LOGGER.info("Access token (from cache): {}", oauthAccessTokenManager.getAccessToken());
    LOGGER.info("Request API without access token");
    accessApi(null);
    LOGGER.info("Request API with access token");
    accessApi(oauthAccessTokenManager.getAccessTokenHttpHeader());
  }
}
