/*
 * Copyright 2013 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.plus.samples.haikuplus;

import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.repackaged.com.google.common.annotations.VisibleForTesting;

import org.apache.jasper.servlet.JspServlet;
import org.mortbay.jetty.Handler;
import org.mortbay.jetty.Server;
import org.mortbay.jetty.SessionManager;
import org.mortbay.jetty.servlet.Context;
import org.mortbay.jetty.servlet.DefaultServlet;
import org.mortbay.jetty.servlet.HashSessionManager;
import org.mortbay.jetty.servlet.SessionHandler;

import java.io.InputStream;
import java.util.Properties;

/**
 * The Haiku+ sample application is a simple database of user-submitted haikus. It allows for a
 * restricted set of functionality which would not be sufficient for a production application,
 * but is sufficient to demonstrate Google+ platform features, such as Google+ Sign-In,
 * personalization, app activities, over-the-air install, and interactive posts.
 *
 * @author joannasmith@google.com (Joanna Smith)
 */
public class HaikuPlus {
  /**
   * Base URL of the application. If you deploy this app, you will need to update this value
   * before running the application.
   */
  private static String appBaseUrl;

  /**
   * Flag to determine if the app should run in "demo mode" which does not allow for the creation
   * of new haikus.  It is a Boolean object so we can detect if the flag has been
   * initialized.
   */
  private static Boolean demoMode;

   /**
   * MIME type to use when sending responses back to Haiku+ clients.
   */
  protected static final String JSON_MIMETYPE = "application/json";

  /**
   * JsonFactory to use in parsing JSON.
   */
  @VisibleForTesting
  static final JsonFactory JSON_FACTORY = new GsonFactory();

  /**
   * HttpTransport to use for external requests.
   */
  @VisibleForTesting
  static final HttpTransport TRANSPORT = new NetHttpTransport();

  /**
   * Register all endpoints that the server will handle.
   * 
   * @param args Command-line arguments.
   * @throws Exception from Jetty if the component fails to start
   */
  public static void main(String[] args) throws Exception {
    Server server = new Server(4567);
    Context context = new Context(server, "/", Context.SESSIONS);
    context.setResourceBase("war/client");

    // Establishes the session manager and the session ID name as "HaikuSessionId".
    SessionHandler sessionHandler = new SessionHandler();
    SessionManager sessionManager = new HashSessionManager();
    sessionManager.setSessionCookie(Authenticate.SESSION_ID_NAME);
    sessionHandler.setSessionManager(sessionManager);
    context.setSessionHandler(sessionHandler);
    
    // Read the configuration properties
    readConfigProperties();

    // Returns a user resource for the currently authenticated user.
    context.addServlet(UserServlet.class, "/api/users/me");
    context.addFilter(AuthenticatedFilter.class, "/api/users/me", Handler.DEFAULT);
    // Disassociates any authentication information with the current session.
    context.addServlet(SignOutServlet.class, "/api/signout");
    // Disconnects a user from the app and deletes all of their data
    context.addServlet(DisconnectServlet.class, "/api/disconnect");
    context.addFilter(AuthenticatedFilter.class, "/api/disconnect", Handler.DEFAULT);
    // Manages the creation and retrieval of haikus.
    context.addServlet(HaikuServlet.class, "/api/haikus/*");

    // Sets the metadata for a haiku in the page before serving it
    context.addServlet(StaticServlet.class, "/haikus/*");

    context.addServlet(JspServlet.class, "*.jsp");
    context.addServlet(DefaultServlet.class, "/");

    server.start();
    server.join();
  }
  
  public static String getAppBaseUrl() {
    if (appBaseUrl == null) {
      readConfigProperties();
    }
    
    return appBaseUrl;
  }

  @VisibleForTesting
  static  void setDemoMode(boolean demo) {
    demoMode = Boolean.valueOf(demo);
  }
  
  public static boolean isDemoMode() {
    if (demoMode == null) {
      readConfigProperties();
    }
    
    return demoMode != null && demoMode;
  }
  
  /**
   * Reads the configuration.properties file and sets the member fields accordingly.
   * @throws RuntimeException if there is an IOException reading the file.
   */
  private static synchronized void readConfigProperties() {
    Properties config = new Properties();
    try {
      InputStream inStream = HaikuPlus.class.getClassLoader()
          .getResourceAsStream("config.properties");
      if (inStream == null) {
        throw new RuntimeException("Cannot load config.properties");
      }
      config.load(inStream);

      appBaseUrl = config.getProperty("APP_BASE_URI");
      // if the properties files does not contain this key, throw an exception
      if (appBaseUrl == null) {
        throw new RuntimeException(
            "APP_BASE_URI property in config.properties is not set to a valid URI");
      }

      demoMode = Boolean.valueOf(config.getProperty("DEMO"));

    } catch (Exception e) {
      throw new RuntimeException("Failed to load configuration properties file", e);
    }
  }
}
