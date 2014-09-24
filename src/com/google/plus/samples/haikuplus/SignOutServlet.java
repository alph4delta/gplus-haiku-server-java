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

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Provides an API endpoint for deleting the session for the currently logged in user.
 *
 *   POST /api/signout
 *
 * @author joannasmith@google.com (Joanna Smith)
 */
public class SignOutServlet extends HttpServlet {
  /**
   * Logger for the Authenticate class.
   */
  Logger logger = Logger.getLogger("SignOutServlet");

  /**
   * Exposed as `POST /api/signout`.
   *
   * Disassociates any authentication information with the current session.
   * @throws IOException if the response fails to fetch its writer
   */
  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    String sessionId = request.getSession().getId();
    if (sessionId != null) {
      Authenticate.authenticatedSessions.remove(sessionId);
    }
    logger.log(Level.INFO, "Sign out succeeded");
    response.setStatus(HttpServletResponse.SC_OK);
    response.getWriter().print("{ msg: \"Sign out complete\" }");
  }
}
