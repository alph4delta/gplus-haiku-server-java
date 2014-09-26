/*
 * Copyright 2014 Google Inc. All Rights Reserved.
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

import com.google.plus.samples.haikuplus.model.DataStore;
import com.google.plus.samples.haikuplus.model.Haiku;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Simple servlet that sets the metadata for the intended haiku in the page.
 *
 * @author joannasmith@google.com (Joanna Smith)
 */
public class StaticServlet extends HttpServlet {
  /**
   * Logger for the Authenticate class.
   */
  Logger logger = Logger.getLogger("StaticServlet");

  /**
   * Specifies the name of the haiku attribute
   */
  private static final String HAIKU_ATTRIBUTE = "haiku";

  /**
   * Sets the metadata for the intended haiku in the page, and then serves the page
   * by forwarding the request.
   */
  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    // Get the path info
    String haikuId = request.getPathInfo();

    if (haikuId != null) {
      // If a haiku ID was included in the url, we need to strip off the leading '/' and then
      // return the stored information for that haiku, if it exists.
      haikuId = haikuId.substring(1);
      // Get the haiku
      Haiku haiku = DataStore.loadHaiku(haikuId);
      if (haiku == null) {
        logger.log(Level.INFO, "The haiku to display does not exist; return 404");
        // The haiku doesn't exist
        response.setStatus(HttpServletResponse.SC_NOT_FOUND);
        response.getWriter().print("404 Haiku not Found");
        return;
      }

      // Set the haiku as a "haiku" attribute in the request
      request.setAttribute(HAIKU_ATTRIBUTE, haiku);
    }

    try {
      request.getRequestDispatcher("/haikus.jsp").forward(request, response);
    } catch (ServletException e) {
      logger.log(Level.INFO, "Jetty failed to forward the request; return 500", e);
      // Jetty had an error forwarding the request.
      response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
      response.getWriter().print("500 while attempting to forward to JSP");
    }
  }
}
