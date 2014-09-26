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

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.repackaged.com.google.common.annotations.VisibleForTesting;
import com.google.api.services.plus.Plus;
import com.google.api.services.plus.model.ItemScope;
import com.google.api.services.plus.model.Moment;
import com.google.plus.samples.haikuplus.model.DataStore;
import com.google.plus.samples.haikuplus.model.Haiku;
import com.google.plus.samples.haikuplus.model.Jsonifiable;
import com.google.plus.samples.haikuplus.model.User;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Provides an API endpoint for viewing, creating,retrieving, and voting on haikus.
 *
 *   GET /api/haikus
 *   GET /api/haikus?filter=circles
 *   POST /api/haikus
 *   GET /api/haikus/{haiku-id}
 *   POST /api/haikus/{haiku-id}/vote
 *
 * @author joannasmith@google.com (Joanna Smith)
 */
public class HaikuServlet extends HttpServlet {
  /**
   * Logger for the Authenticate class.
   */
  Logger logger = Logger.getLogger("HaikuServlet");

  /**
   * HaikuRepository object that wraps a static call to Jsonifiable.
   */
  HaikuRepository repo;

  public HaikuServlet() {
    this(new HaikuRepository());
  }

  @VisibleForTesting
  HaikuServlet(HaikuRepository repo) {
    this.repo = repo;
  }

  /**
   * Name for the filter query parameter.
   */
  private static final String FILTER = "filter";

  /**
   * Valid value for the filter query parameter.
   */
  private static final String CIRCLES = "circles";

  /**
   * Regex pattern for a vote request.
   */
  private static final Pattern VOTE_REGEX = Pattern.compile("(\\S+)/vote");

  /**
   * Base of the Haiku URLs.
   */
  private static final String HAIKUS_BASE_PATH = "/haikus/";

  /**
   * Vote parameter for the Haiku Call-to-Action URLs.
   */
  private static final String VOTE_PARAMETER = "?action=vote";

  /**
   * A valid app activity type for ReviewActivity actions.
   */
  private static final String REVIEW_ACTIVITY = "ReviewActivity";

  /**
   * A valid app activity type for AddActivity actions.
   */
  private static final String ADD_ACTIVITY = "AddActivity";

  /**
   * Collection value for moments.insert Google API calls.
   */
  private static final String VAULT = "vault";

  /**
   * Exposed as `GET /api/haikus[?filter=circles]`.
   *     Returns the list of all haikus, optionally filtered to the haikus created by the users
   *     in our visible circles (filter requires authentication). Will return an empty list "[]"
   *     if no haikus exist.
   *
   * Also exposed as `GET /api/haikus/{haiku-id}`.
   *     Returns the specified haiku, if it exists, or a 404 if not.
   *
   * @throws IOException if the response fails to fetch its writer
   */
  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    String haikuId = request.getPathInfo();
    if (haikuId != null) {
      // If a haiku ID was included in the url, we need to strip off the leading '/' and then
      // return the stored information for that haiku, if it exists.
      getHaiku(response, haikuId.substring(1));
    } else {
      // Otherwise, we need to return the list of haikus
      getHaikuList(request, response);
    }
  }

  /**
   * Returns a 200 with the specified haiku, if it exists, or a 404 if it does not.
   */
  private void getHaiku(HttpServletResponse response, String haikuId) throws IOException {
    Haiku haiku = DataStore.loadHaiku(haikuId);
    if (haiku == null) {
      logger.log(Level.INFO, "The requested haiku does not exist; return 404");
      // The provided id was invalid
      response.setStatus(HttpServletResponse.SC_NOT_FOUND);
      return;
    }

    logger.log(Level.INFO, "GET haiku request succeeded for haiku: " + haikuId);
    writeHaikuToResponse(response, haiku);
  }

  /**
   * Returns the list of haikus, optionally filtered by a user's circles. If a filter is requested,
   * authentication is required. If no haikus exist, an empty list "[]" is returned.
   */
  private void getHaikuList(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    User filterByUser = null;
    // Check if the response should be filtered
    String filter = request.getParameter(FILTER);
    if (filter != null) {
      if (filter.equals(CIRCLES)) {
        String sessionId = request.getSession().getId();
        // We require authentication to build a list of haikus created by a user's social
        // connections, so we invoke an authenticator to check if the user is authenticated
        // and authorized, and to request additional authentication information if not. In
        // this case, we create an executor and instruct it to wait for threads to complete
        // before returning. This will ensure that a user's list of connections is fully
        // updated before we attempt to fetch a list of haikus created by those connections.
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Authenticate authenticator = new Authenticate(executor);

        filterByUser = authenticator.requireAuthentication(sessionId, request, response);
        executor.shutdown();
        // We could ensure that the friends list is not being updated in the background,
        // but for simplicity we proceed with whatever cached data we have.

        if (filterByUser == null) {
          // The current session is not authenticated or the user is not authorized. The response
          // headers would have been set inside of Authenticate, so we simply return.
          return;
        }
      } else {
        logger.log(Level.INFO, "Invalid filter request for list haikus endpoint; return 400");
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        return;
      }
    }

    logger.log(Level.INFO, "List haikus request succeeded");
    // Fetch the list of haikus, and write them to the response. If a filter was requested and
    // the current session is authenticated, then filterByUser will have been set to the authorized
    // user. Otherwise, it will remain null, indicating that we want an unfiltered list of haikus.
    List<Haiku> haikus = DataStore.loadHaikus(filterByUser);
    response.setContentType(HaikuPlus.JSON_MIMETYPE);
    response.setStatus(HttpServletResponse.SC_OK);
    boolean first = true;
    response.getWriter().print("[");
    for (Haiku haiku : haikus) {
      if (!first) {
        response.getWriter().print(",");
      }
      response.getWriter().print(haiku.toJson());
      first = false;
    }
    response.getWriter().print("]");
  }

  /**
   * Exposed as `POST /api/haikus`.
   *     Requires the `demoMode` flag to be disabled.  If the demoMode flag is enabled, this
   *     endpoint always returns 405 (Method not allowed).
   *
   *     Creates a new haiku resource based on the request payload:
   *       id, author, votes and creation_time should not be specified in the request payload and
   *         will be ignored.
   *       title, line_one, line_two and line_three will be sanitized.
   *       Writes an AddActivity moment.
   *
   *     Returns the newly created resource:
   *       id is initialized to a unique identifier.
   *       author_id is initialized to the id of the currently authenticated user.
   *       votes is initialized to 0.
   *       creation_time is initialized to the current time.
   *
   *     Requires authentication.
   *
   * Also exposed as `POST /api/haikus/{haiku-id}/vote`.
   *     Increments the vote count of the specified haiku:
   *       A user may vote for their own haikus.
   *       A user may vote for the same haiku multiple times.
   *       Writes a ReviewActivity app activity for every vote.
   *     Requires authentication.
   *
   * @throws IOException if the response fails to fetch its writer
   */
  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    String path = request.getPathInfo();
    if (path != null) {
      // If a haiku ID was included in the url, we need to strip off the leading '/' and then
      // pass the ID along to process a vote for it, if applicable.
      path = path.substring(1);
      Matcher voteMatcher = VOTE_REGEX.matcher(path);
      if (!voteMatcher.matches()) {
        logger.log(Level.INFO, "Invalid POST request to haikus endpoint; return 400");
        // Not a valid POST request.
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        return;
      }
      String haikuId = voteMatcher.group(1);

      voteForHaiku(request, response, haikuId);
    } else {
      // First, we check if demoMode is enabled, prohibiting haiku creation.
      if (HaikuPlus.isDemoMode()) {
        logger.log(Level.INFO, "Haikus may not be created while in Demo Mode; return 405");
        response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        return;
      }

      // Otherwise, we need to return the list of haikus
      createHaiku(request, response);
    }
  }

  /**
   * Increments the vote count of the specified haiku:
   *   A user may vote for their own haikus.
   *   A user may vote for the same haiku multiple times.
   *   Writes a ReviewActivity app activity for every vote.
   * Requires authentication.
   *
   * @throws IOException if the response fails to fetch its writer
   */
  private void voteForHaiku(HttpServletRequest request, HttpServletResponse response,
      String haikuId) throws IOException {
    Haiku haiku = DataStore.loadHaiku(haikuId);
    if (haiku == null) {
      logger.log(Level.INFO, "The haiku: " + haikuId + " to vote on does not exist; return 400");
      // Not a valid POST request, as the Haiku does not exist.
      response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
      return;
    }

    String sessionId = request.getSession().getId();
    User authenticatedUser = checkRequestAuthentication(request, response, sessionId);
    if (authenticatedUser == null) {
      // The current session is not authenticated or the user is not authorized. The response
      // headers would have been set inside of Authenticate, so we simply return.
      return;
    }

    haiku.addVote();
    DataStore.addHaiku(haiku);

    // Write a ReviewActivity app activity. This will fail from localhost, so in that case,
    // we skip this step.
    if (!"localhost".equals(request.getServerName())) {
      String googleId = authenticatedUser.getGoogleUserId();
      GoogleCredential credential = DataStore.loadCredentialWithGoogleId(googleId);
      if (credential != null) {
        repo.writeAppActivity(haiku.getContentDeepLinkId(), REVIEW_ACTIVITY, googleId, credential);
      }
    }

    logger.log(Level.INFO, "Vote request succeeded for haiku: " + haikuId);
    writeHaikuToResponse(response, haiku);
  }

  /**
   * Requires the `demoMode` flag to be disabled.  If the demoMode flag is enabled, this
   * endpoint always returns 405 (Method not allowed).
   *
   * Creates a new haiku resource based on the request payload:
   *   id, author, votes and creation_time should not be specified in the request payload and
   *     will be ignored.
   *   title, line_one, line_two and line_three will be sanitized.
   *   Writes an AddActivity moment.
   *
   * Returns the newly created resource:
   *   id is initialized to a unique identifier.
   *   author_id is initialized to the id of the currently authenticated user.
   *   votes is initialized to 0.
   *   creation_time is initialized to the current time.
   *
   * Requires authentication.
   *
   * @throws IOException if the response fails to fetch its writer
   */
  private void createHaiku(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    String sessionId = request.getSession().getId();
    User authenticatedUser = checkRequestAuthentication(request, response, sessionId);
    if (authenticatedUser == null) {
      logger.log(Level.INFO, "Cannot create haiku as there is no authenticated user");
      // The current session is not authenticated or the user is not authorized. The response
      // headers would have been set inside of Authenticate, so we simply return.
      return;
    }

    // Read in the request body and parse the JSON into a new Haiku object
    Haiku haiku = repo.fromJson(request);

    // Specify the haiku's author as the current authenticated user
    String googleId = authenticatedUser.getGoogleUserId();
    if (googleId == null) {
      logger.log(Level.INFO,
          "Authenticated user has no Google authorization; cannot create the haiku; return 400");
      // Somehow, the author has no Google ID. This should never happen.
      response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
      return;
    }
    haiku.setAuthor(authenticatedUser);

    // Determine and set the metadata links
    String haikuId = haiku.getId();
    String contentDeepLinkId = HAIKUS_BASE_PATH + haikuId;
    String contentUrl = HaikuPlus.getAppBaseUrl() + contentDeepLinkId;
    String callToActionDeepLinkId = contentDeepLinkId + VOTE_PARAMETER;
    String callToActionUrl = contentUrl + VOTE_PARAMETER;
    haiku.setContentUrl(contentUrl);
    haiku.setContentDeepLinkId(contentDeepLinkId);
    haiku.setCallToActionUrl(callToActionUrl);
    haiku.setCallToActionDeepLinkId(callToActionDeepLinkId);

    // Store the haiku in the DataStore
    DataStore.addHaiku(haiku);

    // Write an AddActivity app activity. This will fail from localhost, so in that case,
    // we skip this step.
    if (!"localhost".equals(request.getServerName())) {
      GoogleCredential credential = DataStore.loadCredentialWithGoogleId(googleId);
      if (credential != null) {
        repo.writeAppActivity(haiku.getContentDeepLinkId(), ADD_ACTIVITY, googleId, credential);
      }
    }

    // Write the haiku back to the client
    writeHaikuToResponse(response, haiku);
  }

  /**
   * Invokes the authentication flow on the request. If the request is authenticated, the
   * signed in user will be returned. Otherwise, null will be returned and the response
   * will be populated with headers requesting authentication information.
   */
  private User checkRequestAuthentication(
      HttpServletRequest request, HttpServletResponse response, String sessionId) {
    ExecutorService executor = Executors.newSingleThreadExecutor();
    Authenticate authenticator = new Authenticate(executor);
    // We require authentication to create a new haiku, so we invoke an authenticator to
    // check if the user is authenticated and authorized, and to request additional
    // authentication information if not.
    User authenticatedUser =
        authenticator.requireAuthentication(sessionId, request, response);
    executor.shutdown();
    return authenticatedUser;
  }

  /**
   * Writes the specified haiku into the response object.
   *
   * @throws IOException if the response fails to fetch its writer
   */
  private void writeHaikuToResponse(HttpServletResponse response, Haiku haiku) throws IOException {
    response.setContentType(HaikuPlus.JSON_MIMETYPE);
    response.setStatus(HttpServletResponse.SC_OK);
    response.getWriter().print(haiku.toJson());
  }

  /**
   * Used as an abstract factory for testing static and final method calls.
   */
  @VisibleForTesting
  static class HaikuRepository {
    public Haiku fromJson(HttpServletRequest request) throws IOException {
      return Jsonifiable.fromJson(request.getReader(), Haiku.class);
    }

    /**
     * Writes an app activity to Google on behalf of the authenticated user.
     */
    void writeAppActivity(String targetUrl, String activityType, String authenticatedUserGoogleId,
        GoogleCredential credential) {
      ItemScope target = new ItemScope().setUrl(targetUrl);
      Moment content = new Moment()
          .setType("http://schemas.google.com/" + activityType).setTarget(target);
      Plus plus = new Plus.Builder(HaikuPlus.TRANSPORT, HaikuPlus.JSON_FACTORY, credential).build();
      try {
        plus.moments().insert(authenticatedUserGoogleId, VAULT, content).execute();
      } catch (IOException e) {
        // The moment failed to write, likely due to a temporary network issue. Either way, we
        // simply allow the program to continue and the moment is left unwritten.
      }
    }
  }
}
