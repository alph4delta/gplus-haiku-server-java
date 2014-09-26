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

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.plus.samples.haikuplus.HaikuServlet.HaikuRepository;
import com.google.plus.samples.haikuplus.model.DataStore;
import com.google.plus.samples.haikuplus.model.DataStore.UserNotFoundException;
import com.google.plus.samples.haikuplus.model.Haiku;
import com.google.plus.samples.haikuplus.model.User;

import org.junit.Test;
import org.mockito.Matchers;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Unit tests for HaikuServlet
 *
 * @author joannasmith@google.com (Joanna Smith)
 */
public class HaikuServletTest {
  /**
   * UTestListHaikus with isAuth = false and filter = {none} for an empty haiku list
   *
   * Retrieve list of Haikus from an unauthenticated session
   *
   * Expected response: Returns a 200 and no haikus since there are no haikus in DataStore
   */
  @Test
  public void testListHaikus_withUnauthenticatedSessionAndNoFilterAndNoHaikus() throws IOException {
    HaikuServlet testServlet = new HaikuServlet();

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    PrintWriter mockWriter = TestUtils.mockHttpRequestResponsePair(mockRequest, mockResponse);

    // Execute the test
    testServlet.doGet(mockRequest, mockResponse);

    // Verify that the request succeeds and that an empty list is written
    verify(mockResponse).setStatus(200);
    verify(mockWriter).print("[");
    verify(mockWriter).print("]");

    TestUtils.cleanUp();
  }

  /**
   * UTestListHaikus with isAuth = false and filter = {none} for a populated haiku list
   *
   * Retrieve list of Haikus from an unauthenticated session
   *
   * Expected response: Returns a 200 and haikus returned match expected haikus in DataStore
   */
  @Test
  public void testListHaikus_withUnauthenticatedSessionAndNoFilterAndHaikus() throws IOException {
    HaikuServlet testServlet = new HaikuServlet();

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    PrintWriter mockWriter = TestUtils.mockHttpRequestResponsePair(mockRequest, mockResponse);

    Haiku testHaiku =
        TestUtils.mockHaikus(TestUtils.TEST_HAIKU_AUTHOR, TestUtils.TEST_HAIKU_GOOGLE_AUTHOR);

    // Execute the test
    testServlet.doGet(mockRequest, mockResponse);

    // Verify that the request succeeds and that the haikus are written
    verify(mockResponse).setStatus(200);
    verify(mockWriter).print(testHaiku.toJson());

    TestUtils.cleanUp();
  }

  /**
   * UTestListHaikus with isAuth = true and filter = {none} for an empty haiku list
   *
   * Retrieve list of Haikus from an authenticated session
   *
   * Expected response: Returns a 200 and no haikus since there are no haikus in DataStore;
   * Should not differ from unauthenticated test
   */
  @Test
  public void testListHaikus_withAuthenticatedSessionAndNoFilterAndNoHaikus() throws IOException {
    HaikuServlet testServlet = new HaikuServlet();

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    PrintWriter mockWriter = TestUtils.mockHttpRequestResponsePair(mockRequest, mockResponse);

    String userId = TestUtils.TEST_USER;
    String googleId = TestUtils.TEST_GOOGLE_USER;
    String sessionId = TestUtils.TEST_SESSION;
    boolean storeUser = false;
    boolean markDataAsFresh = false;
    User mockUser = TestUtils.createMockUser(storeUser, userId, googleId, markDataAsFresh);
    TestUtils.authenticateSessionForUser(sessionId, mockUser);
    TestUtils.storeCredentialForUser(googleId, false);

    // Execute the test
    testServlet.doGet(mockRequest, mockResponse);

    // Verify that the request succeeds and that an empty list is written
    verify(mockResponse).setStatus(200);
    verify(mockWriter).print("[");
    verify(mockWriter).print("]");

    // Verify that the user is still associated with the session
    assertEquals(userId, Authenticate.authenticatedSessions.get(sessionId).getUserId());

    TestUtils.cleanUp();
  }

  /**
   * UTestListHaikus with isAuth = true and filter = {none} for a populated haiku list
   *
   * Retrieve list of Haikus from an authenticated session
   *
   * Expected response: Returns a 200 and haikus returned match expected haikus in DataStore;
   * Should not differ from unauthenticated test
   */
  @Test
  public void testListHaikus_withAuthenticatedSessionAndNoFilterAndHaikus() throws IOException {
    HaikuServlet testServlet = new HaikuServlet();

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    PrintWriter mockWriter = TestUtils.mockHttpRequestResponsePair(mockRequest, mockResponse);

    String userId = TestUtils.TEST_USER;
    String googleId = TestUtils.TEST_GOOGLE_USER;
    String sessionId = TestUtils.TEST_SESSION;
    boolean storeUser = false;
    boolean markDataAsFresh = false;
    User mockUser = TestUtils.createMockUser(storeUser, userId, googleId, markDataAsFresh);
    TestUtils.authenticateSessionForUser(sessionId, mockUser);
    TestUtils.storeCredentialForUser(googleId, false);

    Haiku testHaiku =
        TestUtils.mockHaikus(TestUtils.TEST_HAIKU_AUTHOR, TestUtils.TEST_HAIKU_GOOGLE_AUTHOR);

    // Execute the test
    testServlet.doGet(mockRequest, mockResponse);

    // Verify that the request succeeds and that the haikus are written
    verify(mockResponse).setStatus(200);
    verify(mockWriter).print(testHaiku.toJson());

    // Verify that the user is still associated with the session
    assertEquals(userId, Authenticate.authenticatedSessions.get(sessionId).getUserId());

    TestUtils.cleanUp();
  }

  /**
   * UTestListHaikus with isAuth = false and filter = circles
   *
   * Retrieve filtered list of Haikus from an unauthenticated session
   *
   * Expected response: Response includes an authorization header requesting a Bearer token and
   * a status of 401
   */
  @Test
  public void testListHaikus_withUnauthenticatedSessionAndFilter() throws IOException {
    HaikuServlet testServlet = new HaikuServlet();

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    PrintWriter mockWriter = TestUtils.mockHttpRequestResponsePair(mockRequest, mockResponse);

    TestUtils.mockFilterRequest(mockRequest, TestUtils.CIRCLES);

    Haiku testHaiku =
        TestUtils.mockHaikus(TestUtils.TEST_HAIKU_AUTHOR, TestUtils.TEST_HAIKU_GOOGLE_AUTHOR);

    // Execute the test
    testServlet.doGet(mockRequest, mockResponse);

    // Verify that the request fails, a bearer token is requested, and no haikus are returned
    verify(mockResponse).setStatus(401);
    verify(mockResponse).addHeader(TestUtils.RESPONSE_ID_HEADER_NAME, TestUtils.ID_REQUEST_HEADER);
    verify(mockWriter, never()).print(testHaiku.toJson());

    TestUtils.cleanUp();
  }

  /**
   * UTestListHaikus with isAuth = true and filter = circles for an empty haiku list
   *
   * Retrieve filtered list of Haikus from an authenticated session
   *
   * Expected response: Returns a 200 and no haikus since there are no haikus in DataStore
   */
  @Test
  public void testListHaikus_withAuthenticatedSessionAndFilterAndNoHaikus() throws IOException {
    HaikuServlet testServlet = new HaikuServlet();

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    PrintWriter mockWriter = TestUtils.mockHttpRequestResponsePair(mockRequest, mockResponse);

    TestUtils.mockFilterRequest(mockRequest, TestUtils.CIRCLES);

    String userId = TestUtils.TEST_USER;
    String googleId = TestUtils.TEST_GOOGLE_USER;
    String sessionId = TestUtils.TEST_SESSION;
    boolean storeUser = true;
    boolean markDataAsFresh = true;
    User mockUser = TestUtils.createMockUser(storeUser, userId, googleId, markDataAsFresh);
    TestUtils.authenticateSessionForUser(sessionId, mockUser);
    TestUtils.storeCredentialForUser(googleId, false);

    // Execute the test
    testServlet.doGet(mockRequest, mockResponse);

    // Verify that the request succeeds and that an empty list is written
    verify(mockResponse).setStatus(200);
    verify(mockWriter).print("[");
    verify(mockWriter).print("]");

    // Verify that the user is still associated with the session
    assertEquals(userId, Authenticate.authenticatedSessions.get(sessionId).getUserId());

    TestUtils.cleanUp();
  }

  /**
   * UTestListHaikus with isAuth = true and filter = circles for a populated haiku list
   *
   * Retrieve filtered list of Haikus from an authenticated session
   *
   * Expected response: Returns a 200 and haikus returned match expected haikus in DataStore;
   * The filtered haiku should be present, while the unfiltered haiku is excluded.
   */
  @Test
  public void testListHaikus_withAuthenticatedSessionAndFilterAndHaikus()
      throws IOException, UserNotFoundException {
    HaikuServlet testServlet = new HaikuServlet();

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    PrintWriter mockWriter = TestUtils.mockHttpRequestResponsePair(mockRequest, mockResponse);

    TestUtils.mockFilterRequest(mockRequest, TestUtils.CIRCLES);

    String userId = TestUtils.TEST_USER;
    String googleId = TestUtils.TEST_GOOGLE_USER;
    String sessionId = TestUtils.TEST_SESSION;
    boolean storeUser = true;
    boolean markDataAsFresh = true;
    User mockUser = TestUtils.createMockUser(storeUser, userId, googleId, markDataAsFresh);
    TestUtils.authenticateSessionForUser(sessionId, mockUser);
    TestUtils.storeCredentialForUser(googleId, false);

    Haiku nonFilterHaiku =
        TestUtils.mockHaikus(TestUtils.TEST_HAIKU_AUTHOR, TestUtils.TEST_HAIKU_GOOGLE_AUTHOR);
    String filterUserId = TestUtils.TEST_HAIKU_FILTER_AUTHOR;
    String filterGoogleId = TestUtils.TEST_HAIKU_FILTER_GOOGLE_AUTHOR;
    Haiku filterHaiku = TestUtils.mockHaikus(filterUserId, filterGoogleId);
    TestUtils.mockFilterAuthorEdge(userId, filterUserId);

    // Execute the test
    testServlet.doGet(mockRequest, mockResponse);

    // Verify that the request succeeds, and that only the filterHaiku is returned
    verify(mockResponse).setStatus(200);
    verify(mockWriter).print(filterHaiku.toJson());
    verify(mockWriter, never()).print(nonFilterHaiku.toJson());

    // Verify that the user is still associated with the session
    assertEquals(userId, Authenticate.authenticatedSessions.get(sessionId).getUserId());

    TestUtils.cleanUp();
  }

  /**
   * UTestListHaikus with isAuth = true and filter = invalid
   *
   * Retrieve filtered list of Haikus from an authenticated session
   *
   * Expected response: Returns a 400 since the provided filter is not a valid option
   */
  @Test
  public void testListHaikus_withAuthenticatedSessionAndInvalidFilter() throws IOException {
    HaikuServlet testServlet = new HaikuServlet();

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    PrintWriter mockWriter = TestUtils.mockHttpRequestResponsePair(mockRequest, mockResponse);

    TestUtils.mockFilterRequest(mockRequest, TestUtils.INVALID);

    String userId = TestUtils.TEST_USER;
    String googleId = TestUtils.TEST_GOOGLE_USER;
    String sessionId = TestUtils.TEST_SESSION;
    boolean storeUser = true;
    boolean markDataAsFresh = true;
    User mockUser = TestUtils.createMockUser(storeUser, userId, googleId, markDataAsFresh);
    TestUtils.authenticateSessionForUser(sessionId, mockUser);
    TestUtils.storeCredentialForUser(googleId, false);

    // Execute the test
    testServlet.doGet(mockRequest, mockResponse);

    // Verify that the request succeeds, but no haikus are returned
    verify(mockResponse).setStatus(400);
    verify(mockWriter, never()).print(Matchers.anyString());

    // Verify that the user is still associated with the session
    assertEquals(userId, Authenticate.authenticatedSessions.get(sessionId).getUserId());

    TestUtils.cleanUp();
  }

  /**
   * UTestCreateHaiku with isAuth = false
   *
   * Create a Haiku from an unauthenticated session
   *
   * Expected response: Response includes an authorization header requesting a Bearer token and
   * a status of 401
   */
  @Test
  public void testCreateHaiku_withUnauthenticatedSession() throws IOException {
    HaikuServlet testServlet = new HaikuServlet();

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    PrintWriter mockWriter = TestUtils.mockHttpRequestResponsePair(mockRequest, mockResponse);

    HaikuRepository mockRepo = mock(HaikuRepository.class);
    TestUtils.mockHaikuRequestPayload(mockRepo, mockRequest);

    // Execute the test
    testServlet.doPost(mockRequest, mockResponse);

    // Verify that the request fails, a bearer token is requested, and no haikus are returned
    verify(mockResponse).setStatus(401);
    verify(mockResponse).addHeader(TestUtils.RESPONSE_ID_HEADER_NAME, TestUtils.ID_REQUEST_HEADER);
    verify(mockWriter, never()).print(Matchers.anyString());

    TestUtils.cleanUp();
  }

  /**
   * UTestCreateHaiku with isAuth = true
   *
   * Create a Haiku from an authenticated session
   *
   * Expected response: Returns a 200 and the haiku returned matches haiku payload;
   *     the haiku exists in the DataStore;
   *     the haiku has a vote number of 0;
   *     the haiku's author is the current authenticated user
   */
  @Test
  public void testCreateHaiku_withAuthenticatedSession() throws IOException {
    HaikuRepository mockRepo = mock(HaikuRepository.class);
    HaikuServlet testServlet = new HaikuServlet(mockRepo);

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    PrintWriter mockWriter = TestUtils.mockHttpRequestResponsePair(mockRequest, mockResponse);

    String userId = TestUtils.TEST_USER;
    String googleId = TestUtils.TEST_GOOGLE_USER;
    String sessionId = TestUtils.TEST_SESSION;
    boolean storeUser = true;
    boolean markDataAsFresh = true;
    User mockUser = TestUtils.createMockUser(storeUser, userId, googleId, markDataAsFresh);
    TestUtils.authenticateSessionForUser(sessionId, mockUser);
    TestUtils.storeCredentialForUser(googleId, false);

    // Mock request payload
    Haiku testHaiku = TestUtils.mockHaikuRequestPayload(mockRepo, mockRequest);
    String haikuId = testHaiku.getId();
    testHaiku.setAuthor(mockUser);
    testHaiku.setContentUrl(TestUtils.TEST_URL + haikuId);
    testHaiku.setContentDeepLinkId(TestUtils.TEST_URL_HAIKU + haikuId);
    testHaiku.setCallToActionUrl(TestUtils.TEST_URL + haikuId + TestUtils.TEST_URL_VOTE);
    testHaiku.setCallToActionDeepLinkId(
        TestUtils.TEST_URL_HAIKU + haikuId + TestUtils.TEST_URL_VOTE);

    // Execute the test
    testServlet.doPost(mockRequest, mockResponse);

    // Verify that the request succeeds and that the haiku returned matches the one we sent
    verify(mockResponse).setStatus(200);
    verify(mockWriter).print(testHaiku.toJson());

    // Verify that the haiku exists in the DataStore
    Haiku storedHaiku = DataStore.loadHaiku(testHaiku.getId());
    assertEquals(testHaiku.getId(), storedHaiku.getId());
    assertEquals(testHaiku.getTitle(), storedHaiku.getTitle());
    assertEquals(testHaiku.getLineOne(), storedHaiku.getLineOne());
    assertEquals(testHaiku.getLineTwo(), storedHaiku.getLineTwo());
    assertEquals(testHaiku.getLineThree(), storedHaiku.getLineThree());
    assertEquals(testHaiku.getVotes(), storedHaiku.getVotes());
    assertEquals(testHaiku.getCreationTime(), storedHaiku.getCreationTime());
    assertEquals(testHaiku.getAuthor().getUserId(), storedHaiku.getAuthor().getUserId());

    // Verify that the haiku vote count is 0
    assertEquals(0, storedHaiku.getVotes());

    // Verify that the haiku's author is the current authenticated user
    assertEquals(userId, storedHaiku.getAuthor().getUserId());

    // Verify that the user is still associated with the session
    assertEquals(userId, Authenticate.authenticatedSessions.get(sessionId).getUserId());

    TestUtils.cleanUp();
  }

  /**
   * UTestCreateHaiku with demoMode enabled
   *
   * Create a Haiku from demo mode
   *
   * Expected response: Response is a 405 (Method not allowed)
   */
  @Test
  public void testCreateHaiku_withDemoModeEnabled() throws IOException {
    HaikuServlet testServlet = new HaikuServlet();

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    PrintWriter mockWriter = TestUtils.mockHttpRequestResponsePair(mockRequest, mockResponse);

    // Set demoMode to true for the test so that no new haikus can be created
    HaikuPlus.setDemoMode(true);

    HaikuRepository mockRepo = mock(HaikuRepository.class);
    TestUtils.mockHaikuRequestPayload(mockRepo, mockRequest);

    // Execute the test
    testServlet.doPost(mockRequest, mockResponse);

    // Verify that the request fails with a 405 and no haikus are returned
    verify(mockResponse).setStatus(405);
    verify(mockWriter, never()).print(Matchers.anyString());

    HaikuPlus.setDemoMode(false);
    TestUtils.cleanUp();
  }

  /**
   * UTestGetHaikus for a populated haiku list
   *
   * Retrieve the specified Haikus
   *
   * Expected response: Returns a 200 and the haiku returned matches the expected haiku
   */
  @Test
  public void testGetHaiku_withHaiku() throws IOException {
    HaikuServlet testServlet = new HaikuServlet();

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    PrintWriter mockWriter = TestUtils.mockHttpRequestResponsePair(mockRequest, mockResponse);

    Haiku testHaiku =
        TestUtils.mockHaikus(TestUtils.TEST_HAIKU_AUTHOR, TestUtils.TEST_HAIKU_GOOGLE_AUTHOR);

    TestUtils.mockHaikuIdPath(mockRequest, testHaiku.getId());

    // Execute the test
    testServlet.doGet(mockRequest, mockResponse);

    // Verify that the request succeeds and that the haikus are written
    verify(mockResponse).setStatus(200);
    verify(mockWriter).print(testHaiku.toJson());

    TestUtils.cleanUp();
  }

  /**
   * UTestGetHaikus for an empty haiku list
   *
   * Retrieve the specified Haikus
   *
   * Expected response: Returns a 400 and no haikus are written back
   */
  @Test
  public void testGetHaiku_withoutHaiku() throws IOException {
    HaikuServlet testServlet = new HaikuServlet();

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    PrintWriter mockWriter = TestUtils.mockHttpRequestResponsePair(mockRequest, mockResponse);

    TestUtils.mockHaikus(TestUtils.TEST_HAIKU_AUTHOR, TestUtils.TEST_HAIKU_GOOGLE_AUTHOR);

    TestUtils.mockHaikuIdPath(mockRequest, "fake ID");

    // Execute the test
    testServlet.doGet(mockRequest, mockResponse);

    // Verify that the request fails and that no haikus are written
    verify(mockResponse).setStatus(404);
    verify(mockWriter, never()).print(Matchers.anyString());

    TestUtils.cleanUp();
  }

  /**
   * UTestVote with isAuth = false
   *
   * Vote for a Haiku from an unauthenticated session
   *
   * Expected response: Response includes an authorization header requesting a Bearer token and
   * a status of 401
   */
  @Test
  public void testVoteForHaiku_withUnauthenticatedSession() throws IOException {
    HaikuServlet testServlet = new HaikuServlet();

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    PrintWriter mockWriter = TestUtils.mockHttpRequestResponsePair(mockRequest, mockResponse);

    Haiku testHaiku =
        TestUtils.mockHaikus(TestUtils.TEST_HAIKU_AUTHOR, TestUtils.TEST_HAIKU_GOOGLE_AUTHOR);

    TestUtils.mockHaikuVotePath(mockRequest, testHaiku.getId());

    // Execute the test
    testServlet.doPost(mockRequest, mockResponse);

    // Verify that the request fails, a bearer token is requested, and no haikus are returned
    verify(mockResponse).setStatus(401);
    verify(mockResponse).addHeader(TestUtils.RESPONSE_ID_HEADER_NAME, TestUtils.ID_REQUEST_HEADER);
    verify(mockWriter, never()).print(Matchers.anyString());

    TestUtils.cleanUp();
  }

  /**
   * UTestVote with isAuth = true
   *
   * Vote for a Haiku from an authenticated session
   *
   * Expected response: Returns a 200 and the haiku returned matches the stored haiku;
   *     the haiku exists in the DataStore;
   *     the haiku has a vote number of 1
   */
  @Test
  public void testVoteForHaiku_withAuthenticatedSession() throws IOException {
    HaikuRepository mockRepo = mock(HaikuRepository.class);
    HaikuServlet testServlet = new HaikuServlet(mockRepo);

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    TestUtils.mockHttpRequestResponsePair(mockRequest, mockResponse);

    String userId = TestUtils.TEST_USER;
    String googleId = TestUtils.TEST_GOOGLE_USER;
    String sessionId = TestUtils.TEST_SESSION;
    boolean storeUser = true;
    boolean markDataAsFresh = true;
    User mockUser = TestUtils.createMockUser(storeUser, userId, googleId, markDataAsFresh);
    TestUtils.authenticateSessionForUser(sessionId, mockUser);
    TestUtils.storeCredentialForUser(googleId, false);

    Haiku testHaiku =
        TestUtils.mockHaikus(TestUtils.TEST_HAIKU_AUTHOR, TestUtils.TEST_HAIKU_GOOGLE_AUTHOR);

    TestUtils.mockHaikuVotePath(mockRequest, testHaiku.getId());

    // Execute the test
    testServlet.doPost(mockRequest, mockResponse);

    // Verify that the request succeeds and that the haiku returned matches the one we sent
    verify(mockResponse).setStatus(200);

    // Verify that the haiku exists in the DataStore
    Haiku storedHaiku = DataStore.loadHaiku(testHaiku.getId());
    assertEquals(testHaiku.getId(), storedHaiku.getId());

    // Verify that the haiku vote count is 1
    assertEquals(1, storedHaiku.getVotes());

    // Verify that the user is still associated with the session
    assertEquals(userId, Authenticate.authenticatedSessions.get(sessionId).getUserId());

    TestUtils.cleanUp();
  }

  /**
   * UTestWriteAppActivity
   *
   * Write an AddActivity app activity after creating a Haiku
   *
   * Expected response: App activity target is for correct haiku;
   *     moments.insert was invoked for the authenticated user
   */
  @Test
  public void testWriteAppActivity_afterCreate() throws IOException {
    HaikuRepository mockRepo = mock(HaikuRepository.class);
    HaikuServlet testServlet = new HaikuServlet(mockRepo);

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    PrintWriter mockWriter = TestUtils.mockHttpRequestResponsePair(mockRequest, mockResponse);

    String userId = TestUtils.TEST_USER;
    String googleId = TestUtils.TEST_GOOGLE_USER;
    String sessionId = TestUtils.TEST_SESSION;
    boolean storeUser = true;
    boolean markDataAsFresh = true;
    User mockUser = TestUtils.createMockUser(storeUser, userId, googleId, markDataAsFresh);
    TestUtils.authenticateSessionForUser(sessionId, mockUser);
    GoogleCredential testCredential = TestUtils.storeCredentialForUser(googleId, false);

    // Mock request payload
    Haiku testHaiku = TestUtils.mockHaikuRequestPayload(mockRepo, mockRequest);
    String haikuId = testHaiku.getId();
    testHaiku.setAuthor(mockUser);
    testHaiku.setContentUrl(TestUtils.TEST_URL + haikuId);
    testHaiku.setContentDeepLinkId(TestUtils.TEST_URL_HAIKU + haikuId);
    testHaiku.setCallToActionUrl(TestUtils.TEST_URL + haikuId + TestUtils.TEST_URL_VOTE);
    testHaiku.setCallToActionDeepLinkId(
        TestUtils.TEST_URL_HAIKU + haikuId + TestUtils.TEST_URL_VOTE);

    // Execute the test
    testServlet.doPost(mockRequest, mockResponse);

    // Verify that the request succeeds and that the haiku returned matches the one we sent
    verify(mockResponse).setStatus(200);
    verify(mockWriter).print(testHaiku.toJson());

    // Verify that moments.insert was invoked for the authenticated user and haiku
    verify(mockRepo).writeAppActivity(testHaiku.getContentDeepLinkId(), "AddActivity", googleId,
        testCredential);

    // Verify that the user is still associated with the session
    assertEquals(userId, Authenticate.authenticatedSessions.get(sessionId).getUserId());

    TestUtils.cleanUp();
  }

  /**
   * UTestWriteAppActivity
   *
   * Write an AddActivity app activity after vote for a Haiku
   *
   * Expected response: App activity target is for correct haiku;
   *     moments.insert was invoked for the authenticated user
   */
  @Test
  public void testWriteAppActivity_afterVote() throws IOException {
    HaikuRepository mockRepo = mock(HaikuRepository.class);
    HaikuServlet testServlet = new HaikuServlet(mockRepo);

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    TestUtils.mockHttpRequestResponsePair(mockRequest, mockResponse);

    String userId = TestUtils.TEST_USER;
    String googleId = TestUtils.TEST_GOOGLE_USER;
    String sessionId = TestUtils.TEST_SESSION;
    boolean storeUser = true;
    boolean markDataAsFresh = true;
    User mockUser = TestUtils.createMockUser(storeUser, userId, googleId, markDataAsFresh);
    TestUtils.authenticateSessionForUser(sessionId, mockUser);
    GoogleCredential testCredential = TestUtils.storeCredentialForUser(googleId, false);

    Haiku testHaiku =
        TestUtils.mockHaikus(TestUtils.TEST_HAIKU_AUTHOR, TestUtils.TEST_HAIKU_GOOGLE_AUTHOR);

    TestUtils.mockHaikuVotePath(mockRequest, testHaiku.getId());

    // Execute the test
    testServlet.doPost(mockRequest, mockResponse);

    // Verify that the request succeeds and that the haiku returned matches the one we sent
    verify(mockResponse).setStatus(200);

    // Verify that moments.insert was invoked for the authenticated user and haiku
    verify(mockRepo).writeAppActivity(testHaiku.getContentDeepLinkId(), "ReviewActivity", googleId,
        testCredential);

    // Verify that the user is still associated with the session
    assertEquals(userId, Authenticate.authenticatedSessions.get(sessionId).getUserId());

    TestUtils.cleanUp();
  }
}
