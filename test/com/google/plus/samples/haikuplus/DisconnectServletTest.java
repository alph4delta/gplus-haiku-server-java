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

import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeTokenRequest;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.services.plus.Plus;
import com.google.plus.samples.haikuplus.Authenticate.GoogleIdTokenRepository;
import com.google.plus.samples.haikuplus.model.DataStore;
import com.google.plus.samples.haikuplus.model.User;

import org.junit.Test;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Unit tests for DisconnectServlet
 *
 * @author joannasmith@google.com (Joanna Smith)
 */
public class DisconnectServletTest extends AuthenticatedFilterTest {
  /**
   * UTestDisconnect with isAuth = false
   *
   * Disconnect the user from an unauthenticated session
   *
   * Expected response: Response includes an authorization header requesting a Bearer token and
   * a status of 401
   */
  @Test
  public void testDisconnect_withUnauthenticatedSession() throws IOException {
    // Create testFilter
    Plus mockApiClient = mock(Plus.class);
    GoogleAuthorizationCodeTokenRequest mockTokenRequest = null;
    GoogleCredential actualCredential = null;
    GoogleIdTokenVerifier mockVerifier = null;
    GoogleIdTokenRepository mockRepo = null;
    ExecutorService executor = Executors.newSingleThreadExecutor();
    AuthenticatedFilter testFilter = TestUtils.createTestFilter(
        mockApiClient, mockTokenRequest, actualCredential, mockVerifier, mockRepo, executor);

    DisconnectServlet testServlet = new DisconnectServlet();

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    TestUtils.mockHttpRequestResponsePair(mockRequest, mockResponse);

    TestUtils.setMockRequestHeaders(mockRequest, false, false);

    // Execute the test
    FilterChain mockChain = mock(FilterChain.class);
    testFilter.doFilter(mockRequest, mockResponse, mockChain);
    executor.shutdown();

    // Verify that the request fails, a bearer token is requested, and no haikus are returned
    verify(mockResponse).setStatus(401);
    verify(mockResponse).addHeader(TestUtils.RESPONSE_ID_HEADER_NAME, TestUtils.ID_REQUEST_HEADER);

    // Verify that the disconnect fails
    testServlet.doPost(mockRequest, mockResponse);
    verify(mockResponse).setStatus(403);

    TestUtils.cleanUp();
  }

  /**
   * UTestDisconnect with isAuth = true
   *
   * Disconnect the user from an authenticated session
   *
   * Expected response: 200 is returned; the user is removed from the DataStore; the user is not
   *     associated with the session; there are no stored credentials for the user; there are no
   *     stored haikus for the user
   */
  @Test
  public void testDisconnect_withAuthenticatedSession() throws IOException {
    // Create testFilter
    Plus mockApiClient = mock(Plus.class);
    GoogleAuthorizationCodeTokenRequest mockTokenRequest = null;
    GoogleCredential actualCredential = null;
    GoogleIdTokenVerifier mockVerifier = null;
    GoogleIdTokenRepository mockRepo = null;
    ExecutorService executor = Executors.newSingleThreadExecutor();
    AuthenticatedFilter testFilter = TestUtils.createTestFilter(
        mockApiClient, mockTokenRequest, actualCredential, mockVerifier, mockRepo, executor);

    DisconnectServlet testServlet = new DisconnectServlet();

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    PrintWriter mockWriter = TestUtils.mockHttpRequestResponsePair(mockRequest, mockResponse);

    TestUtils.setMockRequestHeaders(mockRequest, false, false);

    TestUtils.mockPeopleAPIMethods(mockApiClient);

    String userId = TestUtils.TEST_USER;
    String googleId = TestUtils.TEST_GOOGLE_USER;
    String sessionId = TestUtils.TEST_SESSION;
    boolean storeUser = true;
    boolean markDataAsFresh = false;
    User mockUser = TestUtils.createMockUser(storeUser, userId, googleId, markDataAsFresh);
    TestUtils.authenticateSessionForUser(sessionId, mockUser);
    TestUtils.storeCredentialForUser(googleId, false);

    TestUtils.mockHaikus(userId, googleId);

    // Execute the test
    FilterChain mockChain = mock(FilterChain.class);
    testFilter.doFilter(mockRequest, mockResponse, mockChain);
    executor.shutdown();
    try {
      executor.awaitTermination(5, TimeUnit.SECONDS);
    } catch (InterruptedException e) {
    }
    testServlet.doPost(mockRequest, mockResponse);

    // Verify that the request succeeds
    verify(mockResponse).setStatus(200);
    verify(mockWriter).print("{ msg: \"Disconnect complete\" }");

    // Verify that the user is not stored in the DataStore
    assertNull(DataStore.loadUser(userId));
    assertNull(DataStore.edges.get(userId));

    // Verify that the session is not associated with a user
    assertNull(Authenticate.authenticatedSessions.get(TestUtils.TEST_SESSION));

    // Verify that there are no stored credentials for the user
    assertNull(DataStore.loadCredentialWithGoogleId(googleId));

    // Verify that there are no stored haikus for the user
    assertNull(DataStore.userHaikuMap.get(userId));

    TestUtils.cleanUp();
  }
}
