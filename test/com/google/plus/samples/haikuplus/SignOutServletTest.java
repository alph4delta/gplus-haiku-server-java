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

import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeTokenRequest;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.services.plus.Plus;
import com.google.plus.samples.haikuplus.Authenticate.GoogleIdTokenRepository;
import com.google.plus.samples.haikuplus.model.User;

import org.junit.Test;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Unit tests for SignOutServlet
 *
 * @author joannasmith@google.com (Joanna Smith)
 */
public class SignOutServletTest {
  /**
   * UTestSignOut with a signed in user
   *
   * Sign out the user
   *
   * Expected response: User who signed out is no longer associated with the session; User must
   * sign in again to access site and be authenticated (subsequent calls generate an
   * authorization response header requesting an ID token; Current user is the only user signed out
   */
  @Test
  public void testSignOut_signedInUser() throws IOException, ServletException {
    // Create testFilter
    Plus mockApiClient = null;
    GoogleAuthorizationCodeTokenRequest mockTokenRequest = null;
    GoogleCredential actualCredential = null;
    GoogleIdTokenVerifier mockVerifier = null;
    GoogleIdTokenRepository mockRepo = null;
    ExecutorService executor = Executors.newSingleThreadExecutor();
    AuthenticatedFilter testFilter = TestUtils.createTestFilter(
        mockApiClient, mockTokenRequest, actualCredential, mockVerifier, mockRepo, executor);

    SignOutServlet testServlet = new SignOutServlet();

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    PrintWriter mockWriter = TestUtils.mockHttpRequestResponsePair(mockRequest, mockResponse);

    TestUtils.setMockRequestHeaders(mockRequest, false, false);

    String userId = TestUtils.TEST_USER;
    String googleId = TestUtils.TEST_GOOGLE_USER;
    String sessionId = TestUtils.TEST_SESSION;
    boolean storeUser = false;
    boolean markDataAsFresh = false;
    User mockUser = TestUtils.createMockUser(storeUser, userId, googleId, markDataAsFresh);
    TestUtils.authenticateSessionForUser(sessionId, mockUser);
    TestUtils.storeCredentialForUser(googleId, false);

    String secondUserId = TestUtils.TEST_SECOND_USER;
    String secondGoogleId = TestUtils.TEST_SECOND_GOOGLE_USER;
    String secondSessionId = TestUtils.TEST_SECOND_SESSION;
    User secondMockUser =
        TestUtils.createMockUser(storeUser, secondUserId, secondGoogleId, markDataAsFresh);
    TestUtils.authenticateSessionForUser(secondSessionId, secondMockUser);

    // Execute the test
    testServlet.doPost(mockRequest, mockResponse);

    // Verify that the session is not associated with a user
    assertEquals(null, Authenticate.authenticatedSessions.get(TestUtils.TEST_SESSION));
    verify(mockResponse).setStatus(200);
    verify(mockWriter).print("{ msg: \"Sign out complete\" }");

    // Verify that a second user is unaffected
    assertEquals(TestUtils.TEST_SECOND_USER,
        Authenticate.authenticatedSessions.get(TestUtils.TEST_SECOND_SESSION).getUserId());

    // Execute a second authenticated test to verify that the user must authenticate to make
    // another call
    FilterChain mockChain = mock(FilterChain.class);
    testFilter.doFilter(mockRequest, mockResponse, mockChain);
    executor.shutdown();

    verify(mockResponse).addHeader(TestUtils.RESPONSE_ID_HEADER_NAME, TestUtils.ID_REQUEST_HEADER);
    verify(mockResponse).setStatus(401);
    verify(mockChain, never()).doFilter(mockRequest, mockResponse);

    TestUtils.cleanUp();
  }

  /**
   * UTestSignOut with a user that is not signed in
   *
   * Sign out the user
   *
   * Expected response: 200 is returned (a no-op) and the session is not associated with a user
   */
  @Test
  public void testSignOut_signedOutUser() throws IOException {
    SignOutServlet testServlet = new SignOutServlet();

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    PrintWriter mockWriter = TestUtils.mockHttpRequestResponsePair(mockRequest, mockResponse);

    TestUtils.setMockRequestHeaders(mockRequest, false, false);

    String userId = TestUtils.TEST_USER;
    String googleId = TestUtils.TEST_GOOGLE_USER;
    String sessionId = TestUtils.TEST_SESSION;
    boolean storeUser = false;
    boolean markDataAsFresh = false;
    User mockUser = TestUtils.createMockUser(storeUser, userId, googleId, markDataAsFresh);
    TestUtils.authenticateSessionForUser(sessionId, mockUser);
    TestUtils.storeCredentialForUser(googleId, false);

    // Execute the test
    testServlet.doPost(mockRequest, mockResponse);

    // Verify that the session is not associated with a user
    assertEquals(null, Authenticate.authenticatedSessions.get(TestUtils.TEST_SESSION));
    verify(mockResponse).setStatus(200);
    verify(mockWriter).print("{ msg: \"Sign out complete\" }");

    TestUtils.cleanUp();
  }
}
