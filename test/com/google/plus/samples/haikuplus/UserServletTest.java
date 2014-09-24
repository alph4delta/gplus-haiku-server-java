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

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
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

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Unit tests for UserServlet
 *
 * @author joannasmith@google.com (Joanna Smith)
 */
public class UserServletTest extends AuthenticatedFilterTest {
  /**
   * UTestGetUser with isAuth = true
   *
   * Retrieve a user with an authorized session
   *
   * Expected response: User object for the current user is returned, and that User is the
   * correct user
   */
  @Test
  public void testGetUser_withAuthenticatedSessionAndUserCredentials()
      throws IOException, ServletException {
    // Create testFilter
    Plus mockApiClient = mock(Plus.class);
    GoogleAuthorizationCodeTokenRequest mockTokenRequest = null;
    GoogleCredential actualCredential = null;
    GoogleIdTokenVerifier mockVerifier = null;
    GoogleIdTokenRepository mockRepo = null;
    ExecutorService executor = Executors.newSingleThreadExecutor();
    AuthenticatedFilter testFilter = TestUtils.createTestFilter(
        mockApiClient, mockTokenRequest, actualCredential, mockVerifier, mockRepo, executor);

    UserServlet testServlet = new UserServlet();

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    PrintWriter mockWriter = TestUtils.mockHttpRequestResponsePair(mockRequest, mockResponse);

    TestUtils.setMockRequestHeaders(mockRequest, false, false);

    TestUtils.mockPeopleAPIMethods(mockApiClient);

    String userId = TestUtils.TEST_USER;
    String googleId = TestUtils.TEST_GOOGLE_USER;
    String sessionId = TestUtils.TEST_SESSION;
    boolean storeUser = false;
    boolean markDataAsFresh = false;
    User mockUser = TestUtils.createMockUser(storeUser, userId, googleId, markDataAsFresh);
    TestUtils.authenticateSessionForUser(sessionId, mockUser);
    TestUtils.storeCredentialForUser(googleId, false);

    // Execute the test
    FilterChain mockChain = mock(FilterChain.class);
    testFilter.doFilter(mockRequest, mockResponse, mockChain);
    executor.shutdown();

    // After the authentication succeeds, verify that the chain would be called, and then
    // execute the test for the servlet.
    verify(mockChain).doFilter(mockRequest, mockResponse);
    testServlet.doGet(mockRequest, mockResponse);

    // Verify the user object for the current user is returned
    User testUser = DataStore.loadUserWithGoogleId(TestUtils.TEST_GOOGLE_USER);
    verify(mockResponse).setStatus(200);
    verify(mockWriter).print(testUser.toJson());

    // Verify the user is the correct user
    assertEquals(TestUtils.TEST_GOOGLE_USER, testUser.googlePlusId);

    TestUtils.cleanUp();
  }

  /**
   * UTestGetUser with isAuth = false
   *
   * Retrieve a user with an unauthorized session
   *
   * Expected response: Response includes an authorization header requesting a Bearer token and
   * a status of 401
   */
  @Test
  public void testGetUser_withoutAuthenticatedSession() throws ServletException, IOException {
    // Create testFilter
    Plus mockApiClient = null;
    GoogleAuthorizationCodeTokenRequest mockTokenRequest = null;
    GoogleCredential actualCredential = null;
    GoogleIdTokenVerifier mockVerifier = null;
    GoogleIdTokenRepository mockRepo = null;
    ExecutorService executor = Executors.newSingleThreadExecutor();
    AuthenticatedFilter testFilter = TestUtils.createTestFilter(
        mockApiClient, mockTokenRequest, actualCredential, mockVerifier, mockRepo, executor);

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    TestUtils.mockHttpRequestResponsePair(mockRequest, mockResponse);

    TestUtils.setMockRequestHeaders(mockRequest, false, false);

    // Execute the test
    FilterChain mockChain = mock(FilterChain.class);
    testFilter.doFilter(mockRequest, mockResponse, mockChain);
    executor.shutdown();

    // Verify session not authenticated header is included in the response
    verify(mockResponse).addHeader(TestUtils.RESPONSE_ID_HEADER_NAME, TestUtils.ID_REQUEST_HEADER);
    verify(mockResponse).setStatus(401);
    verify(mockChain, never()).doFilter(mockRequest, mockResponse);
  }
}
