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
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeTokenRequest;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken.Payload;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.services.plus.Plus;
import com.google.plus.samples.haikuplus.Authenticate.GoogleIdTokenRepository;
import com.google.plus.samples.haikuplus.Authenticate.TokenInfoResponse;
import com.google.plus.samples.haikuplus.model.DataStore;
import com.google.plus.samples.haikuplus.model.User;

import org.junit.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Unit tests for AuthenticatedFilter
 *
 * @author joannasmith@google.com (Joanna Smith)
 */
public class AuthenticatedFilterTest {
  /**
   * UTestAuth with includeAuthHeader = true, specifically for a Bearer auth header
   *
   * Check request with authorization id token included in header
   *
   * Expected response: TEST_USER associated with TEST_SESSION, and the server requests an
   *   Authorization code
   *   HTTP/1.1 401 Unauthorized
   *   WWW-Authenticate: X-OAuth-Code realm='https://www.google.com/accounts/AuthSubRequest'
   */
  @Test
  public void testAuth_idHeaderWithoutAuthenticatedSession()
      throws GeneralSecurityException, IOException, ServletException {
    // Create testFilter
    Plus mockApiClient = mock(Plus.class);
    GoogleAuthorizationCodeTokenRequest mockTokenRequest = null;
    GoogleCredential actualCredential = null;
    GoogleIdTokenVerifier mockVerifier = mock(GoogleIdTokenVerifier.class);
    GoogleIdTokenRepository mockRepo = mock(GoogleIdTokenRepository.class);
    ExecutorService executor = Executors.newSingleThreadExecutor();
    AuthenticatedFilter testFilter = TestUtils.createTestFilter(
        mockApiClient, mockTokenRequest, actualCredential, mockVerifier, mockRepo, executor);

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    TestUtils.mockHttpRequestResponsePair(mockRequest, mockResponse);

    TestUtils.setMockRequestHeaders(mockRequest, true, false);

    TestUtils.mockPeopleAPIMethods(mockApiClient);

    // Mock the ID token
    GoogleIdToken mockIdToken = mock(GoogleIdToken.class);
    Payload actualPayload = TestUtils.createTestPayload();

    // Testing id token verification
    when(mockRepo.parse(HaikuPlus.JSON_FACTORY,
        TestUtils.HEADER_CONTENT)).thenReturn(mockIdToken);
    when(mockVerifier.verify(mockIdToken)).thenReturn(true);
    List<String> testAudience = Collections.singletonList(TestUtils.getClientId());
    when(mockRepo.verifyAudience(mockIdToken, testAudience)).thenReturn(true);
    when(mockIdToken.getPayload()).thenReturn(actualPayload);

    // Mock the client API call to indicate the missing credentials
    FilterChain mockChain = mock(FilterChain.class);
    doThrow(new Authenticate.InvalidAccessTokenException())
        .when(mockChain).doFilter(mockRequest, mockResponse);

    // Execute the test
    testFilter.doFilter(mockRequest, mockResponse, mockChain);
    executor.shutdown();

    // Verify that the user is associated with the session
    assertNotNull(Authenticate.authenticatedSessions.get(TestUtils.TEST_SESSION));

    // Verify that the server requested an authorization code
    verify(mockResponse)
        .addHeader(TestUtils.RESPONSE_CODE_HEADER_NAME, TestUtils.CODE_REQUEST_HEADER);
    verify(mockResponse).setStatus(401);
    verify(mockChain, never()).doFilter(mockRequest, mockResponse);

    TestUtils.cleanUp();
  }

  /**
   * UTestAuth with includeAuthHeader = true, specifically for a Code auth header
   *
   * Check request with authorization code included in header
   *
   * Expected response: Credentials associated with TEST_USER
   */
  @Test
  public void testAuth_codeHeaderWithAuthenticatedSession() throws IOException, ServletException {
    // Create testFilter
    Plus mockApiClient = mock(Plus.class);
    GoogleAuthorizationCodeTokenRequest mockTokenRequest =
        mock(GoogleAuthorizationCodeTokenRequest.class);
    GoogleCredential actualCredential =
        TestUtils.createTestCredential(true, false);
    GoogleIdTokenVerifier mockVerifier = null;
    GoogleIdTokenRepository mockRepo = null;
    ExecutorService executor = Executors.newSingleThreadExecutor();
    AuthenticatedFilter testFilter = TestUtils.createTestFilter(
        mockApiClient, mockTokenRequest, actualCredential, mockVerifier, mockRepo, executor);

    String userId = TestUtils.TEST_USER;
    String googleId = TestUtils.TEST_GOOGLE_USER;
    String sessionId = TestUtils.TEST_SESSION;
    boolean storeUser = false;
    boolean markDataAsFresh = false;
    User mockUser = TestUtils.createMockUser(storeUser, userId, googleId, markDataAsFresh);
    TestUtils.authenticateSessionForUser(sessionId, mockUser);

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    TestUtils.mockHttpRequestResponsePair(mockRequest, mockResponse);

    TestUtils.setMockRequestHeaders(mockRequest, false, true);

    TestUtils.mockPeopleAPIMethods(mockApiClient);

    // Mock the ID token and the refresh token response
    GoogleTokenResponse mockTokenResponse = mock(GoogleTokenResponse.class);
    GoogleIdToken mockIdToken = mock(GoogleIdToken.class);
    Payload actualPayload = TestUtils.createTestPayload();

    // Testing the code exchange and the ID token verification
    when(mockTokenRequest.execute()).thenReturn(mockTokenResponse);
    when(mockTokenResponse.parseIdToken()).thenReturn(mockIdToken);
    when(mockIdToken.getPayload()).thenReturn(actualPayload);

    // Execute the test
    FilterChain mockChain = mock(FilterChain.class);
    testFilter.doFilter(mockRequest, mockResponse, mockChain);
    executor.shutdown();

    TestUtils.verifyUserHasRefreshToken(TestUtils.TEST_GOOGLE_USER, actualCredential,
        mockChain, mockRequest, mockResponse);

    TestUtils.cleanUp();
  }

  /**
   * UTestAuth with includeAuthHeader = true, specifically for including both auth headers
   *
   * Check request with both authorization code and id token included in header
   *
   * Expected response: TEST_USER and their credentials associated with TEST_SESSION
   */
  @Test
  public void testAuth_idHeaderAndCodeHeaderWithoutAuthenticatedSession()
      throws IOException, GeneralSecurityException, ServletException {
    // Create testFilter
    Plus mockApiClient = mock(Plus.class);
    GoogleAuthorizationCodeTokenRequest mockTokenRequest =
        mock(GoogleAuthorizationCodeTokenRequest.class);
    GoogleCredential actualCredential =
        TestUtils.createTestCredential(true, false);
    GoogleIdTokenVerifier mockVerifier = mock(GoogleIdTokenVerifier.class);
    GoogleIdTokenRepository mockRepo = mock(GoogleIdTokenRepository.class);
    ExecutorService executor = Executors.newSingleThreadExecutor();
    AuthenticatedFilter testFilter = TestUtils.createTestFilter(
        mockApiClient, mockTokenRequest, actualCredential, mockVerifier, mockRepo, executor);

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    TestUtils.mockHttpRequestResponsePair(mockRequest, mockResponse);

    TestUtils.setMockRequestHeaders(mockRequest, true, true);

    TestUtils.mockPeopleAPIMethods(mockApiClient);

    // Mock the ID token, and the refresh token response
    GoogleTokenResponse mockTokenResponse = mock(GoogleTokenResponse.class);
    GoogleIdToken mockIdToken = mock(GoogleIdToken.class);
    Payload actualPayload = TestUtils.createTestPayload();

    // Testing the ID token verification
    when(mockRepo.parse(HaikuPlus.JSON_FACTORY, "test")).thenReturn(mockIdToken);
    when(mockVerifier.verify(mockIdToken)).thenReturn(true);
    List<String> testAudience = Collections.singletonList(TestUtils.getClientId());
    when(mockRepo.verifyAudience(mockIdToken, testAudience)).thenReturn(true);

    // Testing the code exchange
    when(mockTokenRequest.execute()).thenReturn(mockTokenResponse);
    when(mockTokenResponse.parseIdToken()).thenReturn(mockIdToken);
    when(mockIdToken.getPayload()).thenReturn(actualPayload);

    // Execute the test
    FilterChain mockChain = mock(FilterChain.class);
    testFilter.doFilter(mockRequest, mockResponse, mockChain);
    executor.shutdown();

    TestUtils.verifyUserHasAuthenticatedSession(TestUtils.TEST_GOOGLE_USER, TestUtils.TEST_SESSION);
    TestUtils.verifyUserHasRefreshToken(TestUtils.TEST_GOOGLE_USER, actualCredential,
        mockChain, mockRequest, mockResponse);

    TestUtils.cleanUp();
  }

  /**
   * UTestAuth with includeAuthHeader = true, specifically for the iOS case
   *
   * Check request with access token included in header, coming from an iOS device
   *
   * Expected response: TEST_USER and their credentials associated with TEST_SESSION
   */
  @Test
  public void testAuth_iosAccessTokenHeaderWithoutAuthenticatedSession()
      throws IOException, ServletException {
    // Create testFilter
    Plus mockApiClient = mock(Plus.class);
    GoogleAuthorizationCodeTokenRequest mockTokenRequest = null;
    GoogleCredential actualCredential =
        TestUtils.createTestCredential(true, false);
    GoogleIdTokenVerifier mockVerifier = null;
    GoogleIdTokenRepository mockRepo = mock(GoogleIdTokenRepository.class);
    ExecutorService executor = Executors.newSingleThreadExecutor();
    AuthenticatedFilter testFilter = TestUtils.createTestFilter(
        mockApiClient, mockTokenRequest, actualCredential, mockVerifier, mockRepo, executor);

    // Mock out the TokenInfo for the access token verification
    final TokenInfoResponse mockTokenResponse = new TokenInfoResponse();
    mockTokenResponse.audience = TestUtils.getClientId();
    mockTokenResponse.expiresIn = "not null";
    mockTokenResponse.userId = TestUtils.TEST_GOOGLE_USER;

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    TestUtils.mockHttpRequestResponsePair(mockRequest, mockResponse);

    TestUtils.setMockRequestHeaders(mockRequest, true, false);
    TestUtils.setMockUserAgentHeader(mockRequest, TestUtils.IOS_USER_AGENT);

    TestUtils.mockPeopleAPIMethods(mockApiClient);

    // Ensure that the id token verification fails
    doThrow(new IllegalArgumentException())
        .when(mockRepo).parse(HaikuPlus.JSON_FACTORY, TestUtils.HEADER_CONTENT);

    // Execute the test
    FilterChain mockChain = mock(FilterChain.class);
    testFilter.doFilter(mockRequest, mockResponse, mockChain);
    executor.shutdown();

    TestUtils.verifyUserHasAuthenticatedSession(TestUtils.TEST_GOOGLE_USER, TestUtils.TEST_SESSION);
    TestUtils.verifyUserHasRefreshToken(TestUtils.TEST_GOOGLE_USER, actualCredential,
        mockChain, mockRequest, mockResponse);

    TestUtils.cleanUp();
  }

  /**
   * UTestAuth with includeAuthHeader = false, specifically for the iOS case
   *
   * Check request without access token included in header, coming from an iOS device
   *
   * Expected response: Response includes an authorization header requesting an access token and
   * a status of 401
   */
  @Test
  public void testAuth_iosNoAuthHeaderWithoutAuthenticatedSession()
      throws ServletException, IOException {
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

    // Verify that the response is properly built
    verify(mockResponse).addHeader(TestUtils.RESPONSE_ID_HEADER_NAME, TestUtils.ID_REQUEST_HEADER);
    verify(mockResponse).setStatus(401);
    verify(mockChain, never()).doFilter(mockRequest, mockResponse);

    TestUtils.cleanUp();
  }

  /**
   * UTestAuth with includeAuthHeader = false
   *
   * Check request without a user or an authorization header
   *
   * Expected response: Response includes an authorization header requesting an ID token and
   * a status of 401
   */
  @Test
  public void testAuth_noAuthHeaderWithoutAuthenticatedSession()
      throws IOException, ServletException {
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

    // Verify that the response is properly built
    verify(mockResponse).addHeader(TestUtils.RESPONSE_ID_HEADER_NAME, TestUtils.ID_REQUEST_HEADER);
    verify(mockResponse).setStatus(401);
    verify(mockChain, never()).doFilter(mockRequest, mockResponse);
    
    TestUtils.cleanUp();
  }

  /**
   * UTestAuth with includeAuthHeader = false
   *
   * Check request with a user, but without an authorization header
   *
   * Expected response: Response includes an authorization header requesting an authorization
   * code and a status of 401
   */
  @Test
  public void testAuth_noAuthHeaderWithAuthenticatedSession() throws ServletException, IOException {
    // Create testFilter
    Plus mockApiClient = null;
    GoogleAuthorizationCodeTokenRequest mockTokenRequest = null;
    GoogleCredential actualCredential = null;
    GoogleIdTokenVerifier mockVerifier = null;
    GoogleIdTokenRepository mockRepo = null;
    ExecutorService executor = Executors.newSingleThreadExecutor();
    AuthenticatedFilter testFilter = TestUtils.createTestFilter(
        mockApiClient, mockTokenRequest, actualCredential, mockVerifier, mockRepo, executor);

    String userId = TestUtils.TEST_USER;
    String googleId = TestUtils.TEST_GOOGLE_USER;
    String sessionId = TestUtils.TEST_SESSION;
    boolean storeUser = false;
    boolean markDataAsFresh = false;
    User mockUser = TestUtils.createMockUser(storeUser, userId, googleId, markDataAsFresh);
    TestUtils.authenticateSessionForUser(sessionId, mockUser);

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    TestUtils.mockHttpRequestResponsePair(mockRequest, mockResponse);

    TestUtils.setMockRequestHeaders(mockRequest, false, false);
    
    // Mock the client API call to indicate the missing credentials
    FilterChain mockChain = mock(FilterChain.class);
    doThrow(new Authenticate.InvalidAccessTokenException())
        .when(mockChain).doFilter(mockRequest, mockResponse);

    // Execute the test
    testFilter.doFilter(mockRequest, mockResponse, mockChain);
    executor.shutdown();

    // Verify that the response is properly built
    verify(mockResponse)
        .addHeader(TestUtils.RESPONSE_CODE_HEADER_NAME, TestUtils.CODE_REQUEST_HEADER);
    verify(mockResponse).setStatus(401);
    verify(mockChain, never()).doFilter(mockRequest, mockResponse);

    TestUtils.cleanUp();
  }

  /**
   * UTestCreateUser
   *
   * Create User
   *
   * Expected response: User exists in the Datastore with a refresh token associated with the
   * User
   */
  @Test
  public void testCreateUser_withAuthenticatedSessionAndUserCredentials()
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

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    TestUtils.mockHttpRequestResponsePair(mockRequest, mockResponse);

    TestUtils.setMockRequestHeaders(mockRequest, false, false);

    TestUtils.mockPeopleAPIMethods(mockApiClient);

    String userId = TestUtils.TEST_USER;
    String googleId = TestUtils.TEST_GOOGLE_USER;
    String sessionId = TestUtils.TEST_SESSION;
    boolean storeUser = false;
    boolean markDataAsFresh = false;
    User mockUser = TestUtils.createMockUser(storeUser, userId, googleId, markDataAsFresh);
    TestUtils.authenticateSessionForUser(sessionId, mockUser);
    GoogleCredential testCredential = TestUtils.storeCredentialForUser(googleId, false);

    // Execute the test
    FilterChain mockChain = mock(FilterChain.class);
    testFilter.doFilter(mockRequest, mockResponse, mockChain);
    executor.shutdown();

    TestUtils.verifyDatastoreUserExists(googleId);
    TestUtils.verifyUserHasRefreshToken(googleId, testCredential,
        mockChain, mockRequest, mockResponse);

    TestUtils.cleanUp();
  }

  /**
   * UTestCreateUser
   *
   * Create User, with the request coming from an iOS device
   *
   * Expected response: User exists in the Datastore with an access token associated with the
   * User
   */
  @Test
  public void testCreateUser_fromIosWithAuthenticatedSessionAndUserCredentials()
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

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    TestUtils.mockHttpRequestResponsePair(mockRequest, mockResponse);

    TestUtils.setMockRequestHeaders(mockRequest, false, false);

    TestUtils.mockPeopleAPIMethods(mockApiClient);

    String userId = TestUtils.TEST_USER;
    String googleId = TestUtils.TEST_GOOGLE_USER;
    String sessionId = TestUtils.TEST_SESSION;
    boolean storeUser = false;
    boolean markDataAsFresh = false;
    User mockUser = TestUtils.createMockUser(storeUser, userId, googleId, markDataAsFresh);
    TestUtils.authenticateSessionForUser(sessionId, mockUser);
    GoogleCredential testCredential = TestUtils.storeCredentialForUser(googleId, true);

    // Execute the test
    FilterChain mockChain = mock(FilterChain.class);
    testFilter.doFilter(mockRequest, mockResponse, mockChain);
    executor.shutdown();

    TestUtils.verifyDatastoreUserExists(googleId);
    TestUtils.verifyUserHasRefreshToken(googleId, testCredential,
        mockChain, mockRequest, mockResponse);

    TestUtils.cleanUp();
  }

  /**
   * UTestGenerateGraph
   *
   * Generate User graph
   *
   * Expected response: Graph exists for the user: the correct connections exist in data store
   *    and duplicate connections do not exist in data store
   */
  @Test
  public void testGenerateGraph_withAuthenticatedSessionAndUserCredentials()
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

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    TestUtils.mockHttpRequestResponsePair(mockRequest, mockResponse);

    TestUtils.setMockRequestHeaders(mockRequest, false, false);

    TestUtils.mockPeopleAPIMethods(mockApiClient);

    String userId = TestUtils.TEST_USER;
    String googleId = TestUtils.TEST_GOOGLE_USER;
    String sessionId = TestUtils.TEST_SESSION;
    boolean storeUser = true;
    boolean markDataAsFresh = false;
    User mockUser = TestUtils.createMockUser(storeUser, userId, googleId, markDataAsFresh);
    TestUtils.authenticateSessionForUser(sessionId, mockUser);
    GoogleCredential testCredential = TestUtils.storeCredentialForUser(googleId, false);

    // Execute the test
    FilterChain mockChain = mock(FilterChain.class);
    testFilter.doFilter(mockRequest, mockResponse, mockChain);

    // Tell the executor to complete all threads before verifying the result.
    executor.shutdown();
    try {
      executor.awaitTermination(5, TimeUnit.SECONDS);
    } catch (InterruptedException e) {
    }

    // Verify that user exists in the data store
    User testUser = DataStore.loadUserWithGoogleId(googleId);
    assertEquals(googleId, testUser.googlePlusId);

    TestUtils.verifyUserHasRefreshToken(googleId, testCredential,
        mockChain, mockRequest, mockResponse);

    // Verify that the new edge exists for the user -- there should only be one
    List<String> edges = DataStore.edges.get(userId);
    assertNotNull(edges);
    assertEquals(edges.get(0), TestUtils.TEST_SECOND_USER);

    TestUtils.cleanUp();
  }
}
