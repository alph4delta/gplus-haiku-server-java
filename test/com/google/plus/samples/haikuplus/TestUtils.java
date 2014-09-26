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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeTokenRequest;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken.Payload;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.services.plus.Plus;
import com.google.api.services.plus.model.PeopleFeed;
import com.google.api.services.plus.model.Person;
import com.google.plus.samples.haikuplus.Authenticate.GoogleIdTokenRepository;
import com.google.plus.samples.haikuplus.HaikuServlet.HaikuRepository;
import com.google.plus.samples.haikuplus.model.DataStore;
import com.google.plus.samples.haikuplus.model.DataStore.UserNotFoundException;
import com.google.plus.samples.haikuplus.model.Haiku;
import com.google.plus.samples.haikuplus.model.User;

import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.Reader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ExecutorService;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * Utility class for test classes
 *
 * @author joannasmith@google.com (Joanna Smith)
 */
public final class TestUtils {
  // Test values for authenticating sessions and users
  static final String TEST_SESSION = "testSession";
  static final String TEST_USER = "testUser";
  static final String TEST_GOOGLE_USER = "testGoogleUser";
  static final String TEST_SECOND_SESSION = "testSecondSession";
  static final String TEST_SECOND_USER = "testSecondUser";
  static final String TEST_SECOND_GOOGLE_USER = "testSecondGoogleUser";
  static final String TEST_REFRESH_TOKEN = "testRefreshToken";
  static final String TEST_ACCESS_TOKEN = "testAccessToken";

  // Test values for non-users
  static final String NON_HAIKU_USER = "nonHaikuUser";
  static final String NON_FILTER_USER = "nonFilterUser";

  // Test values for haikus and their authors
  static final String TEST_HAIKU_AUTHOR = "TestHaikuAuthor";
  static final String TEST_HAIKU_FILTER_AUTHOR = "TestHaikuFilterAuthor";
  static final String TEST_HAIKU_GOOGLE_AUTHOR = "TestHaikuGoogleAuthor";
  static final String TEST_HAIKU_FILTER_GOOGLE_AUTHOR = "TestHaikuFilterGoogleAuthor";
  static final String TEST_HAIKU_TITLE = "TestTitle";
  static final String TEST_HAIKU_LINE_ONE = "TestLineOne";
  static final String TEST_HAIKU_LINE_TWO = "TestLineTwo";
  static final String TEST_HAIKU_LINE_THREE = "TestLineThree";
  static final String TEST_URL = "http://localhost:4567/haikus/";
  static final String TEST_URL_VOTE = "?action=vote";
  static final String TEST_URL_HAIKU = "/haikus/";
  static final String FILTER = "filter";
  static final String CIRCLES = "circles";
  static final String INVALID = "invalid";

  // Test values for API Console configurations should match the actual configurations
  private static GoogleClientSecrets clientSecrets;

  // Test headers for authentication requests
  static final String HEADER_CONTENT = "test";
  static final String CODE_HEADER_NAME = "X-OAuth-Code";
  static final String ID_HEADER_SCHEME = "Bearer";
  static final String ID_HEADER_NAME = "Authorization";

  // Test headers for authentication responses
  static final String RESPONSE_ID_HEADER_NAME = "WWW-Authenticate";
  static final String RESPONSE_CODE_HEADER_NAME = "X-OAuth-Code";
  static final String CODE_REQUEST_HEADER =
      "realm=\"https://www.google.com/accounts/AuthSubRequest\"";
  static final String ID_REQUEST_HEADER =
      "Bearer realm=\"https://www.google.com/accounts/AuthSubRequest\"";

  // Test headers for user agent
  static final String USER_AGENT_HEADER_NAME = "User-Agent";
  static final String IOS_USER_AGENT = "Haiku+Client-iOS";

  // Used to create a test Person resource
  static final String TEST_GOOGLE_PROFILE_URL = "testGoogleProfileUrl";
  static final String TEST_GOOGLE_PHOTO_URL = "testGooglePhotoUrl";
  static final String TEST_GOOGLE_NAME = "testGoogleName";

  // Special values for use when making Google API calls
  static final String ME = "me";
  static final String VISIBLE = "visible";
  
  /**
   * Reads the client secret configuration file.
   *
   * @throws RuntimeException if there is a problem reading this file
   *  (such as it does not exist yet)
   */
  static void initClientSecrets() {
    try {
      Reader reader = new FileReader("client_secrets.json");
      clientSecrets = GoogleClientSecrets.load(HaikuPlus.JSON_FACTORY, reader);
    } catch (IOException e) {
      throw new RuntimeException("Cannot initialize client secrets", e);
    }
  }

  static String getClientId() {
    if (clientSecrets == null) {
      initClientSecrets();
    }
    return clientSecrets.getWeb().getClientId();
  }

  static String getClientSecret() {
    if (clientSecrets == null) {
      initClientSecrets();
    }
    return clientSecrets.getWeb().getClientSecret();
  }
  
  /**
   * Creates and returns a simple AuthenticatedFilter object for testing
   */
  static AuthenticatedFilter createTestFilter(
      final Plus mockApiClient,
      final GoogleAuthorizationCodeTokenRequest mockTokenRequest,
      final GoogleCredential actualCredential,
      GoogleIdTokenVerifier mockVerifier,
      GoogleIdTokenRepository mockRepo,
      ExecutorService executor) {
    Authenticate auth = new Authenticate(mockVerifier, mockRepo, executor) {
      @Override
      Plus createPlusApiClient(GoogleCredential credential) {
        return mockApiClient;
      }

      @Override
      GoogleAuthorizationCodeTokenRequest createTokenExchanger(String authorization, 
          String redirectUri) {
        return mockTokenRequest;
      }

      @Override
      GoogleCredential createCredential(String accessToken, String refreshToken) {
        return actualCredential;
      }

      // Overrides the access token verification to avoid the HTTP GET request.
      @Override
      String verifyAccessToken(String authorization, HttpServletResponse response) {
        DataStore.updateCredentialWithGoogleId(TEST_GOOGLE_USER, actualCredential);
        return TEST_GOOGLE_USER;
      }
    };
    return new AuthenticatedFilter(auth);
  }

  /**
   * Mocks the HttpServletRequest to return the session ID
   */
  static void setMockRequestSession(HttpServletRequest mockRequest) {
    HttpSession mockSession = mock(HttpSession.class);
    when(mockRequest.getSession()).thenReturn(mockSession);
    when(mockSession.getId()).thenReturn(TEST_SESSION);
  }

  /**
   * Mock the HttpServletRequest and HttpServletResponse objects to support writing to
   * the response, retrieving sessions from the request, and retrieving the request URL.
   */
  static PrintWriter mockHttpRequestResponsePair(HttpServletRequest mockRequest,
      HttpServletResponse mockResponse) throws IOException {
    PrintWriter mockWriter = mock(PrintWriter.class);
    setMockRequestSession(mockRequest);
    when(mockResponse.getWriter()).thenReturn(mockWriter);
    when(mockRequest.getRequestURL()).thenReturn(new StringBuffer(TEST_URL));
    when(mockRequest.getServerName()).thenReturn("not localhost");
    return mockWriter;
  }

  /**
   * Mocks the HttpServletRequest to return the correct headers, depending on the boolean values
   * provided to indicate when each header should be included
   */
  static void setMockRequestHeaders(HttpServletRequest mockRequest,
      boolean bearer, boolean code) {
    if (bearer) {
      when(mockRequest.getHeader(ID_HEADER_NAME))
          .thenReturn(ID_HEADER_SCHEME + " " + HEADER_CONTENT);
    } else {
      when(mockRequest.getHeader(ID_HEADER_NAME)).thenReturn(null);
    }

    if (code) {
      when(mockRequest.getHeader(CODE_HEADER_NAME)).thenReturn(HEADER_CONTENT);
    } else {
      when(mockRequest.getHeader(CODE_HEADER_NAME)).thenReturn(null);
    }
  }

  /**
   * Mocks the HttpServletRequest to return the correct headers, depending on the boolean values
   * provided to indicate when each header should be included
   */
  static void setMockUserAgentHeader(HttpServletRequest mockRequest, String userAgent) {
    when(mockRequest.getHeader(USER_AGENT_HEADER_NAME)).thenReturn(userAgent);
  }

  /**
   * Creates a mock of a User object, and populates it with an ID for testing, as well as
   * a Google ID.
   *
   * If {@code store} is true, it also stores the user in the DataStore for lookup.
   */
  static User createMockUser(boolean store, String userId, String googleId, boolean fresh) {
    User mockUser = mock(User.class);

    when(mockUser.getUserId()).thenReturn(userId);
    when(mockUser.getGoogleUserId()).thenReturn(googleId);
    if (fresh) {
      mockUser.lastUpdated = new Date();
    }
    if (store) {
      // We add the direct values here for use cases when the DataStore copies the mock to return
      mockUser.googlePlusId = googleId;
      mockUser.id = userId;

      DataStore.updateUser(mockUser);
    }
    return mockUser;
  }

  /**
   * Associates a test session with a test user
   */
  static void authenticateSessionForUser(String session, User mockUser) {
    Authenticate.authenticatedSessions.put(session, mockUser);
  }

  /**
   * Creates a GoogleCredential with test values associated with it based on the boolean
   * parameters indicating which tokens to include
   */
  static GoogleCredential createTestCredential(boolean refresh,
      boolean access) {
    final GoogleCredential actualCredential =
        new GoogleCredential.Builder()
            .setJsonFactory(HaikuPlus.JSON_FACTORY)
            .setTransport(HaikuPlus.TRANSPORT)
            .setClientSecrets(getClientId(), getClientSecret())
            .build();
    if (refresh) {
      actualCredential.setRefreshToken(TEST_REFRESH_TOKEN);
    }
    if (access) {
      actualCredential.setAccessToken(TEST_ACCESS_TOKEN);
    }
    return actualCredential;
  }

  /**
   * Associates a GoogleCredential with a test user
   */
  static GoogleCredential storeCredentialForUser(String googleId, boolean fromIos) {
    final GoogleCredential actualCredential = createTestCredential(!fromIos, fromIos);

    DataStore.updateCredentialWithGoogleId(googleId, actualCredential);
    return actualCredential;
  }

  /**
   * Creates a Payload object with the test user as the subject
   */
  static Payload createTestPayload() {
    Payload actualPayload = new Payload();
    actualPayload.setSubject(TEST_GOOGLE_USER);
    return actualPayload;
  }

  /**
   * Mocks the Google+ people.get and people.list API calls
   */
  static void mockPeopleAPIMethods(final Plus mockApiClient) throws IOException {
    Plus.People mockPeopleObject = mock(Plus.People.class);
    // Create the response for a people.get call
    Plus.People.Get mockPeopleGetObject = mock (Plus.People.Get.class);
    Person actualPerson = createTestPersonResponse(TEST_GOOGLE_USER);
    // Create the response for a people.list call
    Plus.People.List mockPeopleListObject = mock (Plus.People.List.class);
    PeopleFeed actualFeed = createTestPeopleFeed();

    when(mockApiClient.people()).thenReturn(mockPeopleObject);

    // Mock out people.get
    when(mockPeopleObject.get(ME)).thenReturn(mockPeopleGetObject);
    when(mockPeopleGetObject.execute()).thenReturn(actualPerson);

    // Mock out people.list
    when(mockPeopleObject.list(ME, VISIBLE)).thenReturn(mockPeopleListObject);
    when(mockPeopleListObject.execute()).thenReturn(actualFeed);
  }

  /**
   * Creates a Person object with associated test values
   */
  private static Person createTestPersonResponse(String googleId) {
    Person actualPerson = new Person();

    actualPerson.setId(googleId);
    actualPerson.setDisplayName(TEST_GOOGLE_NAME);
    Person.Image testImage = new Person.Image();
    testImage.setUrl(TEST_GOOGLE_PHOTO_URL);
    actualPerson.setImage(testImage);
    actualPerson.setUrl(TEST_GOOGLE_PROFILE_URL);
    return actualPerson;
  }

  /**
   * Creates a PeopleFeed object with prepopulated Person objects
   */
  private static PeopleFeed createTestPeopleFeed() {
    PeopleFeed feed = new PeopleFeed();
    List<Person> peopleList = new ArrayList<Person>();

    // Create a user connection that is a Haiku+ user
    Person haikuPerson = createTestPersonResponse(TEST_SECOND_GOOGLE_USER);
    peopleList.add(haikuPerson);

    DataStore.googleIdMap.put(TEST_SECOND_GOOGLE_USER, TEST_SECOND_USER);
    createMockUser(true, TEST_SECOND_USER, TEST_SECOND_GOOGLE_USER, false);

    // Create a user connection that is not a Haiku+ user
    Person nonhaikuPerson = createTestPersonResponse(NON_HAIKU_USER);
    peopleList.add(nonhaikuPerson);

    feed.setItems(peopleList);
    return feed;
  }

  /**
   * Places a test haiku in the DataStore
   */
  static Haiku mockHaikus(String userId, String googleId) {
    Haiku testHaiku = new Haiku();
    String haikuId = testHaiku.getId();
    testHaiku.setTitle(TEST_HAIKU_TITLE);
    testHaiku.setLineOne(TEST_HAIKU_LINE_ONE);
    testHaiku.setLineTwo(TEST_HAIKU_LINE_TWO);
    testHaiku.setLineThree(TEST_HAIKU_LINE_THREE);

    testHaiku.setContentUrl(TestUtils.TEST_URL + haikuId);
    testHaiku.setContentDeepLinkId(TestUtils.TEST_URL_HAIKU + haikuId);
    testHaiku.setCallToActionUrl(TestUtils.TEST_URL + haikuId + TestUtils.TEST_URL_VOTE);
    testHaiku.setCallToActionDeepLinkId(
        TestUtils.TEST_URL_HAIKU + haikuId + TestUtils.TEST_URL_VOTE);

    User author = createMockUser(true, userId, googleId, false);
    testHaiku.setAuthor(author);

    DataStore.addHaiku(testHaiku);
    return testHaiku;
  }

  /**
   * Creates a directed edge from the test user to the author
   * @throws UserNotFoundException 
   */
  static void mockFilterAuthorEdge(String testUserId, String authorId)
      throws UserNotFoundException {
    DataStore.updateCirclesForUser(testUserId, Collections.singletonList(authorId));
  }

  /**
   * Creates a filter parameter with the provided value
   */
  static void mockFilterRequest(HttpServletRequest mockRequest, String value) {
    when(mockRequest.getParameter(FILTER)).thenReturn(value);
  }

  /**
   * Creates a request containing the fields that are needed to create a new haiku
   */
  static Haiku mockHaikuRequestPayload(HaikuRepository mockRepo, HttpServletRequest mockRequest)
      throws IOException {
    Haiku testHaiku = new Haiku();
    testHaiku.setTitle(TEST_HAIKU_TITLE);
    testHaiku.setLineOne(TEST_HAIKU_LINE_ONE);
    testHaiku.setLineTwo(TEST_HAIKU_LINE_TWO);
    testHaiku.setLineThree(TEST_HAIKU_LINE_THREE);
    when(mockRepo.fromJson(mockRequest)).thenReturn(new Haiku(testHaiku));
    return testHaiku;
  }

  /**
   * Creates the request path from the testHaiku's ID
   */
  static void mockHaikuIdPath(HttpServletRequest mockRequest, String haikuId) {
    when(mockRequest.getPathInfo()).thenReturn("/" + haikuId);
  }

  /**
   * Creates the request path from the testHaiku's ID
   */
  static void mockHaikuVotePath(HttpServletRequest mockRequest, String haikuId) {
    when(mockRequest.getPathInfo()).thenReturn("/" + haikuId + "/vote");
  }

  /**
   * Verifies that the stored user is the expected user by comparing the stored fields
   * against the test values for Google+ ID, name, photo URL, and profile URL.
   */
  static void verifyDatastoreUserExists(String googleId) {
    User testUser = DataStore.loadUserWithGoogleId(googleId);
    assertEquals(googleId, testUser.googlePlusId);
    assertEquals(TestUtils.TEST_GOOGLE_NAME, testUser.googleDisplayName);
    assertEquals(TestUtils.TEST_GOOGLE_PHOTO_URL, testUser.googlePhotoUrl);
    assertEquals(TestUtils.TEST_GOOGLE_PROFILE_URL, testUser.googleProfileUrl);
  }

  /**
   * Verifies that the user has been associated with the current session and both values
   * are in the authenticatedSessions map.
   */
  static void verifyUserHasAuthenticatedSession(String userId, String sessionId) {
    assertEquals(userId, Authenticate.authenticatedSessions.get(sessionId).getGoogleUserId());
  }

  /**
   * Verifies the user credential has been stored as expected and that the chain.doFilter
   * method is invoked.
   *
   * @param testCredential the Credential object to be compared against the stored Credential
   * @param mockChain the filter chain to be invoked
   */
  static void verifyUserHasRefreshToken(String googleId, GoogleCredential testCredential,
      FilterChain mockChain, HttpServletRequest mockRequest, HttpServletResponse mockResponse)
      throws IOException, ServletException {
    GoogleCredential storedCredential =
        DataStore.loadCredentialWithGoogleId(googleId);
    assertEquals(storedCredential, testCredential);
    verify(mockChain).doFilter(mockRequest, mockResponse);
  }

  /**
   * Clears the test session, test credentials, and User objects that may have been
   * injected during a test
   */
  static void cleanUp() {
    Authenticate.authenticatedSessions.clear();
    DataStore.clear();
  }
}
