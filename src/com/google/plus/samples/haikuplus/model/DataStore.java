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

package com.google.plus.samples.haikuplus.model;

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.repackaged.com.google.common.annotations.VisibleForTesting;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;


/**
 * A datastore abstraction API which understands the three data types that correspond to the
 * resource types:
 * Users
 * Haikus
 * User edges
 *
 * Resources loaded from the datastore will always be copies.
 *
 * This API is designed to abstract out where you would make database calls. You should expect
 * to replace the functionality here with how you would interact with your database.
 *
 * @author joannasmith@google.com (Joanna Smith)
 */
public class DataStore {
  /**
   * Cache of user data, retrievable by Haiku+ ID
   */
  private static final Map<String, User> users = new ConcurrentHashMap<String, User>();

  /**
   * Mapping of Google IDs to Haiku+ IDs
   */
  @VisibleForTesting
  public static final Map<String, String> googleIdMap = new ConcurrentHashMap<String, String>();

  /**
   * Local storage of users and their authentication credentials.
   */
  private static Map<String, GoogleCredential> credentials =
      new ConcurrentHashMap<String, GoogleCredential>();

  /**
   * Cache of haikus, mapped by the haiku's ID
   */
  private static Map<String, Haiku> haikus = new ConcurrentHashMap<String, Haiku>();

   /**
    * Mapping of user IDs to haiku IDs
    */
  @VisibleForTesting
  public static Map<String, List<String>> userHaikuMap =
      new ConcurrentHashMap<String, List<String>>();

  /**
   * List of user connections, mapped by the user's Haiku+ ID to the list of edges that user has.
   */
  @VisibleForTesting
  public static Map<String, List<String>> edges = new ConcurrentHashMap<String, List<String>>();

  /**
   * Updates an existing user in the list, or adds a new user to the list of users.
   *
   * Does not ensure uniqueness of any attributes of newUser.
   * Expects the user id to be set for existing users; may initialize the id for new users.
   *
   * @param user the user to add or update.
   * @returns the Haiku+ ID of the updated user.
   */
  public static String updateUser(User user) {
    String userId = user.getUserId();
    users.put(userId, user);

    String googleId = user.getGoogleUserId();
    if (googleId != null) {
      googleIdMap.put(googleId, userId);
    }

    return userId;
  }

  /**
   * Loads a copy of a user from the datastore.
   *
   * @param userId the user ID of the user to load.
   * @returns a copy of the specified user if it exists or null if the user does not exist.
   */
  public static User loadUser(String userId){
    User user = users.get(userId);
    if (user != null) {
      return new User(user);
    } else {
      return null;
    }
  }

  /**
   * Loads a copy of a user from the datastore.
   *
   * @param googleId the Google ID of the user to load.
   * @returns a copy of the specified user if it exists or null if the user does not exist.
   */
  public static User loadUserWithGoogleId(String googleId){
    String userId = googleIdMap.get(googleId);
    if (userId != null) {
      return loadUser(userId);
    }
    return null;
  }

  /**
   * Deletes a user from the datastore.
   *
   * @param userId the user ID of the user to delete.
   */
  public static void deleteUser(String userId) {
    User user = loadUser(userId);
    if (user != null) {
      String googleUserId = user.getGoogleUserId();
      if (googleUserId != null) {
        googleIdMap.remove(googleUserId);
      }
    }
    edges.remove(userId);
    users.remove(userId);
  }

  /**
   * Updates an existing user credential in the list, or adds a new user credential to the list
   * of credentials, referenced by the user's Google ID.
   *
   * @param googleId the Google ID of the user to authorize.
   * @param credential the GoogleCredential object authorizing the user.
   */
  public static void updateCredentialWithGoogleId(String googleId, GoogleCredential credential) {
    credentials.put(googleId, credential);
  }

  /**
   * Loads a user's Google credentials from the datastore.
   *
   * @param googleId the Google ID of the user to lookup.
   * @returns the associated GoogleCredential object, or null if the credentials do not exist.
   */
  public static GoogleCredential loadCredentialWithGoogleId(String googleId) {
    return credentials.get(googleId);
  }

  /**
   * Loads a user's Google credentials from the datastore. If the credential does not exist,
   * a CredentialNotFoundException is raised.
   *
   * @param googleId the Google ID of the user to lookup.
   * @returns the associated GoogleCredential object.
   */
  public static GoogleCredential requireCredentialWithGoogleId(String googleId)
      throws CredentialNotFoundException{
    GoogleCredential credential = loadCredentialWithGoogleId(googleId);

    if (credential == null) {
      throw new CredentialNotFoundException();
    }

    return credential;
  }

  /**
   * Deletes a user's Google credentials from the datastore.
   *
   * @param googleId the Google ID of the user credentials to delete.
   */
  public static void deleteCredentialWithGoogleId(String googleId) {
    credentials.remove(googleId);
  }

  /**
   * Deletes all existing edges for the specified user from the datastore, and then adds
   * the new edges in the supplied list of Google+ users. This allows us to ensure that
   * uncircled users are removed and all new users are added, which is important so that
   * we do not surprise the user with inconsistent social connections.
   *
   * @param sourceUser the application user ID of the user which is the source of the
   *     social connection.
   * @param circles the list of Google+ user IDs for which that user has an edge
   * @throws UserNotFoundException if the user does not exist in the datastore.
   */
  public static void updateCirclesForUser(String sourceUser, List<String> circles)
      throws UserNotFoundException {
    User user = loadUser(sourceUser);
    if (user == null) {
      throw new UserNotFoundException();
    }

    edges.remove(sourceUser);
    edges.put(sourceUser, circles);
  }

  /**
   * Adds a new haiku to the datastore.
   *
   * Does not ensure uniqueness of any attributes of newHaiku.
   *
   * @returns the ID of the newly created haiku.
   * @param newHaiku the new haiku to add.
   */
  public static String addHaiku(Haiku newHaiku) {
    String haikuId = newHaiku.getId();
    haikus.put(haikuId, newHaiku);

    // Also add a mapping of the user to their created haikus. Normally, a relational database
    // could identify these haikus with a query, but we maintain a mapping for simplicity.
    String userId = newHaiku.getAuthor().getUserId();
    List<String> userHaikus = userHaikuMap.get(userId);
    if (userHaikus != null) {
      userHaikus.add(haikuId);
    } else {
      List<String> userHaikuList = new ArrayList<String>();
      userHaikuList.add(haikuId);
      userHaikuMap.put(userId, userHaikuList);
    }

    return haikuId;
  }

  /**
   * Loads a haiku from the datastore.
   *
   * @param haikuId the haiku ID of the haiku to load.
   * @returns a copy of the specified haiku if it exists, or null if it does not.
   */
  public static Haiku loadHaiku(String haikuId) {
    Haiku haiku = haikus.get(haikuId);

    if (haiku != null) {
      return new Haiku(haiku);
    } else {
      return null;
    }
  }

  /**
   * Delete all haikus written by a user from the datastore.
   *
   * @param userId the app user ID.
   */
  public static void deleteHaikusForUser(String userId) {
    List<String> userHaikus = userHaikuMap.get(userId);
    if (userHaikus != null) {
      for (String haikuId : userHaikus) {
        haikus.remove(haikuId);
      }
      userHaikuMap.remove(userId);
    }
  }

  /**
   * Loads a list of all haikus from the datastore, optionally filtered to
   * the circles of the specified User.
   *
   * @param restrictByCircles (optional) the User to restrict haikus to; null if the list
   *     is unfiltered.
   * @returns the list of haikus.
   */
  public static List<Haiku> loadHaikus(User restrictByCircles) {
    List<Haiku> haikuList = new ArrayList<Haiku>();
    List<String> circles = null;
    if (restrictByCircles != null) {
      circles = loadConnectionsForUser(restrictByCircles.getUserId());
    }

    for (String haikuId : haikus.keySet()) {
      Haiku h = haikus.get(haikuId);
      if (circles != null) {
        if (!circles.contains(h.getAuthor().getUserId())) {
          continue;
        }
      }
      haikuList.add(h);
    }

    // We sort the list by vote and date before returning it.
    return sortHaikusByVote(haikuList);
  }

  /**
   * Compiles a list of Haiku+ user IDs for the edges associated with the provided user.
   * This makes it easier to determine if a haiku was created by a user's connection. A
   * relational database could query for this information, but for simplicity of the sample,
   * we construct a list here.
   */
  private static List<String> loadConnectionsForUser(String userId) {
    return edges.get(userId);
  }

  /**
   * Sorts the provided list of haikus in decreasing order by vote number. A tie in votes is then
   * ordered by most recent creation time.
   */
  private static List<Haiku> sortHaikusByVote(List<Haiku> haikus) {
    Collections.sort(haikus, new CustomComparator());
    return haikus;
  }

  /**
   * Reset all of the data in the DataStore.
   */
  public static void clear() {
    users.clear();
    googleIdMap.clear();
    credentials.clear();
    haikus.clear();
    userHaikuMap.clear();
    edges.clear();
  }

  /**
   * Custom comparator to sort a list of haikus by number of votes and time created. A tie in
   * vote count is then ordered by most recent creation time.
   */
  private static class CustomComparator implements Comparator<Haiku>{
    @Override
    public int compare(Haiku h1, Haiku h2) {
      if (h1.getVotes() < h2.getVotes()) {
        return -1;
      } else if (h1.getVotes() > h2.getVotes()) {
        return 1;
      } else {
        if (h1.getCreationTime().before(h2.getCreationTime())) {
          return -1;
        } else if (h1.getCreationTime().after(h2.getCreationTime())) {
          return 1;
        } else {
          return 0;
        }
      }
    }
  }

  /**
   * Inner class to define the CredentialNotFoundException, which is raised when a
   * user does not exist, but an attempt it made to store edges for that user.
   */
  public static class CredentialNotFoundException extends Exception {}

  /**
   * Inner class to define the UserNotFoundException, which is raised when a
   * credential does not exist, but is required.
   */
  public static class UserNotFoundException extends Exception {}
}
