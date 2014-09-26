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

package com.google.plus.samples.haikuplus.model;

import com.google.gson.annotations.Expose;

import java.util.Date;
import java.util.UUID;

/**
 * User of the Haiku+ application, including their cached Google user data and their Haiku+
 * user ID.
 *
 * Data members of this class are intentionally public in order to allow Gson
 * to function effectively when generating JSON representations of the class.
 *
 * @author joannasmith@google.com (Joanna Smith)
 */
public class User extends Jsonifiable {

  /**
   * Primary identifier of this User. Specific to Haiku+.
   */
  @Expose
  public String id;

  /**
   * Google ID for this User.
   */
  @Expose
  public String googlePlusId;

  /**
   * Display name that this User has chosen for Google products.
   */
  @Expose
  public String googleDisplayName;

  /**
   * Public Google+ profile photo URL for this User.
   */
  @Expose
  public String googlePhotoUrl;

  /**
   * Public Google+ profile URL for this User.
   */
  @Expose
  public String googleProfileUrl;

  /**
   * Used to determine whether the User's cached Google data is "fresh" (less than one day old).
   * 
   * Note: You might prefer an alternate library for managing time in your application. We chose 
   * Date for brevity in the sample.
   */
  @Expose
  public Date lastUpdated = null;

  /**
   * 1 day in milliseconds for cached data calculations (1000 * 60 * 60 * 24).
   * 
   * Note: This is not a recommended way to manage time comparisons. However, we are using it for 
   * brevity in the sample.
   */
  private static final Long ONE_DAY_IN_MS = 86400000L;

  public User() {
    // In practice, we recommend generating user IDs from a sequence, but for the sake of brevity
    // in this sample, we are using UUIDs.
    id = UUID.randomUUID().toString();
  }

  // For use by the Datastore class when creating a copy of a user
  User(User user) {
    this.id = user.id;
    this.googlePlusId = user.googlePlusId;
    this.googleDisplayName = user.googleDisplayName;
    this.googlePhotoUrl = user.googlePhotoUrl;
    this.googleProfileUrl = user.googleProfileUrl;
    this.lastUpdated = user.lastUpdated;
  }

  /**
   * Returns true if the cached Google user data is less than one day old
   */
  public boolean isDataFresh() {
    if (lastUpdated == null) {
      return false;
    }

    Date now = new Date();
    long timeDifference = now.getTime() - lastUpdated.getTime();
    return timeDifference < ONE_DAY_IN_MS;
  }

  public void setUserId(String userId) {
    id = userId;
  }

  public void setGoogleUserId(String googleId) {
    googlePlusId = googleId;
  }

  public void setGoogleDisplayName(String displayName) {
    googleDisplayName = displayName;
  }

  public void setGooglePhotoUrl(String photoUrl) {
    googlePhotoUrl = photoUrl;
  }

  public void setGoogleProfileUrl(String profileUrl) {
    googleProfileUrl = profileUrl;
  }

  public void setLastUpdated() {
    lastUpdated = new Date();
  }

  public String getUserId() {
    return id;
  }

  public String getGoogleUserId() {
    return googlePlusId;
  }

  public String getGoogleDisplayName() {
    return googleDisplayName;
  }

  public String getGooglePhotoUrl() {
    return googlePhotoUrl;
  }

  public String getGoogleProfileUrl() {
    return googleProfileUrl;
  }

  public Date getLastUpdated() {
    return lastUpdated;
  }
}
