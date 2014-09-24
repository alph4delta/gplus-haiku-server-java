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

import com.google.api.client.repackaged.com.google.common.annotations.VisibleForTesting;
import com.google.gson.annotations.Expose;

import java.util.Date;
import java.util.UUID;

/**
 * Contains the data for a haiku written by a registered user.
 *
 * Data members of this class are intentionally public in order to allow Gson
 * to function effectively when generating JSON representations of the class.
 *
 * @author joannasmith@google.com (Joanna Smith)
 */
public class Haiku extends Jsonifiable {
  /**
   * Application ID for this haiku.
   */
  @Expose
  @ReadOnly
  public String id;

  /**
   * The Haiku+ user that created the Haiku.
   */
  @Expose
  @ReadOnly
  public User author;

  /**
   * Title of the haiku.
   */
  @Expose
  public String title;

  /**
   * The first line of the haiku.
   */
  @Expose
  public String lineOne;

  /**
   * The second line of the haiku.
   */
  @Expose
  public String lineTwo;

  /**
   * The third line of the haiku.
   */
  @Expose
  public String lineThree;

  /**
   * Number of votes this haiku has received.
   */
  @Expose
  @ReadOnly
  public int votes;

  /**
   * Timestamp of the haiku.
   * 
   * Note: You might prefer an alternate library for managing time in your application. We chose 
   * Date for brevity in the sample.
   */
  @Expose
  @ReadOnly
  public Date creationTime;

  /**
   * Used by the Google fetcher to populate the snippet of a Google+ post.
   */
  @Expose
  @ReadOnly
  public String contentUrl;

  /**
   * Used to navigate to the target content in mobile applications.
   */
  @Expose
  @ReadOnly
  public String contentDeepLinkId;

  /**
   * Used to invoke the action that will be taken.
   */
  @Expose
  @ReadOnly
  public String callToActionUrl;

  /**
   * Used to invoke actions within mobile applications.
   */
  @Expose
  @ReadOnly
  public String callToActionDeepLinkId;

  public Haiku() {
    // In practice, we recommend generating haiku IDs from a sequence, but for the sake of brevity
    // in this sample, we are using UUIDs.
    id = UUID.randomUUID().toString();

    votes = 0;
    creationTime = new Date();
  }

  // For use by the Datastore class when creating a copy of a haiku
  @VisibleForTesting
  public Haiku(Haiku haiku) {
    this.id = haiku.id;
    this.author = haiku.author;
    this.title = haiku.title;
    this.lineOne = haiku.lineOne;
    this.lineTwo = haiku.lineTwo;
    this.lineThree = haiku.lineThree;
    this.votes = haiku.votes;
    this.creationTime = haiku.creationTime;
    this.contentUrl = haiku.contentUrl;
    this.contentDeepLinkId = haiku.contentDeepLinkId;
    this.callToActionUrl = haiku.callToActionUrl;
    this.callToActionDeepLinkId = haiku.callToActionDeepLinkId;
  }

  public String getId() {
    return id;
  }

  public User getAuthor() {
    return author;
  }

  public void setAuthor(User author) {
    this.author = author;
  }

  public String getTitle() {
    return title;
  }

  public void setTitle(String title) {
    this.title = title;
  }

  public String getLineOne() {
    return lineOne;
  }

  public void setLineOne(String lineOne) {
    this.lineOne = lineOne;
  }

  public String getLineTwo() {
    return lineTwo;
  }

  public void setLineTwo(String lineTwo) {
    this.lineTwo = lineTwo;
  }

  public String getLineThree() {
    return lineThree;
  }

  public void setLineThree(String lineThree) {
    this.lineThree = lineThree;
  }

  public Date getCreationTime() {
    return creationTime;
  }

  public int getVotes() {
    return votes;
  }

  public void setVotes(int votes) {
    this.votes = votes;
  }

  public void addVote() {
    this.votes += 1;
  }

  public String getContentUrl() {
    return contentUrl;
  }

  public void setContentUrl(String contentUrl) {
    this.contentUrl = contentUrl;
  }

  public String getContentDeepLinkId() {
    return contentDeepLinkId;
  }

  public void setContentDeepLinkId(String contentDeepLinkId) {
    this.contentDeepLinkId = contentDeepLinkId;
  }

  public String getCallToActionUrl() {
    return callToActionUrl;
  }

  public void setCallToActionUrl(String callToActionUrl) {
    this.callToActionUrl = callToActionUrl;
  }

  public String getCallToActionDeepLinkId() {
    return callToActionDeepLinkId;
  }

  public void setCallToActionDeepLinkId(String callToActionDeepLinkId) {
    this.callToActionDeepLinkId = callToActionDeepLinkId;
  }
}
