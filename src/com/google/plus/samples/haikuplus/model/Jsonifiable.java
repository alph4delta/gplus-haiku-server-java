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

import com.google.gson.ExclusionStrategy;
import com.google.gson.FieldAttributes;
import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;

import java.io.Reader;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.reflect.Type;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

/**
 * Adds JSON serialization and deserialization to a class.  Uses Gson as the
 * underlying serialization mechanism.  Also adds java.util.Date serialization
 * and deserialization.
 *
 * @author joannasmith@google.com (Joanna Smith)
 * @author vicfryzel@google.com (Vic Fryzel)
 * @author cartland@google.com (Chris Cartland)
 */
public abstract class Jsonifiable {

  // Date configurations for ISO 8601 formatting in all date serializations/deserializations.
  private static final String TIME_SCHEME = "yyyy-MM-dd'T'HH:mm:ss'Z'";
  private static final TimeZone TZ = TimeZone.getTimeZone("UTC");
  private static final DateFormat DF = new SimpleDateFormat(TIME_SCHEME);
  static {
    DF.setTimeZone(TZ);
  }

  /**
   * JSON serializer for java.util.Date, required when serializing larger objects containing
   * Date members.
   */
  public static final JsonSerializer<Date> DATE_SERIALIZER = new JsonSerializer<Date>() {
    @Override
    public JsonElement serialize(Date src, Type typeOfSrc,
        JsonSerializationContext context) {
      try {
        return new JsonPrimitive(DF.format(src));
      } catch (NullPointerException e) {
        return null;
      }
    }
  };

  /**
   * JSON deserializer for java.util.Date, required when deserializing larger objects containing
   * Date members.
   */
  public static final JsonDeserializer<Date> DATE_DESERIALIZER = new JsonDeserializer<Date>() {
    @Override
    public Date deserialize(JsonElement json, Type typeOfT,
        JsonDeserializationContext context) throws JsonParseException {
      try {
        return DF.parse(json.getAsString());
      } catch (NullPointerException e) {
        return null;
      } catch (ParseException e) {
        return null;
      }
    }
  };

  /**
   * Gson object to use in all serialization and deserialization.
   */
  private static ExclusionStrategy excludeReadOnly = new ReadOnlyExclusionStrategy();
  public static final Gson GSON = new GsonBuilder()
      .excludeFieldsWithoutExposeAnnotation()
      .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
      .registerTypeAdapter(Date.class, Jsonifiable.DATE_SERIALIZER)
      .registerTypeAdapter(Date.class, Jsonifiable.DATE_DESERIALIZER)
      .addDeserializationExclusionStrategy(excludeReadOnly)
      .disableHtmlEscaping()
      .create();

  /**
   * @param json Object to convert to instance representation.
   * @param clazz Type to which object should be converted.
   * @return Instance representation of the given JSON object.
   */
  public static <T> T fromJson(String json, Class<T> clazz) {
    return GSON.fromJson(json, clazz);
  }

  /**
   * @param reader Reader from which to read JSON string.
   * @param clazz Type to which object should be converted.
   * @return Instance representation of the given JSON object.
   */
  public static <T> T fromJson(Reader reader, Class<T> clazz) {
    return GSON.fromJson(reader, clazz);
  }

  /**
   * @return JSON representation of this instance.
   */
  public String toJson() {
    return GSON.toJson(this);
  }

  /**
   * @return this.toJson()
   */
  @Override
  public String toString() {
    return toJson();
  }

  /**
   * Custom annotation to indicate read-only access to Gson.
   */
  @Retention(RetentionPolicy.RUNTIME)
  public @interface ReadOnly {}

  /**
   * Excludes any field (or class) that is tagged with an "@ReadOnly" annotation.
   */
  private static class ReadOnlyExclusionStrategy implements ExclusionStrategy {
    @Override
    public boolean shouldSkipClass(Class<?> clazz) {
      return clazz.getAnnotation(ReadOnly.class) != null;
    }

    @Override
    public boolean shouldSkipField(FieldAttributes f) {
      return f.getAnnotation(ReadOnly.class) != null;
    }
  }
}
