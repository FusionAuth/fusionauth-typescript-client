/*
 * Copyright (c) 2018-2020, FusionAuth, All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

export class JWTManager {
  public static revokedJWTs: object = {};
  constructor() {}

  /**
   * Checks if a JWT is valid. This assumes that the JWT contains a property named <code>exp</code> that is a
   * NumericDate value defined in the JWT specification and a property named <code>sub</code> that is the user id the
   * JWT belongs to.
   *
   * @param {object} jwt The JWT object.
   * @returns {boolean} True if the JWT is valid, false if it isn't.
   */
  public static isValid(jwt): boolean {
    const expiration = JWTManager.revokedJWTs[jwt.sub];
    return typeof(expiration) === 'undefined' || expiration === null || expiration < jwt.exp * 1000;
  }

  /**
   * Revokes all JWTs for the user with the given id using the duration (in seconds).
   *
   * @param {string} userId The user id (usually a UUID as a string).
   * @param {Number} durationSeconds The duration of all JWTs in seconds.
   */
  public static revoke(userId: string, durationSeconds: number): void {
    JWTManager.revokedJWTs[userId] = Date.now() + (durationSeconds * 1000);
  }

  /**
   * Cleans up the cache to remove old user's that have expired.
   * @private
   */
  static _cleanUp(): void {
    const now = Date.now();
    Object.keys(JWTManager.revokedJWTs).forEach((item, index, _array) => {
      const expiration = JWTManager.revokedJWTs[item];
      if (expiration < now) {
        delete JWTManager.revokedJWTs[item];
      }
    });
  }
}

/**
 * Set an interval to clean-up the cache, call .unref() to allow the process to exit without manually calling clearInterval.
 */
setInterval(JWTManager._cleanUp, 7000).unref();

