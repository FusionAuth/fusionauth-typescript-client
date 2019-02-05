/*
 * Copyright (c) 2019, FusionAuth, All Rights Reserved
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

export class ClientResponse {
  public statusCode: number;
  public response: object | string;
  public exception: Error;

  wasSuccessful() {
    return this.statusCode >= 200 && this.statusCode < 300;
  }
}

export interface IRestClientBuilder {
  build(host: string): IRestClient;
}

export interface IRestClient {
  /**
   * Sets the authorization header using a key
   *
   * @param {string} key The value of the authorization header.
   * @returns {IRestClient}
   */
  withAuthorization(key): IRestClient;

  /**
   * Adds a segment to the request uri
   */
  withUriSegment(segment): IRestClient;

  /**
   * Adds a header to the request.
   *
   * @param key The name of the header.
   * @param value The value of the header.
   */
  withHeader(key: string, value: string): IRestClient;

  /**
   * Sets the body of the client request.
   *
   * @param body The object to be written to the request body as JSON.
   */
  withJSONBody(body: object): IRestClient;

  /**
   * Sets the http method for the request
   */
  withMethod(method): IRestClient;

  /**
   * Sets the uri of the request
   */
  withUri(uri): IRestClient;

  /**
   * Adds parameters to the request.
   *
   * @param name The name of the parameter.
   * @param value The value of the parameter, may be a string, object or number.
   */
  withParameter(name, value): IRestClient;

  /**
   * Run the request and return a promise. This promise will resolve if the request is successful
   * and reject otherwise.
   */
  go(): Promise<ClientResponse>;
}