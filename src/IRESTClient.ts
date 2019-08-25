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

import ClientResponse from "./ClientResponse";

export default interface IRESTClient {

   /**
   * Sets the authorization header using a key
   *
   * @param {string} tenantId The value of the X-FusionAuth-TenantId header.
   * @returns {DefaultRESTClient}
   */
  withTenantId(tenantId): IRESTClient;


  /**
   * Sets the authorization header using a key
   *
   * @param {string} key The value of the authorization header.
   * @returns {IRESTClient}
   */
  withAuthorization(key): IRESTClient;

  /**
   * Adds a segment to the request uri
   */
  withUriSegment(segment): IRESTClient;

  /**
   * Adds a header to the request.
   *
   * @param key The name of the header.
   * @param value The value of the header.
   */
  withHeader(key: string, value: string): IRESTClient;

  /**
   * Sets the body of the client request.
   *
   * @param body The object to be written to the request body as JSON.
   */
  withJSONBody(body: object): IRESTClient;

  /**
   * Sets the http method for the request
   */
  withMethod(method): IRESTClient;

  /**
   * Sets the uri of the request
   */
  withUri(uri): IRESTClient;

  /**
   * Adds parameters to the request.
   *
   * @param name The name of the parameter.
   * @param value The value of the parameter, may be a string, object or number.
   */
  withParameter(name, value): IRESTClient;

  /**
   * Run the request and return a promise. This promise will resolve if the request is successful
   * and reject otherwise.
   */
  go<T>(): Promise<ClientResponse<T>>;
}