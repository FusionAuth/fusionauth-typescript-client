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

import {ClientResponse, IRestClient} from "./IRestClient";

let request = require("request");

/**
 * @author Brett P
 * @author Tyler Scott
 */
export class RequestClient implements IRestClient {
  public body: string;
  public headers: {[key: string]:string} = {};
  public method: string;
  public parameters: {[key: string]:string} = {};
  public uri: string;

  constructor(public host: string) {
  }

  /**
   * Sets the authorization header using a key
   *
   * @param {string} key The value of the authorization header.
   * @returns {RequestClient}
   */
  withAuthorization(key): RequestClient {
    if (key === null || typeof key === 'undefined') {
      return this;
    }

    this.withHeader('Authorization', key);
    return this;
  }

  /**
   * Adds a segment to the request uri
   */
  withUriSegment(segment): RequestClient {
    if (segment === null || segment === undefined) {
      return this;
    }
    if (this.uri === null) {
      this.uri = '';
    }
    if (this.uri.charAt(this.uri.length - 1) !== '/') {
      this.uri += '/';
    }
    this.uri = this.uri + segment;
    return this;
  }

  /**
   * Get the full url + parameter list
   */
  getFullUrl() {
    return this.host + this.uri + this.getQueryString();
  }

  /**
   * Adds a header to the request.
   *
   * @param key The name of the header.
   * @param value The value of the header.
   */
  withHeader(key: string, value: string): RequestClient {
    this.headers[key] = value;
    return this;
  }

  /**
   * Sets the body of the client request.
   *
   * @param body The object to be written to the request body as JSON.
   */
  withJSONBody(body: object): RequestClient {
    this.body = JSON.stringify(body);
    this.withHeader('Content-Type', 'application/json');
    // Omit the Content-Length, this is set by the browser. It is considered an un-safe header to set manually.
    return this;
  }

  /**
   * Sets the http method for the request
   */
  withMethod(method): RequestClient {
    this.method = method;
    return this;
  }

  /**
   * Sets the uri of the request
   */
  withUri(uri): RequestClient {
    this.uri = uri;
    return this;
  }

  /**
   * Adds parameters to the request.
   *
   * @param name The name of the parameter.
   * @param value The value of the parameter, may be a string, object or number.
   */
  withParameter(name, value): RequestClient {
    this.parameters[name] = value;
    return this;
  }

  /**
   * Run the request and return a promise. This promise will resolve if the request is successful
   * and reject otherwise.
   */
  go(): Promise<ClientResponse> {
    return new Promise<ClientResponse>((resolve, reject) => {
      request({
        uri: this.getFullUrl(),
        method: this.method,
        headers: this.headers,
        body: this.body
      }, (error, response, body) => {
        let clientResponse = new ClientResponse();
        if (error) {
          clientResponse.exception = error;
          reject(clientResponse);
        } else {
          clientResponse.statusCode = response.statusCode;
          clientResponse.response = body;

          try { // Try parsing as json
            clientResponse.response = JSON.parse(body);
          } catch (e) {
          }

          if (clientResponse.wasSuccessful()) {
            resolve(clientResponse);
          } else {
            reject(clientResponse)
          }
        }
      });
    });
  }

  private getQueryString() {
    var queryString = '';
    for (let key in this.parameters) {
      queryString += (queryString.length === 0) ? '?' : '&';
      queryString += key + '=' + encodeURIComponent(this.parameters[key]);
    }
    return queryString;
  }
}