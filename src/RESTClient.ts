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
  public response: String;
  public exception: Error;

  wasSuccessful() {
    return this.statusCode >= 200 && this.statusCode < 300;
  }
}

/**
 * @author Brett P
 */
export class RESTClient {
  public body: string;
  public headers: Map<string, string> = new Map();
  public method: string;
  public parameters: Map<string, string> = new Map();
  public uri: string;

  constructor(public host: string) {
  }

  /**
   * Sets the authorization header using a key
   *
   * @param {string} key The value of the authorization header.
   * @returns {RESTClient}
   */
  withAuthorization(key): RESTClient {
    if (key === null || typeof key === 'undefined') {
      return this;
    }

    this.withHeader('Authorization', key);
    return this;
  }

  /**
   * Adds a segment to the request uri
   */
  withUriSegment(segment): RESTClient {
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
  withHeader(key: string, value: string): RESTClient {
    this.headers.set(key, value);
    return this;
  }

  /**
   * Sets the body of the client request.
   *
   * @param body The object to be written to the request body as JSON.
   */
  withJSONBody(body: object): RESTClient {
    this.body = JSON.stringify(body);
    this.withHeader('Content-Type', 'application/json');
    // Omit the Content-Length, this is set by the browser. It is considered an un-safe header to set manually.
    return this;
  }

  /**
   * Sets the http method for the request
   */
  withMethod(method): RESTClient {
    this.method = method;
    return this;
  }

  /**
   * Sets the uri of the request
   */
  withUri(uri): RESTClient {
    this.uri = uri;
    return this;
  }

  /**
   * Adds parameters to the request.
   *
   * @param name The name of the parameter.
   * @param value The value of the parameter, may be a string, object or number.
   */
  withParameter(name, value): RESTClient {
    this.parameters = this.parameters.set(name, value);
    return this;
  }

  /**
   * Run the request and return a promise. This promise will resolve if the request is successful
   * and reject otherwise.
   */
  go(): Promise<ClientResponse> {
    return new Promise<ClientResponse>((resolve, reject) => {
      var xhr = new XMLHttpRequest();
      var clientResponse = new ClientResponse();
      try {
        xhr.onreadystatechange = function () {
          if (xhr.readyState === XMLHttpRequest.DONE) {
            clientResponse.statusCode = xhr.status;

            var json = xhr.response;
            try {
              json = JSON.parse(xhr.response)
            } catch (e) {
            }

            clientResponse.response = json;

            if (clientResponse.wasSuccessful()) {
              resolve(clientResponse);
            } else {
              reject(clientResponse)
            }
          }
        };

        xhr.open(this.method, this.getFullUrl(), true);
        this.headers.forEach((value, key, _) => {
          xhr.setRequestHeader(key, value);
        });
        xhr.send(this.body);
      } catch (e) {
        clientResponse.exception = e;
        reject(clientResponse)
      }
    });
  }

  private getQueryString() {
    var queryString = '';
    this.parameters.forEach((value, key, _) => {
      queryString += (queryString.length === 0) ? '?' : '&';
      queryString += key + '=' + encodeURIComponent(value);
    });
    return queryString;
  }
}