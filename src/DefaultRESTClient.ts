/*
 * Copyright (c) 2019-2020, FusionAuth, All Rights Reserved
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

import IRESTClient, {ErrorResponseHandler, ResponseHandler} from "./IRESTClient";
import ClientResponse from "./ClientResponse";
import fetch, {BodyInit, RequestCredentials, Response} from 'node-fetch';
import {URLSearchParams} from "url";

/**
 * @author Brett P
 * @author Tyler Scott
 * @author TJ Peden
 */
export default class DefaultRESTClient<RT, ERT> implements IRESTClient<RT, ERT> {
  public body: BodyInit;
  public headers: Record<string, string> = {};
  public method: string;
  public parameters: Record<string, string> = {};
  public uri: string;
  public credentials: RequestCredentials;
  public responseHandler: ResponseHandler<RT> = DefaultRESTClient.JSONResponseHandler;
  public errorResponseHandler: ErrorResponseHandler<ERT> = DefaultRESTClient.ErrorJSONResponseHandler;

  constructor(public host: string) {
  }

  /**
   * Sets the authorization header using a key
   *
   * @param {string} key The value of the authorization header.
   * @returns {DefaultRESTClient}
   */
  withAuthorization(key: string): DefaultRESTClient<RT, ERT> {
    if (key === null || typeof key === 'undefined') {
      return this;
    }

    this.withHeader('Authorization', key);
    return this;
  }

  /**
   * Adds a segment to the request uri
   */
  withUriSegment(segment: string | number): DefaultRESTClient<RT, ERT> {
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
   * Sets the body of the client request.
   *
   * @param body The object to be written to the request body as form data.
   */
  withFormData(body: URLSearchParams): DefaultRESTClient<RT, ERT> {
    const body2 = new URLSearchParams();
    if (body) {
      body.forEach((value, name, searchParams) => {
        if (value && value.length > 0 && value != "null" && value != "undefined") {
          body2.set(name,value);
        }
      });
      body = body2;
    }
    this.body = body;
    this.withHeader('Content-Type', 'application/x-www-form-urlencoded');
    return this;
  }

  /**
   * Adds a header to the request.
   *
   * @param key The name of the header.
   * @param value The value of the header.
   */
  withHeader(key: string, value: string): DefaultRESTClient<RT, ERT> {
    this.headers[key] = value;
    return this;
  }

  /**
   * Sets the body of the client request.
   *
   * @param body The object to be written to the request body as JSON.
   */
  withJSONBody(body: object): DefaultRESTClient<RT, ERT> {
    this.body = JSON.stringify(body);
    this.withHeader('Content-Type', 'application/json');
    // Omit the Content-Length, this is set auto-magically by the request library
    return this;
  }

  /**
   * Sets the http method for the request
   */
  withMethod(method: string): DefaultRESTClient<RT, ERT> {
    this.method = method;
    return this;
  }

  /**
   * Sets the uri of the request
   */
  withUri(uri: string): DefaultRESTClient<RT, ERT> {
    this.uri = uri;
    return this;
  }

  /**
   * Adds parameters to the request.
   *
   * @param name The name of the parameter.
   * @param value The value of the parameter, may be a string, object or number.
   */
  withParameter(name: string, value: any): DefaultRESTClient<RT, ERT> {
    this.parameters[name] = value;
    return this;
  }

  /**
   * Sets request's credentials.
   *
   * @param value A string indicating whether credentials will be sent with the request always, never, or only when sent to a same-origin URL.
   */
  withCredentials(value: RequestCredentials): DefaultRESTClient<RT, ERT> {
    this.credentials = value;
    return this;
  }

  withResponseHandler(handler: ResponseHandler<RT>): DefaultRESTClient<RT, ERT> {
    this.responseHandler = handler;
    return this;
  }

  withErrorResponseHandler(handler: ErrorResponseHandler<ERT>): DefaultRESTClient<RT, ERT> {
    this.errorResponseHandler = handler;
    return this;
  }

  /**
   * Run the request and return a promise. This promise will resolve if the request is successful
   * and reject otherwise.
   */
  async go(): Promise<ClientResponse<RT>> {
    const clientResponse = new ClientResponse<RT>();

    let response: Response;
    try {
      response = await fetch(
          this.getFullUrl(),
          {
            method: this.method,
            headers: this.headers,
            body: this.body as BodyInit,
            // @ts-ignore (Credentials are not supported on NodeJS)
            credentials: this.credentials,
          },
      );

      if (response.ok) {
        return await this.responseHandler(response);
      } else {
        throw await this.errorResponseHandler(response);
      }
    } catch (error) {
      if (error instanceof ClientResponse) {
        throw error; // Don't catch a ClientResponse (we want this to trigger the catch of the promise
      }

      if (response) { // Try to recover the response status
        clientResponse.statusCode = response.status;
      }
      clientResponse.exception = error;

      throw clientResponse;
    }
  }

  private getQueryString() {
    var queryString = '';
    for (let key in this.parameters) {
      queryString += (queryString.length === 0) ? '?' : '&';
      queryString += key + '=' + encodeURIComponent(this.parameters[key]);
    }
    return queryString;
  }

  /**
   * A function that returns the JSON form of the response text.
   *
   * @param response
   * @constructor
   */
  static async JSONResponseHandler<RT>(response: Response): Promise<ClientResponse<RT>> {
    let clientResponse = new ClientResponse<RT>();

    clientResponse.statusCode = response.status;
    let type = response.headers.get("content-type");
    if (type && type.startsWith("application/json")) {
      clientResponse.response = await response.json();
    }

    return clientResponse;
  }

  /**
   * A function that returns the JSON form of the response text.
   *
   * @param response
   * @constructor
   */
  static async ErrorJSONResponseHandler<ERT>(response: Response): Promise<ClientResponse<ERT>> {
    let clientResponse = new ClientResponse<ERT>();

    clientResponse.statusCode = response.status;
    let type = response.headers.get("content-type");
    if (type && type.startsWith("application/json")) {
      clientResponse.exception = await response.json();
    }

    return clientResponse;
  }
}
