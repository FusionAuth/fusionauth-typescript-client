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

export type ResponseHandler<T> = (response: Response) => Promise<ClientResponse<T>>;
export type ErrorResponseHandler<T> = (response: Response) => Promise<ClientResponse<T>>;

export default interface IRESTClient<RT, ERT> {
  /**
   * Sets the authorization header using a key
   *
   * @param {string} key The value of the authorization header.
   * @returns {IRESTClient}
   */
  withAuthorization(key: string): IRESTClient<RT, ERT>;

  /**
   * Adds a segment to the request uri
   */
  withUriSegment(segment: string | number): IRESTClient<RT, ERT>;

  /**
   * Sets the body of the client request.
   *
   * @param body The object to be written to the request body as form data.
   */
  withFormData(body: FormData): IRESTClient<RT, ERT>;

  /**
   * Adds a header to the request.
   *
   * @param key The name of the header.
   * @param value The value of the header.
   */
  withHeader(key: string, value: string): IRESTClient<RT, ERT>;

  /**
   * Sets the body of the client request.
   *
   * @param body The object to be written to the request body as JSON.
   */
  withJSONBody(body: object): IRESTClient<RT, ERT>;

  /**
   * Sets the http method for the request
   */
  withMethod(method: string): IRESTClient<RT, ERT>;

  /**
   * Sets the uri of the request
   */
  withUri(uri: string): IRESTClient<RT, ERT>;

  /**
   * Adds parameters to the request.
   *
   * @param name The name of the parameter.
   * @param value The value of the parameter, may be a string, object or number.
   */
  withParameter(name: string, value: any): IRESTClient<RT, ERT>;

  /**
   * Sets request's credentials.
   *
   * @param value A string indicating whether credentials will be sent with the request always, never, or only when sent to a same-origin URL.
   */
  withCredentials(value: RequestCredentials): IRESTClient<RT, ERT>;

  /**
   * Sets the response handler. This could do processing before the ClientResponse is returned depending on the APIs expected response.
   *
   * @param handler
   */
  withResponseHandler(handler: ResponseHandler<RT>): IRESTClient<RT, ERT>;

  /**
   * Sets the error response handler.  Error response handlers have a generic but due to typescript limitations,
   * this value will not be propagated to the Promise catch statement
   * 
   * @param handler
   */
  withErrorResponseHandler(handler: ErrorResponseHandler<ERT>): IRESTClient<RT, ERT>;

  /**
   * Run the request and return a promise. This promise will resolve if the request is successful
   * and reject otherwise.
   */
  go(): Promise<ClientResponse<RT>>;
}