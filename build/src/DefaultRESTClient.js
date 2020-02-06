"use strict";
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
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const ClientResponse_1 = require("./ClientResponse");
const cross_fetch_1 = require("cross-fetch");
const queryString = require("query-string");
/**
 * @author Brett P
 * @author Tyler Scott
 * @author TJ Peden
 */
class DefaultRESTClient {
    constructor(host) {
        this.host = host;
        this.headers = {};
        this.parameters = {};
        this.responseHandler = DefaultRESTClient.emptyResponseHandler;
        this.errorResponseHandler = DefaultRESTClient.emptyResponseHandler;
    }
    /**
     * Sets the authorization header using a key
     *
     * @param {string} key The value of the authorization header.
     * @returns {DefaultRESTClient}
     */
    withAuthorization(key) {
        if (key === null || typeof key === 'undefined') {
            return this;
        }
        this.withHeader('Authorization', key);
        return this;
    }
    /**
     * Adds a segment to the request uri
     */
    withUriSegment(segment) {
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
    withFormData(body) {
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
    withHeader(key, value) {
        this.headers[key] = value;
        return this;
    }
    /**
     * Sets the body of the client request.
     *
     * @param body The object to be written to the request body as JSON.
     */
    withJSONBody(body) {
        this.body = JSON.stringify(body);
        this.withHeader('Content-Type', 'application/json');
        // Omit the Content-Length, this is set auto-magically by the request library
        return this;
    }
    /**
     * Sets the http method for the request
     */
    withMethod(method) {
        this.method = method;
        return this;
    }
    /**
     * Sets the uri of the request
     */
    withUri(uri) {
        this.uri = uri;
        return this;
    }
    /**
     * Adds parameters to the request.
     *
     * @param name The name of the parameter.
     * @param value The value of the parameter, may be a string, object or number.
     */
    withParameter(name, value) {
        this.parameters[name] = value;
        return this;
    }
    /**
     * Sets request's credentials.
     *
     * @param value A string indicating whether credentials will be sent with the request always, never, or only when sent to a same-origin URL.
     */
    withCredentials(value) {
        this.credentials = value;
        return this;
    }
    withResponseHandler(handler) {
        this.responseHandler = handler;
        return this;
    }
    withErrorResponseHandler(handler) {
        this.errorResponseHandler = handler;
        return this;
    }
    /**
     * Run the request and return a promise. This promise will resolve if the request is successful
     * and reject otherwise.
     */
    go() {
        return __awaiter(this, void 0, void 0, function* () {
            const clientResponse = new ClientResponse_1.default();
            let response;
            try {
                response = yield cross_fetch_1.default(this.getFullUrl(), {
                    method: this.method,
                    headers: this.headers,
                    body: this.body,
                    credentials: this.credentials,
                });
                if (response.ok) {
                    return yield this.responseHandler(response);
                }
                else {
                    throw yield this.errorResponseHandler(response);
                }
            }
            catch (error) {
                if (error instanceof ClientResponse_1.default) {
                    throw error; // Don't catch a ClientResponse (we want this to trigger the catch of the promise
                }
                if (response) { // Try to recover the response status
                    clientResponse.statusCode = response.status;
                }
                clientResponse.exception = error;
                throw clientResponse;
            }
        });
    }
    getQueryString() {
        const generatedQueryString = queryString.stringify(this.parameters);
        return `?${generatedQueryString}`;
    }
    static emptyResponseHandler(response) {
        return __awaiter(this, void 0, void 0, function* () {
            let clientResponse = new ClientResponse_1.default();
            clientResponse.statusCode = response.status;
            return clientResponse;
        });
    }
}
exports.default = DefaultRESTClient;
//# sourceMappingURL=DefaultRESTClient.js.map