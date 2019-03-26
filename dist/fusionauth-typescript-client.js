(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
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
function __export(m) {
    for (var p in m) if (!exports.hasOwnProperty(p)) exports[p] = m[p];
}
Object.defineProperty(exports, "__esModule", { value: true });
__export(require("./src/FusionAuthClient"));
__export(require("./src/IRESTClient"));
__export(require("./src/DefaultRESTClientBuilder"));

},{"./src/DefaultRESTClientBuilder":11,"./src/FusionAuthClient":12,"./src/IRESTClient":13}],2:[function(require,module,exports){
'use strict';

var isCallable = require('is-callable');

var toStr = Object.prototype.toString;
var hasOwnProperty = Object.prototype.hasOwnProperty;

var forEachArray = function forEachArray(array, iterator, receiver) {
    for (var i = 0, len = array.length; i < len; i++) {
        if (hasOwnProperty.call(array, i)) {
            if (receiver == null) {
                iterator(array[i], i, array);
            } else {
                iterator.call(receiver, array[i], i, array);
            }
        }
    }
};

var forEachString = function forEachString(string, iterator, receiver) {
    for (var i = 0, len = string.length; i < len; i++) {
        // no such thing as a sparse string.
        if (receiver == null) {
            iterator(string.charAt(i), i, string);
        } else {
            iterator.call(receiver, string.charAt(i), i, string);
        }
    }
};

var forEachObject = function forEachObject(object, iterator, receiver) {
    for (var k in object) {
        if (hasOwnProperty.call(object, k)) {
            if (receiver == null) {
                iterator(object[k], k, object);
            } else {
                iterator.call(receiver, object[k], k, object);
            }
        }
    }
};

var forEach = function forEach(list, iterator, thisArg) {
    if (!isCallable(iterator)) {
        throw new TypeError('iterator must be a function');
    }

    var receiver;
    if (arguments.length >= 3) {
        receiver = thisArg;
    }

    if (toStr.call(list) === '[object Array]') {
        forEachArray(list, iterator, receiver);
    } else if (typeof list === 'string') {
        forEachString(list, iterator, receiver);
    } else {
        forEachObject(list, iterator, receiver);
    }
};

module.exports = forEach;

},{"is-callable":4}],3:[function(require,module,exports){
(function (global){
var win;

if (typeof window !== "undefined") {
    win = window;
} else if (typeof global !== "undefined") {
    win = global;
} else if (typeof self !== "undefined"){
    win = self;
} else {
    win = {};
}

module.exports = win;

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{}],4:[function(require,module,exports){
'use strict';

var fnToStr = Function.prototype.toString;

var constructorRegex = /^\s*class\b/;
var isES6ClassFn = function isES6ClassFunction(value) {
	try {
		var fnStr = fnToStr.call(value);
		return constructorRegex.test(fnStr);
	} catch (e) {
		return false; // not a function
	}
};

var tryFunctionObject = function tryFunctionToStr(value) {
	try {
		if (isES6ClassFn(value)) { return false; }
		fnToStr.call(value);
		return true;
	} catch (e) {
		return false;
	}
};
var toStr = Object.prototype.toString;
var fnClass = '[object Function]';
var genClass = '[object GeneratorFunction]';
var hasToStringTag = typeof Symbol === 'function' && typeof Symbol.toStringTag === 'symbol';

module.exports = function isCallable(value) {
	if (!value) { return false; }
	if (typeof value !== 'function' && typeof value !== 'object') { return false; }
	if (typeof value === 'function' && !value.prototype) { return true; }
	if (hasToStringTag) { return tryFunctionObject(value); }
	if (isES6ClassFn(value)) { return false; }
	var strClass = toStr.call(value);
	return strClass === fnClass || strClass === genClass;
};

},{}],5:[function(require,module,exports){
module.exports = isFunction

var toString = Object.prototype.toString

function isFunction (fn) {
  var string = toString.call(fn)
  return string === '[object Function]' ||
    (typeof fn === 'function' && string !== '[object RegExp]') ||
    (typeof window !== 'undefined' &&
     // IE8 and below
     (fn === window.setTimeout ||
      fn === window.alert ||
      fn === window.confirm ||
      fn === window.prompt))
};

},{}],6:[function(require,module,exports){
var trim = require('trim')
  , forEach = require('for-each')
  , isArray = function(arg) {
      return Object.prototype.toString.call(arg) === '[object Array]';
    }

module.exports = function (headers) {
  if (!headers)
    return {}

  var result = {}

  forEach(
      trim(headers).split('\n')
    , function (row) {
        var index = row.indexOf(':')
          , key = trim(row.slice(0, index)).toLowerCase()
          , value = trim(row.slice(index + 1))

        if (typeof(result[key]) === 'undefined') {
          result[key] = value
        } else if (isArray(result[key])) {
          result[key].push(value)
        } else {
          result[key] = [ result[key], value ]
        }
      }
  )

  return result
}
},{"for-each":2,"trim":7}],7:[function(require,module,exports){

exports = module.exports = trim;

function trim(str){
  return str.replace(/^\s*|\s*$/g, '');
}

exports.left = function(str){
  return str.replace(/^\s*/, '');
};

exports.right = function(str){
  return str.replace(/\s*$/, '');
};

},{}],8:[function(require,module,exports){
"use strict";
var window = require("global/window")
var isFunction = require("is-function")
var parseHeaders = require("parse-headers")
var xtend = require("xtend")

module.exports = createXHR
// Allow use of default import syntax in TypeScript
module.exports.default = createXHR;
createXHR.XMLHttpRequest = window.XMLHttpRequest || noop
createXHR.XDomainRequest = "withCredentials" in (new createXHR.XMLHttpRequest()) ? createXHR.XMLHttpRequest : window.XDomainRequest

forEachArray(["get", "put", "post", "patch", "head", "delete"], function(method) {
    createXHR[method === "delete" ? "del" : method] = function(uri, options, callback) {
        options = initParams(uri, options, callback)
        options.method = method.toUpperCase()
        return _createXHR(options)
    }
})

function forEachArray(array, iterator) {
    for (var i = 0; i < array.length; i++) {
        iterator(array[i])
    }
}

function isEmpty(obj){
    for(var i in obj){
        if(obj.hasOwnProperty(i)) return false
    }
    return true
}

function initParams(uri, options, callback) {
    var params = uri

    if (isFunction(options)) {
        callback = options
        if (typeof uri === "string") {
            params = {uri:uri}
        }
    } else {
        params = xtend(options, {uri: uri})
    }

    params.callback = callback
    return params
}

function createXHR(uri, options, callback) {
    options = initParams(uri, options, callback)
    return _createXHR(options)
}

function _createXHR(options) {
    if(typeof options.callback === "undefined"){
        throw new Error("callback argument missing")
    }

    var called = false
    var callback = function cbOnce(err, response, body){
        if(!called){
            called = true
            options.callback(err, response, body)
        }
    }

    function readystatechange() {
        if (xhr.readyState === 4) {
            setTimeout(loadFunc, 0)
        }
    }

    function getBody() {
        // Chrome with requestType=blob throws errors arround when even testing access to responseText
        var body = undefined

        if (xhr.response) {
            body = xhr.response
        } else {
            body = xhr.responseText || getXml(xhr)
        }

        if (isJson) {
            try {
                body = JSON.parse(body)
            } catch (e) {}
        }

        return body
    }

    function errorFunc(evt) {
        clearTimeout(timeoutTimer)
        if(!(evt instanceof Error)){
            evt = new Error("" + (evt || "Unknown XMLHttpRequest Error") )
        }
        evt.statusCode = 0
        return callback(evt, failureResponse)
    }

    // will load the data & process the response in a special response object
    function loadFunc() {
        if (aborted) return
        var status
        clearTimeout(timeoutTimer)
        if(options.useXDR && xhr.status===undefined) {
            //IE8 CORS GET successful response doesn't have a status field, but body is fine
            status = 200
        } else {
            status = (xhr.status === 1223 ? 204 : xhr.status)
        }
        var response = failureResponse
        var err = null

        if (status !== 0){
            response = {
                body: getBody(),
                statusCode: status,
                method: method,
                headers: {},
                url: uri,
                rawRequest: xhr
            }
            if(xhr.getAllResponseHeaders){ //remember xhr can in fact be XDR for CORS in IE
                response.headers = parseHeaders(xhr.getAllResponseHeaders())
            }
        } else {
            err = new Error("Internal XMLHttpRequest Error")
        }
        return callback(err, response, response.body)
    }

    var xhr = options.xhr || null

    if (!xhr) {
        if (options.cors || options.useXDR) {
            xhr = new createXHR.XDomainRequest()
        }else{
            xhr = new createXHR.XMLHttpRequest()
        }
    }

    var key
    var aborted
    var uri = xhr.url = options.uri || options.url
    var method = xhr.method = options.method || "GET"
    var body = options.body || options.data
    var headers = xhr.headers = options.headers || {}
    var sync = !!options.sync
    var isJson = false
    var timeoutTimer
    var failureResponse = {
        body: undefined,
        headers: {},
        statusCode: 0,
        method: method,
        url: uri,
        rawRequest: xhr
    }

    if ("json" in options && options.json !== false) {
        isJson = true
        headers["accept"] || headers["Accept"] || (headers["Accept"] = "application/json") //Don't override existing accept header declared by user
        if (method !== "GET" && method !== "HEAD") {
            headers["content-type"] || headers["Content-Type"] || (headers["Content-Type"] = "application/json") //Don't override existing accept header declared by user
            body = JSON.stringify(options.json === true ? body : options.json)
        }
    }

    xhr.onreadystatechange = readystatechange
    xhr.onload = loadFunc
    xhr.onerror = errorFunc
    // IE9 must have onprogress be set to a unique function.
    xhr.onprogress = function () {
        // IE must die
    }
    xhr.onabort = function(){
        aborted = true;
    }
    xhr.ontimeout = errorFunc
    xhr.open(method, uri, !sync, options.username, options.password)
    //has to be after open
    if(!sync) {
        xhr.withCredentials = !!options.withCredentials
    }
    // Cannot set timeout with sync request
    // not setting timeout on the xhr object, because of old webkits etc. not handling that correctly
    // both npm's request and jquery 1.x use this kind of timeout, so this is being consistent
    if (!sync && options.timeout > 0 ) {
        timeoutTimer = setTimeout(function(){
            if (aborted) return
            aborted = true//IE9 may still call readystatechange
            xhr.abort("timeout")
            var e = new Error("XMLHttpRequest timeout")
            e.code = "ETIMEDOUT"
            errorFunc(e)
        }, options.timeout )
    }

    if (xhr.setRequestHeader) {
        for(key in headers){
            if(headers.hasOwnProperty(key)){
                xhr.setRequestHeader(key, headers[key])
            }
        }
    } else if (options.headers && !isEmpty(options.headers)) {
        throw new Error("Headers cannot be set on an XDomainRequest object")
    }

    if ("responseType" in options) {
        xhr.responseType = options.responseType
    }

    if ("beforeSend" in options &&
        typeof options.beforeSend === "function"
    ) {
        options.beforeSend(xhr)
    }

    // Microsoft Edge browser sends "undefined" when send is called with undefined value.
    // XMLHttpRequest spec says to pass null as body to indicate no body
    // See https://github.com/naugtur/xhr/issues/100.
    xhr.send(body || null)

    return xhr


}

function getXml(xhr) {
    // xhr.responseXML will throw Exception "InvalidStateError" or "DOMException"
    // See https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest/responseXML.
    try {
        if (xhr.responseType === "document") {
            return xhr.responseXML
        }
        var firefoxBugTakenEffect = xhr.responseXML && xhr.responseXML.documentElement.nodeName === "parsererror"
        if (xhr.responseType === "" && !firefoxBugTakenEffect) {
            return xhr.responseXML
        }
    } catch (e) {}

    return null
}

function noop() {}

},{"global/window":3,"is-function":5,"parse-headers":6,"xtend":9}],9:[function(require,module,exports){
module.exports = extend

var hasOwnProperty = Object.prototype.hasOwnProperty;

function extend() {
    var target = {}

    for (var i = 0; i < arguments.length; i++) {
        var source = arguments[i]

        for (var key in source) {
            if (hasOwnProperty.call(source, key)) {
                target[key] = source[key]
            }
        }
    }

    return target
}

},{}],10:[function(require,module,exports){
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
Object.defineProperty(exports, "__esModule", { value: true });
const IRESTClient_1 = require("./IRESTClient");
let request = require("request");
/**
 * @author Brett P
 * @author Tyler Scott
 */
class DefaultRESTClient {
    constructor(host) {
        this.host = host;
        this.headers = {};
        this.parameters = {};
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
     * Run the request and return a promise. This promise will resolve if the request is successful
     * and reject otherwise.
     */
    go() {
        return new Promise((resolve, reject) => {
            request({
                uri: this.getFullUrl(),
                method: this.method,
                headers: this.headers,
                body: this.body
            }, (error, response, body) => {
                let clientResponse = new IRESTClient_1.ClientResponse();
                if (error) {
                    clientResponse.exception = error;
                    reject(clientResponse);
                }
                else {
                    clientResponse.statusCode = response.statusCode;
                    clientResponse.response = body;
                    try { // Try parsing as json
                        clientResponse.response = JSON.parse(body);
                    }
                    catch (e) {
                    }
                    if (clientResponse.wasSuccessful()) {
                        resolve(clientResponse);
                    }
                    else {
                        reject(clientResponse);
                    }
                }
            });
        });
    }
    getQueryString() {
        var queryString = '';
        for (let key in this.parameters) {
            queryString += (queryString.length === 0) ? '?' : '&';
            queryString += key + '=' + encodeURIComponent(this.parameters[key]);
        }
        return queryString;
    }
}
exports.DefaultRESTClient = DefaultRESTClient;

},{"./IRESTClient":13,"request":8}],11:[function(require,module,exports){
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
Object.defineProperty(exports, "__esModule", { value: true });
const DefaultRESTClient_1 = require("./DefaultRESTClient");
class DefaultRESTClientBuilder {
    build(host) {
        return new DefaultRESTClient_1.DefaultRESTClient(host);
    }
}
exports.DefaultRESTClientBuilder = DefaultRESTClientBuilder;

},{"./DefaultRESTClient":10}],12:[function(require,module,exports){
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
Object.defineProperty(exports, "__esModule", { value: true });
const DefaultRESTClientBuilder_1 = require("./DefaultRESTClientBuilder");
class FusionAuthClient {
    constructor(apiKey, host) {
        this.apiKey = apiKey;
        this.host = host;
        this.clientBuilder = new DefaultRESTClientBuilder_1.DefaultRESTClientBuilder();
    }
    /**
     * Takes an action on a user. The user being actioned is called the "actionee" and the user taking the action is called the
     * "actioner". Both user ids are required. You pass the actionee's user id into the method and the actioner's is put into the
     * request object.
     *
     * @param {string} actioneeUserId The actionee's user id.
     * @param {Object} request The action request that includes all of the information about the action being taken including
     *    the id of the action, any options and the duration (if applicable).
     */
    actionUser(actioneeUserId, request) {
        return this.start()
            .withUri('/api/user/action')
            .withUriSegment(actioneeUserId)
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Cancels the user action.
     *
     * @param {string} actionId The action id of the action to cancel.
     * @param {Object} request The action request that contains the information about the cancellation.
     */
    cancelAction(actionId, request) {
        return this.start()
            .withUri('/api/user/action')
            .withUriSegment(actionId)
            .withJSONBody(request)
            .withMethod("DELETE")
            .go();
    }
    /**
     * Changes a user's password using the change password Id. This usually occurs after an email has been sent to the user
     * and they clicked on a link to reset their password.
     *
     * @param {string} changePasswordId The change password Id used to find the user. This value is generated by FusionAuth once the change password workflow has been initiated.
     * @param {Object} request The change password request that contains all of the information used to change the password.
     */
    changePassword(changePasswordId, request) {
        return this.start()
            .withUri('/api/user/change-password')
            .withUriSegment(changePasswordId)
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Changes a user's password using their identity (login id and password). Using a loginId instead of the changePasswordId
     * bypasses the email verification and allows a password to be changed directly without first calling the #forgotPassword
     * method.
     *
     * @param {Object} request The change password request that contains all of the information used to change the password.
     */
    changePasswordByIdentity(request) {
        return this.start()
            .withUri('/api/user/change-password')
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Adds a comment to the user's account.
     *
     * @param {Object} request The request object that contains all of the information used to create the user comment.
     */
    commentOnUser(request) {
        return this.start()
            .withUri('/api/user/comment')
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Creates an application. You can optionally specify an Id for the application, if not provided one will be generated.
     *
     * @param {string} applicationId (Optional) The Id to use for the application. If not provided a secure random UUID will be generated.
     * @param {Object} request The request object that contains all of the information used to create the application.
     */
    createApplication(applicationId, request) {
        return this.start()
            .withUri('/api/application')
            .withUriSegment(applicationId)
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Creates a new role for an application. You must specify the id of the application you are creating the role for.
     * You can optionally specify an Id for the role inside the ApplicationRole object itself, if not provided one will be generated.
     *
     * @param {string} applicationId The Id of the application to create the role on.
     * @param {string} roleId (Optional) The Id of the role. If not provided a secure random UUID will be generated.
     * @param {Object} request The request object that contains all of the information used to create the application role.
     */
    createApplicationRole(applicationId, roleId, request) {
        return this.start()
            .withUri('/api/application')
            .withUriSegment(applicationId)
            .withUriSegment("role")
            .withUriSegment(roleId)
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Creates an audit log with the message and user name (usually an email). Audit logs should be written anytime you
     * make changes to the FusionAuth database. When using the FusionAuth App web interface, any changes are automatically
     * written to the audit log. However, if you are accessing the API, you must write the audit logs yourself.
     *
     * @param {Object} request The request object that contains all of the information used to create the audit log entry.
     */
    createAuditLog(request) {
        return this.start()
            .withUri('/api/system/audit-log')
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Creates an email template. You can optionally specify an Id for the template, if not provided one will be generated.
     *
     * @param {string} emailTemplateId (Optional) The Id for the template. If not provided a secure random UUID will be generated.
     * @param {Object} request The request object that contains all of the information used to create the email template.
     */
    createEmailTemplate(emailTemplateId, request) {
        return this.start()
            .withUri('/api/email/template')
            .withUriSegment(emailTemplateId)
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Creates a group. You can optionally specify an Id for the group, if not provided one will be generated.
     *
     * @param {string} groupId (Optional) The Id for the group. If not provided a secure random UUID will be generated.
     * @param {Object} request The request object that contains all of the information used to create the group.
     */
    createGroup(groupId, request) {
        return this.start()
            .withUri('/api/group')
            .withUriSegment(groupId)
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Creates a member in a group.
     *
     * @param {Object} request The request object that contains all of the information used to create the group member(s).
     */
    createGroupMembers(request) {
        return this.start()
            .withUri('/api/group/member')
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Creates an identity provider. You can optionally specify an Id for the identity provider, if not provided one will be generated.
     *
     * @param {string} identityProviderId (Optional) The Id of the identity provider. If not provided a secure random UUID will be generated.
     * @param {Object} request The request object that contains all of the information used to create the identity provider.
     */
    createIdentityProvider(identityProviderId, request) {
        return this.start()
            .withUri('/api/identity-provider')
            .withUriSegment(identityProviderId)
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Creates a Lambda. You can optionally specify an Id for the lambda, if not provided one will be generated.
     *
     * @param {string} lambdaId (Optional) The Id for the lambda. If not provided a secure random UUID will be generated.
     * @param {Object} request The request object that contains all of the information used to create the lambda.
     */
    createLambda(lambdaId, request) {
        return this.start()
            .withUri('/api/lambda')
            .withUriSegment(lambdaId)
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Creates a tenant. You can optionally specify an Id for the tenant, if not provided one will be generated.
     *
     * @param {string} tenantId (Optional) The Id for the tenant. If not provided a secure random UUID will be generated.
     * @param {Object} request The request object that contains all of the information used to create the tenant.
     */
    createTenant(tenantId, request) {
        return this.start()
            .withUri('/api/tenant')
            .withUriSegment(tenantId)
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Creates a user. You can optionally specify an Id for the user, if not provided one will be generated.
     *
     * @param {string} userId (Optional) The Id for the user. If not provided a secure random UUID will be generated.
     * @param {Object} request The request object that contains all of the information used to create the user.
     */
    createUser(userId, request) {
        return this.start()
            .withUri('/api/user')
            .withUriSegment(userId)
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Creates a user action. This action cannot be taken on a user until this call successfully returns. Anytime after
     * that the user action can be applied to any user.
     *
     * @param {string} userActionId (Optional) The Id for the user action. If not provided a secure random UUID will be generated.
     * @param {Object} request The request object that contains all of the information used to create the user action.
     */
    createUserAction(userActionId, request) {
        return this.start()
            .withUri('/api/user-action')
            .withUriSegment(userActionId)
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Creates a user reason. This user action reason cannot be used when actioning a user until this call completes
     * successfully. Anytime after that the user action reason can be used.
     *
     * @param {string} userActionReasonId (Optional) The Id for the user action reason. If not provided a secure random UUID will be generated.
     * @param {Object} request The request object that contains all of the information used to create the user action reason.
     */
    createUserActionReason(userActionReasonId, request) {
        return this.start()
            .withUri('/api/user-action-reason')
            .withUriSegment(userActionReasonId)
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Creates a webhook. You can optionally specify an Id for the webhook, if not provided one will be generated.
     *
     * @param {string} webhookId (Optional) The Id for the webhook. If not provided a secure random UUID will be generated.
     * @param {Object} request The request object that contains all of the information used to create the webhook.
     */
    createWebhook(webhookId, request) {
        return this.start()
            .withUri('/api/webhook')
            .withUriSegment(webhookId)
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Deactivates the application with the given Id.
     *
     * @param {string} applicationId The Id of the application to deactivate.
     */
    deactivateApplication(applicationId) {
        return this.start()
            .withUri('/api/application')
            .withUriSegment(applicationId)
            .withMethod("DELETE")
            .go();
    }
    /**
     * Deactivates the user with the given Id.
     *
     * @param {string} userId The Id of the user to deactivate.
     */
    deactivateUser(userId) {
        return this.start()
            .withUri('/api/user')
            .withUriSegment(userId)
            .withMethod("DELETE")
            .go();
    }
    /**
     * Deactivates the user action with the given Id.
     *
     * @param {string} userActionId The Id of the user action to deactivate.
     */
    deactivateUserAction(userActionId) {
        return this.start()
            .withUri('/api/user-action')
            .withUriSegment(userActionId)
            .withMethod("DELETE")
            .go();
    }
    /**
     * Deactivates the users with the given ids.
     *
     * @param {Array<string>} userIds The ids of the users to deactivate.
     */
    deactivateUsers(userIds) {
        return this.start()
            .withUri('/api/user/bulk')
            .withParameter('userId', userIds)
            .withMethod("DELETE")
            .go();
    }
    /**
     * Hard deletes an application. This is a dangerous operation and should not be used in most circumstances. This will
     * delete the application, any registrations for that application, metrics and reports for the application, all the
     * roles for the application, and any other data associated with the application. This operation could take a very
     * long time, depending on the amount of data in your database.
     *
     * @param {string} applicationId The Id of the application to delete.
     */
    deleteApplication(applicationId) {
        return this.start()
            .withUri('/api/application')
            .withUriSegment(applicationId)
            .withParameter('hardDelete', true)
            .withMethod("DELETE")
            .go();
    }
    /**
     * Hard deletes an application role. This is a dangerous operation and should not be used in most circumstances. This
     * permanently removes the given role from all users that had it.
     *
     * @param {string} applicationId The Id of the application to deactivate.
     * @param {string} roleId The Id of the role to delete.
     */
    deleteApplicationRole(applicationId, roleId) {
        return this.start()
            .withUri('/api/application')
            .withUriSegment(applicationId)
            .withUriSegment("role")
            .withUriSegment(roleId)
            .withMethod("DELETE")
            .go();
    }
    /**
     * Deletes the email template for the given Id.
     *
     * @param {string} emailTemplateId The Id of the email template to delete.
     */
    deleteEmailTemplate(emailTemplateId) {
        return this.start()
            .withUri('/api/email/template')
            .withUriSegment(emailTemplateId)
            .withMethod("DELETE")
            .go();
    }
    /**
     * Deletes the group for the given Id.
     *
     * @param {string} groupId The Id of the group to delete.
     */
    deleteGroup(groupId) {
        return this.start()
            .withUri('/api/group')
            .withUriSegment(groupId)
            .withMethod("DELETE")
            .go();
    }
    /**
     * Removes users as members of a group.
     *
     * @param {Object} request The member request that contains all of the information used to remove members to the group.
     */
    deleteGroupMembers(request) {
        return this.start()
            .withUri('/api/group/member')
            .withJSONBody(request)
            .withMethod("DELETE")
            .go();
    }
    /**
     * Deletes the identity provider for the given Id.
     *
     * @param {string} identityProviderId The Id of the identity provider to delete.
     */
    deleteIdentityProvider(identityProviderId) {
        return this.start()
            .withUri('/api/identity-provider')
            .withUriSegment(identityProviderId)
            .withMethod("DELETE")
            .go();
    }
    /**
     * Deletes the lambda for the given Id.
     *
     * @param {string} lambdaId The Id of the lambda to delete.
     */
    deleteLambda(lambdaId) {
        return this.start()
            .withUri('/api/lambda')
            .withUriSegment(lambdaId)
            .withMethod("DELETE")
            .go();
    }
    /**
     * Deletes the user registration for the given user and application.
     *
     * @param {string} userId The Id of the user whose registration is being deleted.
     * @param {string} applicationId The Id of the application to remove the registration for.
     */
    deleteRegistration(userId, applicationId) {
        return this.start()
            .withUri('/api/user/registration')
            .withUriSegment(userId)
            .withUriSegment(applicationId)
            .withMethod("DELETE")
            .go();
    }
    /**
     * Deletes the tenant for the given Id.
     *
     * @param {string} tenantId The Id of the tenant to delete.
     */
    deleteTenant(tenantId) {
        return this.start()
            .withUri('/api/tenant')
            .withUriSegment(tenantId)
            .withMethod("DELETE")
            .go();
    }
    /**
     * Deletes the user for the given Id. This permanently deletes all information, metrics, reports and data associated
     * with the user.
     *
     * @param {string} userId The Id of the user to delete.
     */
    deleteUser(userId) {
        return this.start()
            .withUri('/api/user')
            .withUriSegment(userId)
            .withParameter('hardDelete', true)
            .withMethod("DELETE")
            .go();
    }
    /**
     * Deletes the user action for the given Id. This permanently deletes the user action and also any history and logs of
     * the action being applied to any users.
     *
     * @param {string} userActionId The Id of the user action to delete.
     */
    deleteUserAction(userActionId) {
        return this.start()
            .withUri('/api/user-action')
            .withUriSegment(userActionId)
            .withParameter('hardDelete', true)
            .withMethod("DELETE")
            .go();
    }
    /**
     * Deletes the user action reason for the given Id.
     *
     * @param {string} userActionReasonId The Id of the user action reason to delete.
     */
    deleteUserActionReason(userActionReasonId) {
        return this.start()
            .withUri('/api/user-action-reason')
            .withUriSegment(userActionReasonId)
            .withMethod("DELETE")
            .go();
    }
    /**
     * Deletes the users with the given ids.
     *
     * @param {Object} request The ids of the users to delete.
     */
    deleteUsers(request) {
        return this.start()
            .withUri('/api/user/bulk')
            .withJSONBody(request)
            .withMethod("DELETE")
            .go();
    }
    /**
     * Deletes the webhook for the given Id.
     *
     * @param {string} webhookId The Id of the webhook to delete.
     */
    deleteWebhook(webhookId) {
        return this.start()
            .withUri('/api/webhook')
            .withUriSegment(webhookId)
            .withMethod("DELETE")
            .go();
    }
    /**
     * Disable Two Factor authentication for a user.
     *
     * @param {string} userId The Id of the User for which you're disabling Two Factor authentication.
     * @param {string} code The Two Factor code used verify the the caller knows the Two Factor secret.
     */
    disableTwoFactor(userId, code) {
        return this.start()
            .withUri('/api/user/two-factor')
            .withParameter('userId', userId)
            .withParameter('code', code)
            .withMethod("DELETE")
            .go();
    }
    /**
     * Enable Two Factor authentication for a user.
     *
     * @param {string} userId The Id of the user to enable Two Factor authentication.
     * @param {Object} request The two factor enable request information.
     */
    enableTwoFactor(userId, request) {
        return this.start()
            .withUri('/api/user/two-factor')
            .withUriSegment(userId)
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Exchange a refresh token for a new JWT.
     *
     * @param {Object} request The refresh request.
     */
    exchangeRefreshTokenForJWT(request) {
        return this.start()
            .withUri('/api/jwt/refresh')
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Begins the forgot password sequence, which kicks off an email to the user so that they can reset their password.
     *
     * @param {Object} request The request that contains the information about the user so that they can be emailed.
     */
    forgotPassword(request) {
        return this.start()
            .withUri('/api/user/forgot-password')
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Generate a new Email Verification Id to be used with the Verify Email API. This API will not attempt to send an
     * email to the User. This API may be used to collect the verificationId for use with a third party system.
     *
     * @param {string} email The email address of the user that needs a new verification email.
     */
    generateEmailVerificationId(email) {
        return this.start()
            .withUri('/api/user/verify-email')
            .withParameter('email', email)
            .withParameter('sendVerifyPasswordEmail', false)
            .withMethod("PUT")
            .go();
    }
    /**
     * Generate a new Application Registration Verification Id to be used with the Verify Registration API. This API will not attempt to send an
     * email to the User. This API may be used to collect the verificationId for use with a third party system.
     *
     * @param {string} email The email address of the user that needs a new verification email.
     * @param {string} applicationId The Id of the application to be verified.
     */
    generateRegistrationVerificationId(email, applicationId) {
        return this.start()
            .withUri('/api/user/verify-registration')
            .withParameter('email', email)
            .withParameter('sendVerifyPasswordEmail', false)
            .withParameter('applicationId', applicationId)
            .withMethod("PUT")
            .go();
    }
    /**
     * Generate a Two Factor secret that can be used to enable Two Factor authentication for a User. The response will contain
     * both the secret and a Base32 encoded form of the secret which can be shown to a User when using a 2 Step Authentication
     * application such as Google Authenticator.
     *
     */
    generateTwoFactorSecret() {
        return this.start()
            .withUri('/api/two-factor/secret')
            .withMethod("GET")
            .go();
    }
    /**
     * Generate a Two Factor secret that can be used to enable Two Factor authentication for a User. The response will contain
     * both the secret and a Base32 encoded form of the secret which can be shown to a User when using a 2 Step Authentication
     * application such as Google Authenticator.
     *
     * @param {string} encodedJWT The encoded JWT (access token).
     */
    generateTwoFactorSecretUsingJWT(encodedJWT) {
        return this.start()
            .withUri('/api/two-factor/secret')
            .withAuthorization('JWT ' + encodedJWT)
            .withMethod("GET")
            .go();
    }
    /**
     * Handles login via third-parties including Social login, external OAuth and OpenID Connect, and other
     * login systems.
     *
     * @param {Object} request The third-party login request that contains information from the third-party login
     *    providers that FusionAuth uses to reconcile the user's account.
     */
    identityProviderLogin(request) {
        return this.start()
            .withUri('/api/identity-provider/login')
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Bulk imports multiple users. This does some validation, but then tries to run batch inserts of users. This reduces
     * latency when inserting lots of users. Therefore, the error response might contain some information about failures,
     * but it will likely be pretty generic.
     *
     * @param {Object} request The request that contains all of the information about all of the users to import.
     */
    importUsers(request) {
        return this.start()
            .withUri('/api/user/import')
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Issue a new access token (JWT) for the requested Application after ensuring the provided JWT is valid. A valid
     * access token is properly signed and not expired.
     * <p>
     * This API may be used in an SSO configuration to issue new tokens for another application after the user has
     * obtained a valid token from authentication.
     *
     * @param {string} applicationId The Application Id for which you are requesting a new access token be issued.
     * @param {string} encodedJWT The encoded JWT (access token).
     */
    issueJWT(applicationId, encodedJWT) {
        return this.start()
            .withUri('/api/jwt/issue')
            .withAuthorization('JWT ' + encodedJWT)
            .withParameter('applicationId', applicationId)
            .withMethod("GET")
            .go();
    }
    /**
     * Logs a user in.
     *
     * @param {Object} request The login request that contains the user credentials used to log them in.
     */
    login(request) {
        return this.start()
            .withUri('/api/login')
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Sends a ping to FusionAuth indicating that the user was automatically logged into an application. When using
     * FusionAuth's SSO or your own, you should call this if the user is already logged in centrally, but accesses an
     * application where they no longer have a session. This helps correctly track login counts, times and helps with
     * reporting.
     *
     * @param {string} userId The Id of the user that was logged in.
     * @param {string} applicationId The Id of the application that they logged into.
     * @param {string} callerIPAddress (Optional) The IP address of the end-user that is logging in. If a null value is provided
     *    the IP address will be that of the client or last proxy that sent the request.
     */
    loginPing(userId, applicationId, callerIPAddress) {
        return this.start()
            .withUri('/api/login')
            .withUriSegment(userId)
            .withUriSegment(applicationId)
            .withParameter('ipAddress', callerIPAddress)
            .withMethod("PUT")
            .go();
    }
    /**
     * The Logout API is intended to be used to remove the refresh token and access token cookies if they exist on the
     * client and revoke the refresh token stored. This API does nothing if the request does not contain an access
     * token or refresh token cookies.
     *
     * @param {Object} global When this value is set to true all of the refresh tokens issued to the owner of the
     *    provided token will be revoked.
     * @param {string} refreshToken (Optional) The refresh_token as a request parameter instead of coming in via a cookie.
     *    If provided this takes precedence over the cookie.
     */
    logout(global, refreshToken) {
        return this.start()
            .withHeader('Content-Type', 'text/plain')
            .withUri('/api/logout')
            .withParameter('global', global)
            .withParameter('refreshToken', refreshToken)
            .withMethod("POST")
            .go();
    }
    /**
     * Retrieves the identity provider for the given domain. A 200 response code indicates the domain is managed
     * by a registered identity provider. A 404 indicates the domain is not managed.
     *
     * @param {string} domain The domain or email address to lookup.
     */
    lookupIdentityProvider(domain) {
        return this.start()
            .withUri('/api/identity-provider/lookup')
            .withParameter('domain', domain)
            .withMethod("GET")
            .go();
    }
    /**
     * Modifies a temporal user action by changing the expiration of the action and optionally adding a comment to the
     * action.
     *
     * @param {string} actionId The Id of the action to modify. This is technically the user action log id.
     * @param {Object} request The request that contains all of the information about the modification.
     */
    modifyAction(actionId, request) {
        return this.start()
            .withUri('/api/user/action')
            .withUriSegment(actionId)
            .withJSONBody(request)
            .withMethod("PUT")
            .go();
    }
    /**
     * Complete a login request using a passwordless code
     *
     * @param {Object} request The passwordless login request that contains all of the information used to complete login.
     */
    passwordlessLogin(request) {
        return this.start()
            .withUri('/api/passwordless/login')
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Reactivates the application with the given Id.
     *
     * @param {string} applicationId The Id of the application to reactivate.
     */
    reactivateApplication(applicationId) {
        return this.start()
            .withUri('/api/application')
            .withUriSegment(applicationId)
            .withParameter('reactivate', true)
            .withMethod("PUT")
            .go();
    }
    /**
     * Reactivates the user with the given Id.
     *
     * @param {string} userId The Id of the user to reactivate.
     */
    reactivateUser(userId) {
        return this.start()
            .withUri('/api/user')
            .withUriSegment(userId)
            .withParameter('reactivate', true)
            .withMethod("PUT")
            .go();
    }
    /**
     * Reactivates the user action with the given Id.
     *
     * @param {string} userActionId The Id of the user action to reactivate.
     */
    reactivateUserAction(userActionId) {
        return this.start()
            .withUri('/api/user-action')
            .withUriSegment(userActionId)
            .withParameter('reactivate', true)
            .withMethod("PUT")
            .go();
    }
    /**
     * Reconcile a User to FusionAuth using JWT issued from another Identity Provider.
     *
     * @param {Object} request The reconcile request that contains the data to reconcile the User.
     */
    reconcileJWT(request) {
        return this.start()
            .withUri('/api/jwt/reconcile')
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Registers a user for an application. If you provide the User and the UserRegistration object on this request, it
     * will create the user as well as register them for the application. This is called a Full Registration. However, if
     * you only provide the UserRegistration object, then the user must already exist and they will be registered for the
     * application. The user id can also be provided and it will either be used to look up an existing user or it will be
     * used for the newly created User.
     *
     * @param {string} userId (Optional) The Id of the user being registered for the application and optionally created.
     * @param {Object} request The request that optionally contains the User and must contain the UserRegistration.
     */
    register(userId, request) {
        return this.start()
            .withUri('/api/user/registration')
            .withUriSegment(userId)
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Re-sends the verification email to the user.
     *
     * @param {string} email The email address of the user that needs a new verification email.
     */
    resendEmailVerification(email) {
        return this.start()
            .withUri('/api/user/verify-email')
            .withParameter('email', email)
            .withMethod("PUT")
            .go();
    }
    /**
     * Re-sends the application registration verification email to the user.
     *
     * @param {string} email The email address of the user that needs a new verification email.
     * @param {string} applicationId The Id of the application to be verified.
     */
    resendRegistrationVerification(email, applicationId) {
        return this.start()
            .withUri('/api/user/verify-registration')
            .withParameter('email', email)
            .withParameter('applicationId', applicationId)
            .withMethod("PUT")
            .go();
    }
    /**
     * Retrieves a single action log (the log of a user action that was taken on a user previously) for the given Id.
     *
     * @param {string} actionId The Id of the action to retrieve.
     */
    retrieveAction(actionId) {
        return this.start()
            .withUri('/api/user/action')
            .withUriSegment(actionId)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves all of the actions for the user with the given Id. This will return all time based actions that are active,
     * and inactive as well as non-time based actions.
     *
     * @param {string} userId The Id of the user to fetch the actions for.
     */
    retrieveActions(userId) {
        return this.start()
            .withUri('/api/user/action')
            .withParameter('userId', userId)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves all of the actions for the user with the given Id that are currently preventing the User from logging in.
     *
     * @param {string} userId The Id of the user to fetch the actions for.
     */
    retrieveActionsPreventingLogin(userId) {
        return this.start()
            .withUri('/api/user/action')
            .withParameter('userId', userId)
            .withParameter('preventingLogin', true)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves all of the actions for the user with the given Id that are currently active.
     * An active action means one that is time based and has not been canceled, and has not ended.
     *
     * @param {string} userId The Id of the user to fetch the actions for.
     */
    retrieveActiveActions(userId) {
        return this.start()
            .withUri('/api/user/action')
            .withParameter('userId', userId)
            .withParameter('active', true)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the application for the given id or all of the applications if the id is null.
     *
     * @param {string} applicationId (Optional) The application id.
     */
    retrieveApplication(applicationId) {
        return this.start()
            .withUri('/api/application')
            .withUriSegment(applicationId)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves all of the applications.
     *
     */
    retrieveApplications() {
        return this.start()
            .withUri('/api/application')
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves a single audit log for the given Id.
     *
     * @param {number} auditLogId The Id of the audit log to retrieve.
     */
    retrieveAuditLog(auditLogId) {
        return this.start()
            .withUri('/api/system/audit-log')
            .withUriSegment(auditLogId)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the daily active user report between the two instants. If you specify an application id, it will only
     * return the daily active counts for that application.
     *
     * @param {string} applicationId (Optional) The application id.
     * @param {number} start The start instant as UTC milliseconds since Epoch.
     * @param {number} end The end instant as UTC milliseconds since Epoch.
     */
    retrieveDailyActiveReport(applicationId, start, end) {
        return this.start()
            .withUri('/api/report/daily-active-user')
            .withParameter('applicationId', applicationId)
            .withParameter('start', start)
            .withParameter('end', end)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the email template for the given Id. If you don't specify the id, this will return all of the email templates.
     *
     * @param {string} emailTemplateId (Optional) The Id of the email template.
     */
    retrieveEmailTemplate(emailTemplateId) {
        return this.start()
            .withUri('/api/email/template')
            .withUriSegment(emailTemplateId)
            .withMethod("GET")
            .go();
    }
    /**
     * Creates a preview of the email template provided in the request. This allows you to preview an email template that
     * hasn't been saved to the database yet. The entire email template does not need to be provided on the request. This
     * will create the preview based on whatever is given.
     *
     * @param {Object} request The request that contains the email template and optionally a locale to render it in.
     */
    retrieveEmailTemplatePreview(request) {
        return this.start()
            .withUri('/api/email/template/preview')
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Retrieves all of the email templates.
     *
     */
    retrieveEmailTemplates() {
        return this.start()
            .withUri('/api/email/template')
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the group for the given Id.
     *
     * @param {string} groupId The Id of the group.
     */
    retrieveGroup(groupId) {
        return this.start()
            .withUri('/api/group')
            .withUriSegment(groupId)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves all of the groups.
     *
     */
    retrieveGroups() {
        return this.start()
            .withUri('/api/group')
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the identity provider for the given id or all of the identity providers if the id is null.
     *
     * @param {string} identityProviderId (Optional) The identity provider id.
     */
    retrieveIdentityProvider(identityProviderId) {
        return this.start()
            .withUri('/api/identity-provider')
            .withUriSegment(identityProviderId)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves all of the identity providers.
     *
     */
    retrieveIdentityProviders() {
        return this.start()
            .withUri('/api/identity-provider')
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves all of the actions for the user with the given Id that are currently inactive.
     * An inactive action means one that is time based and has been canceled or has expired, or is not time based.
     *
     * @param {string} userId The Id of the user to fetch the actions for.
     */
    retrieveInactiveActions(userId) {
        return this.start()
            .withUri('/api/user/action')
            .withParameter('userId', userId)
            .withParameter('active', false)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves all of the applications that are currently inactive.
     *
     */
    retrieveInactiveApplications() {
        return this.start()
            .withUri('/api/application')
            .withParameter('inactive', true)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves all of the user actions that are currently inactive.
     *
     */
    retrieveInactiveUserActions() {
        return this.start()
            .withUri('/api/user-action')
            .withParameter('inactive', true)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the available integrations.
     *
     */
    retrieveIntegration() {
        return this.start()
            .withUri('/api/integration')
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the Public Key configured for verifying JSON Web Tokens (JWT) by the key Id. If the key Id is provided a
     * single public key will be returned if one is found by that id. If the optional parameter key Id is not provided all
     * public keys will be returned.
     *
     * @param {string} keyId (Optional) The Id of the public key.
     */
    retrieveJWTPublicKey(keyId) {
        return this.start()
            .withUri('/api/jwt/public-key')
            .withUriSegment(keyId)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves all Public Keys configured for verifying JSON Web Tokens (JWT).
     *
     */
    retrieveJWTPublicKeys() {
        return this.start()
            .withUri('/api/jwt/public-key')
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the lambda for the given Id.
     *
     * @param {string} lambdaId The Id of the lambda.
     */
    retrieveLambda(lambdaId) {
        return this.start()
            .withUri('/api/lambda')
            .withUriSegment(lambdaId)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves all of the lambdas.
     *
     */
    retrieveLambdas() {
        return this.start()
            .withUri('/api/lambda')
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the login report between the two instants. If you specify an application id, it will only return the
     * login counts for that application.
     *
     * @param {string} applicationId (Optional) The application id.
     * @param {number} start The start instant as UTC milliseconds since Epoch.
     * @param {number} end The end instant as UTC milliseconds since Epoch.
     */
    retrieveLoginReport(applicationId, start, end) {
        return this.start()
            .withUri('/api/report/login')
            .withParameter('applicationId', applicationId)
            .withParameter('start', start)
            .withParameter('end', end)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the monthly active user report between the two instants. If you specify an application id, it will only
     * return the monthly active counts for that application.
     *
     * @param {string} applicationId (Optional) The application id.
     * @param {number} start The start instant as UTC milliseconds since Epoch.
     * @param {number} end The end instant as UTC milliseconds since Epoch.
     */
    retrieveMonthlyActiveReport(applicationId, start, end) {
        return this.start()
            .withUri('/api/report/monthly-active-user')
            .withParameter('applicationId', applicationId)
            .withParameter('start', start)
            .withParameter('end', end)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the Oauth2 configuration for the application for the given Application Id.
     *
     * @param {string} applicationId The Id of the Application to retrieve OAuth configuration.
     */
    retrieveOauthConfiguration(applicationId) {
        return this.start()
            .withUri('/api/application')
            .withUriSegment(applicationId)
            .withUriSegment("oauth-configuration")
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the password validation rules.
     *
     */
    retrievePasswordValidationRules() {
        return this.start()
            .withUri('/api/system-configuration/password-validation-rules')
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the last number of login records.
     *
     * @param {number} offset The initial record. e.g. 0 is the last login, 100 will be the 100th most recent login.
     * @param {number} limit (Optional, defaults to 10) The number of records to retrieve.
     */
    retrieveRecentLogins(offset, limit) {
        return this.start()
            .withUri('/api/user/recent-login')
            .withParameter('offset', offset)
            .withParameter('limit', limit)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the refresh tokens that belong to the user with the given Id.
     *
     * @param {string} userId The Id of the user.
     */
    retrieveRefreshTokens(userId) {
        return this.start()
            .withUri('/api/jwt/refresh')
            .withParameter('userId', userId)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the user registration for the user with the given id and the given application id.
     *
     * @param {string} userId The Id of the user.
     * @param {string} applicationId The Id of the application.
     */
    retrieveRegistration(userId, applicationId) {
        return this.start()
            .withUri('/api/user/registration')
            .withUriSegment(userId)
            .withUriSegment(applicationId)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the registration report between the two instants. If you specify an application id, it will only return
     * the registration counts for that application.
     *
     * @param {string} applicationId (Optional) The application id.
     * @param {number} start The start instant as UTC milliseconds since Epoch.
     * @param {number} end The end instant as UTC milliseconds since Epoch.
     */
    retrieveRegistrationReport(applicationId, start, end) {
        return this.start()
            .withUri('/api/report/registration')
            .withParameter('applicationId', applicationId)
            .withParameter('start', start)
            .withParameter('end', end)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the system configuration.
     *
     */
    retrieveSystemConfiguration() {
        return this.start()
            .withUri('/api/system-configuration')
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the tenant for the given Id.
     *
     * @param {string} tenantId The Id of the tenant.
     */
    retrieveTenant(tenantId) {
        return this.start()
            .withUri('/api/tenant')
            .withUriSegment(tenantId)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves all of the tenants.
     *
     */
    retrieveTenants() {
        return this.start()
            .withUri('/api/tenant')
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the totals report. This contains all of the total counts for each application and the global registration
     * count.
     *
     */
    retrieveTotalReport() {
        return this.start()
            .withUri('/api/report/totals')
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the user for the given Id.
     *
     * @param {string} userId The Id of the user.
     */
    retrieveUser(userId) {
        return this.start()
            .withUri('/api/user')
            .withUriSegment(userId)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the user action for the given Id. If you pass in null for the id, this will return all of the user
     * actions.
     *
     * @param {string} userActionId (Optional) The Id of the user action.
     */
    retrieveUserAction(userActionId) {
        return this.start()
            .withUri('/api/user-action')
            .withUriSegment(userActionId)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the user action reason for the given Id. If you pass in null for the id, this will return all of the user
     * action reasons.
     *
     * @param {string} userActionReasonId (Optional) The Id of the user action reason.
     */
    retrieveUserActionReason(userActionReasonId) {
        return this.start()
            .withUri('/api/user-action-reason')
            .withUriSegment(userActionReasonId)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves all the user action reasons.
     *
     */
    retrieveUserActionReasons() {
        return this.start()
            .withUri('/api/user-action-reason')
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves all of the user actions.
     *
     */
    retrieveUserActions() {
        return this.start()
            .withUri('/api/user-action')
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the user by a change password Id. The intended use of this API is to retrieve a user after the forgot
     * password workflow has been initiated and you may not know the user's email or username.
     *
     * @param {string} changePasswordId The unique change password Id that was sent via email or returned by the Forgot Password API.
     */
    retrieveUserByChangePasswordId(changePasswordId) {
        return this.start()
            .withUri('/api/user')
            .withParameter('changePasswordId', changePasswordId)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the user for the given email.
     *
     * @param {string} email The email of the user.
     */
    retrieveUserByEmail(email) {
        return this.start()
            .withUri('/api/user')
            .withParameter('email', email)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the user for the loginId. The loginId can be either the username or the email.
     *
     * @param {string} loginId The email or username of the user.
     */
    retrieveUserByLoginId(loginId) {
        return this.start()
            .withUri('/api/user')
            .withParameter('loginId', loginId)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the user for the given username.
     *
     * @param {string} username The username of the user.
     */
    retrieveUserByUsername(username) {
        return this.start()
            .withUri('/api/user')
            .withParameter('username', username)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the user by a verificationId. The intended use of this API is to retrieve a user after the forgot
     * password workflow has been initiated and you may not know the user's email or username.
     *
     * @param {string} verificationId The unique verification Id that has been set on the user object.
     */
    retrieveUserByVerificationId(verificationId) {
        return this.start()
            .withUri('/api/user')
            .withParameter('verificationId', verificationId)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves all of the comments for the user with the given Id.
     *
     * @param {string} userId The Id of the user.
     */
    retrieveUserComments(userId) {
        return this.start()
            .withUri('/api/user/comment')
            .withUriSegment(userId)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the login report between the two instants for a particular user by Id. If you specify an application id, it will only return the
     * login counts for that application.
     *
     * @param {string} applicationId (Optional) The application id.
     * @param {string} userId The userId id.
     * @param {number} start The start instant as UTC milliseconds since Epoch.
     * @param {number} end The end instant as UTC milliseconds since Epoch.
     */
    retrieveUserLoginReport(applicationId, userId, start, end) {
        return this.start()
            .withUri('/api/report/login')
            .withParameter('applicationId', applicationId)
            .withParameter('userId', userId)
            .withParameter('start', start)
            .withParameter('end', end)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the login report between the two instants for a particular user by login Id. If you specify an application id, it will only return the
     * login counts for that application.
     *
     * @param {string} applicationId (Optional) The application id.
     * @param {string} loginId The userId id.
     * @param {number} start The start instant as UTC milliseconds since Epoch.
     * @param {number} end The end instant as UTC milliseconds since Epoch.
     */
    retrieveUserLoginReportByLoginId(applicationId, loginId, start, end) {
        return this.start()
            .withUri('/api/report/login')
            .withParameter('applicationId', applicationId)
            .withParameter('loginId', loginId)
            .withParameter('start', start)
            .withParameter('end', end)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the last number of login records for a user.
     *
     * @param {string} userId The Id of the user.
     * @param {number} offset The initial record. e.g. 0 is the last login, 100 will be the 100th most recent login.
     * @param {number} limit (Optional, defaults to 10) The number of records to retrieve.
     */
    retrieveUserRecentLogins(userId, offset, limit) {
        return this.start()
            .withUri('/api/user/recent-login')
            .withParameter('userId', userId)
            .withParameter('offset', offset)
            .withParameter('limit', limit)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the user for the given Id. This method does not use an API key, instead it uses a JSON Web Token (JWT) for authentication.
     *
     * @param {string} encodedJWT The encoded JWT (access token).
     */
    retrieveUserUsingJWT(encodedJWT) {
        return this.start()
            .withUri('/api/user')
            .withAuthorization('JWT ' + encodedJWT)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the webhook for the given Id. If you pass in null for the id, this will return all the webhooks.
     *
     * @param {string} webhookId (Optional) The Id of the webhook.
     */
    retrieveWebhook(webhookId) {
        return this.start()
            .withUri('/api/webhook')
            .withUriSegment(webhookId)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves all the webhooks.
     *
     */
    retrieveWebhooks() {
        return this.start()
            .withUri('/api/webhook')
            .withMethod("GET")
            .go();
    }
    /**
     * Revokes a single refresh token, all tokens for a user or all tokens for an application. If you provide a user id
     * and an application id, this will delete all the refresh tokens for that user for that application.
     *
     * @param {string} token (Optional) The refresh token to delete.
     * @param {string} userId (Optional) The user id whose tokens to delete.
     * @param {string} applicationId (Optional) The application id of the tokens to delete.
     */
    revokeRefreshToken(token, userId, applicationId) {
        return this.start()
            .withUri('/api/jwt/refresh')
            .withParameter('token', token)
            .withParameter('userId', userId)
            .withParameter('applicationId', applicationId)
            .withMethod("DELETE")
            .go();
    }
    /**
     * Searches the audit logs with the specified criteria and pagination.
     *
     * @param {Object} request The search criteria and pagination information.
     */
    searchAuditLogs(request) {
        return this.start()
            .withUri('/api/system/audit-log/search')
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Searches the event logs with the specified criteria and pagination.
     *
     * @param {Object} request The search criteria and pagination information.
     */
    searchEventLogs(request) {
        return this.start()
            .withUri('/api/system/event-log/search')
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Retrieves the users for the given ids. If any id is invalid, it is ignored.
     *
     * @param {Array<string>} ids The user ids to search for.
     */
    searchUsers(ids) {
        return this.start()
            .withUri('/api/user/search')
            .withParameter('ids', ids)
            .withMethod("GET")
            .go();
    }
    /**
     * Retrieves the users for the given search criteria and pagination.
     *
     * @param {Object} request The search criteria and pagination constraints. Fields used: queryString, numberOfResults, startRow,
     *    and sort fields.
     */
    searchUsersByQueryString(request) {
        return this.start()
            .withUri('/api/user/search')
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Send an email using an email template id. You can optionally provide <code>requestData</code> to access key value
     * pairs in the email template.
     *
     * @param {string} emailTemplateId The id for the template.
     * @param {Object} request The send email request that contains all of the information used to send the email.
     */
    sendEmail(emailTemplateId, request) {
        return this.start()
            .withUri('/api/email/send')
            .withUriSegment(emailTemplateId)
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Send a passwordless authentication code in an email to complete login.
     *
     * @param {Object} request The passwordless send request that contains all of the information used to send an email containing a code.
     */
    sendPasswordlessCode(request) {
        return this.start()
            .withUri('/api/passwordless/send')
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Send a Two Factor authentication code to assist in setting up Two Factor authentication or disabling.
     *
     * @param {Object} request The request object that contains all of the information used to send the code.
     */
    sendTwoFactorCode(request) {
        return this.start()
            .withUri('/api/two-factor/send')
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Send a Two Factor authentication code to allow the completion of Two Factor authentication.
     *
     * @param {string} twoFactorId The Id returned by the Login API necessary to complete Two Factor authentication.
     */
    sendTwoFactorCodeForLogin(twoFactorId) {
        return this.start()
            .withHeader('Content-Type', 'text/plain')
            .withUri('/api/two-factor/send')
            .withUriSegment(twoFactorId)
            .withMethod("POST")
            .go();
    }
    /**
     * Complete login using a 2FA challenge
     *
     * @param {Object} request The login request that contains the user credentials used to log them in.
     */
    twoFactorLogin(request) {
        return this.start()
            .withUri('/api/two-factor/login')
            .withJSONBody(request)
            .withMethod("POST")
            .go();
    }
    /**
     * Updates the application with the given Id.
     *
     * @param {string} applicationId The Id of the application to update.
     * @param {Object} request The request that contains all of the new application information.
     */
    updateApplication(applicationId, request) {
        return this.start()
            .withUri('/api/application')
            .withUriSegment(applicationId)
            .withJSONBody(request)
            .withMethod("PUT")
            .go();
    }
    /**
     * Updates the application role with the given id for the application.
     *
     * @param {string} applicationId The Id of the application that the role belongs to.
     * @param {string} roleId The Id of the role to update.
     * @param {Object} request The request that contains all of the new role information.
     */
    updateApplicationRole(applicationId, roleId, request) {
        return this.start()
            .withUri('/api/application')
            .withUriSegment(applicationId)
            .withUriSegment("role")
            .withUriSegment(roleId)
            .withJSONBody(request)
            .withMethod("PUT")
            .go();
    }
    /**
     * Updates the email template with the given Id.
     *
     * @param {string} emailTemplateId The Id of the email template to update.
     * @param {Object} request The request that contains all of the new email template information.
     */
    updateEmailTemplate(emailTemplateId, request) {
        return this.start()
            .withUri('/api/email/template')
            .withUriSegment(emailTemplateId)
            .withJSONBody(request)
            .withMethod("PUT")
            .go();
    }
    /**
     * Updates the group with the given Id.
     *
     * @param {string} groupId The Id of the group to update.
     * @param {Object} request The request that contains all of the new group information.
     */
    updateGroup(groupId, request) {
        return this.start()
            .withUri('/api/group')
            .withUriSegment(groupId)
            .withJSONBody(request)
            .withMethod("PUT")
            .go();
    }
    /**
     * Updates the identity provider with the given Id.
     *
     * @param {string} identityProviderId The Id of the identity provider to update.
     * @param {Object} request The request object that contains the updated identity provider.
     */
    updateIdentityProvider(identityProviderId, request) {
        return this.start()
            .withUri('/api/identity-provider')
            .withUriSegment(identityProviderId)
            .withJSONBody(request)
            .withMethod("PUT")
            .go();
    }
    /**
     * Updates the available integrations.
     *
     * @param {Object} request The request that contains all of the new integration information.
     */
    updateIntegrations(request) {
        return this.start()
            .withUri('/api/integration')
            .withJSONBody(request)
            .withMethod("PUT")
            .go();
    }
    /**
     * Updates the lambda with the given Id.
     *
     * @param {string} lambdaId The Id of the lambda to update.
     * @param {Object} request The request that contains all of the new lambda information.
     */
    updateLambda(lambdaId, request) {
        return this.start()
            .withUri('/api/lambda')
            .withUriSegment(lambdaId)
            .withJSONBody(request)
            .withMethod("PUT")
            .go();
    }
    /**
     * Updates the registration for the user with the given id and the application defined in the request.
     *
     * @param {string} userId The Id of the user whose registration is going to be updated.
     * @param {Object} request The request that contains all of the new registration information.
     */
    updateRegistration(userId, request) {
        return this.start()
            .withUri('/api/user/registration')
            .withUriSegment(userId)
            .withJSONBody(request)
            .withMethod("PUT")
            .go();
    }
    /**
     * Updates the system configuration.
     *
     * @param {Object} request The request that contains all of the new system configuration information.
     */
    updateSystemConfiguration(request) {
        return this.start()
            .withUri('/api/system-configuration')
            .withJSONBody(request)
            .withMethod("PUT")
            .go();
    }
    /**
     * Updates the tenant with the given Id.
     *
     * @param {string} tenantId The Id of the tenant to update.
     * @param {Object} request The request that contains all of the new tenant information.
     */
    updateTenant(tenantId, request) {
        return this.start()
            .withUri('/api/tenant')
            .withUriSegment(tenantId)
            .withJSONBody(request)
            .withMethod("PUT")
            .go();
    }
    /**
     * Updates the user with the given Id.
     *
     * @param {string} userId The Id of the user to update.
     * @param {Object} request The request that contains all of the new user information.
     */
    updateUser(userId, request) {
        return this.start()
            .withUri('/api/user')
            .withUriSegment(userId)
            .withJSONBody(request)
            .withMethod("PUT")
            .go();
    }
    /**
     * Updates the user action with the given Id.
     *
     * @param {string} userActionId The Id of the user action to update.
     * @param {Object} request The request that contains all of the new user action information.
     */
    updateUserAction(userActionId, request) {
        return this.start()
            .withUri('/api/user-action')
            .withUriSegment(userActionId)
            .withJSONBody(request)
            .withMethod("PUT")
            .go();
    }
    /**
     * Updates the user action reason with the given Id.
     *
     * @param {string} userActionReasonId The Id of the user action reason to update.
     * @param {Object} request The request that contains all of the new user action reason information.
     */
    updateUserActionReason(userActionReasonId, request) {
        return this.start()
            .withUri('/api/user-action-reason')
            .withUriSegment(userActionReasonId)
            .withJSONBody(request)
            .withMethod("PUT")
            .go();
    }
    /**
     * Updates the webhook with the given Id.
     *
     * @param {string} webhookId The Id of the webhook to update.
     * @param {Object} request The request that contains all of the new webhook information.
     */
    updateWebhook(webhookId, request) {
        return this.start()
            .withUri('/api/webhook')
            .withUriSegment(webhookId)
            .withJSONBody(request)
            .withMethod("PUT")
            .go();
    }
    /**
     * Validates the provided JWT (encoded JWT string) to ensure the token is valid. A valid access token is properly
     * signed and not expired.
     * <p>
     * This API may be used to verify the JWT as well as decode the encoded JWT into human readable identity claims.
     *
     * @param {string} encodedJWT The encoded JWT (access token).
     */
    validateJWT(encodedJWT) {
        return this.start()
            .withUri('/api/jwt/validate')
            .withAuthorization('JWT ' + encodedJWT)
            .withMethod("GET")
            .go();
    }
    /**
     * Confirms a email verification. The Id given is usually from an email sent to the user.
     *
     * @param {string} verificationId The email verification id sent to the user.
     */
    verifyEmail(verificationId) {
        return this.start()
            .withHeader('Content-Type', 'text/plain')
            .withUri('/api/user/verify-email')
            .withUriSegment(verificationId)
            .withMethod("POST")
            .go();
    }
    /**
     * Confirms an application registration. The Id given is usually from an email sent to the user.
     *
     * @param {string} verificationId The registration verification Id sent to the user.
     */
    verifyRegistration(verificationId) {
        return this.start()
            .withHeader('Content-Type', 'text/plain')
            .withUri('/api/user/verify-registration')
            .withUriSegment(verificationId)
            .withMethod("POST")
            .go();
    }
    /* ===================================================================================================================
     * Private methods
     * ===================================================================================================================*/
    /**
     * creates a rest client
     *
     * @returns {IRestClient} The RESTClient that will be used to call.
     * @private
     */
    start() {
        return this.clientBuilder.build(this.host).withAuthorization(this.apiKey);
    }
}
exports.FusionAuthClient = FusionAuthClient;

},{"./DefaultRESTClientBuilder":11}],13:[function(require,module,exports){
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
Object.defineProperty(exports, "__esModule", { value: true });
class ClientResponse {
    wasSuccessful() {
        return this.statusCode >= 200 && this.statusCode < 300;
    }
}
exports.ClientResponse = ClientResponse;

},{}]},{},[1]);
