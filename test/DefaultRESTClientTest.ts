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

'use strict';

import * as chai from 'chai';
import DefaultRESTClient from "../src/DefaultRESTClient"
import {URLSearchParams} from "url";


describe('#DefaultRESTClient()', function () {

  it('Can Create DefaultRESTClient', async () => {
    const client = new DefaultRESTClient('http://localhost:9011');
    chai.assert.isNotNull(client);
  });

  describe('withFormData', function () {
    it('null', async () => {
      const client = new DefaultRESTClient('http://localhost:9011');
      let body = client.withFormData(null).body;
      chai.assert.isNull(body);
    });

    it('empty', async () => {
      const client = new DefaultRESTClient('http://localhost:9011');
      let params = new URLSearchParams();
      let body = client.withFormData(params).body;
      chai.assert.isNotNull(body);
      chai.assert.strictEqual(body.toString(), "");
    });

    it('with one value', async () => {
      const client = new DefaultRESTClient('http://localhost:9011');
      let params = new URLSearchParams();
      params.set('key','value');
      let body = client.withFormData(params).body;
      chai.assert.isNotNull(body);
      chai.assert.strictEqual(body.toString(), "key=value");
    });

    it('with two values', async () => {
      const client = new DefaultRESTClient('http://localhost:9011');
      let params = new URLSearchParams();
      params.set('key','value');
      params.set('key2','value2');
      let body = client.withFormData(params).body;
      chai.assert.isNotNull(body);
      chai.assert.strictEqual(body.toString(), "key=value&key2=value2");
    });

    it('skips undefined value', async () => {
      const client = new DefaultRESTClient('http://localhost:9011');
      let params = new URLSearchParams();
      params.set('key','value');
      params.set('key2',undefined);
      let body = client.withFormData(params).body;
      chai.assert.isNotNull(body);
      chai.assert.strictEqual(body.toString(), "key=value");
    });

    it('skips null value', async () => {
      const client = new DefaultRESTClient('http://localhost:9011');
      let params = new URLSearchParams();
      params.set('key','value');
      params.set('key2',null);
      let body = client.withFormData(params).body;
      chai.assert.isNotNull(body);
      chai.assert.strictEqual(body.toString(), "key=value");
    });

    it('sets content type', async () => {
      const client = new DefaultRESTClient('http://localhost:9011');
      let params = new URLSearchParams();
      let headers = client.withFormData(params).headers
      chai.assert.isNotNull(headers);
      chai.assert.strictEqual(headers['Content-Type'], "application/x-www-form-urlencoded");
    });

  });

});
