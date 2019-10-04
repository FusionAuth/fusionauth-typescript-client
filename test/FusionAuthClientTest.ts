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

import {ApplicationRequest, FusionAuthClient} from '../index';
import * as chai from 'chai'
import './nodejs-tls-fix'
// import 'mocha'

let client;

describe('#FusionAuthClient()', function () {

  beforeEach(async () => {
    client = new FusionAuthClient('bf69486b-4733-4470-a592-f1bfce7af580', 'https://local.fusionauth.io');

    try {
      await client.deleteApplication('e5e2b0b3-c329-4b08-896c-d4f9f612b5c0');
    } catch (ignore) {
    }

    try {
      const applicationRequest: ApplicationRequest = {application: {name: 'Node.js FusionAuth Client'}};
      let response = await client.createApplication('e5e2b0b3-c329-4b08-896c-d4f9f612b5c0', applicationRequest);
      chai.assert.strictEqual(response.statusCode, 200);
      chai.assert.isNotNull(response.response);
    } catch (response) {
      console.error(JSON.stringify(response.response, null, 2));
      throw new Error("Failed to setup FusionAuth Client for testing");
    }
  });

  it('Create and Delete a User', async () => {
    let clientResponse = await client.createUser(null, {
      user: {
        email: 'nodejs@fusionauth.io',
        firstName: 'Jäne',
        password: 'password'
      },
      skipVerification: true,
      sendSetPasswordEmail: false
    });
    chai.assert.strictEqual(clientResponse.statusCode, 200);
    chai.assert.isNotNull(clientResponse.response);
    chai.expect(clientResponse.response).to.have.property('user');
    chai.expect(clientResponse.response.user).to.have.property('id');

    clientResponse = await client.deleteUser(clientResponse.response.user.id);
    chai.assert.strictEqual(clientResponse.statusCode, 200);
    // Browser will return empty, node will return null, account for both scenarios
    if (clientResponse.response === null) {
      chai.assert.isNull(clientResponse.response);
    } else {
      chai.assert.isUndefined(clientResponse.response);
    }

    try {
      await client.retrieveUserByEmail('nodejs@fusionauth.io');
      chai.expect.fail("The user should have been deleted!");
    } catch (clientResponse) {
      chai.assert.strictEqual(clientResponse.statusCode, 404);
    }
  });
});