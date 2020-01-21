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
import ClientResponse from "../src/ClientResponse";
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
      chai.assert.isUndefined(response.exception);
      chai.assert.strictEqual(response.statusCode, 200);
      chai.assert.isNotNull(response.response);
    } catch (error) {
      console.error("Failed to setup FusionAuth Client for testing.", error)
      throw error;
    }

    // Cleanup the user (just in case a test partially failed)
    try {
      let response = await client.retrieveUserByEmail("nodejs@fusionauth.io")
      if (response.wasSuccessful()) {
        await client.deleteUser(response.response.user.id)
      }
    } catch (ignore) {
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
    chai.assert.isUndefined(clientResponse.exception);
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

  it('Patch Application', async () => {
    const applicationRequest: ApplicationRequest = {application: {name: 'Node.js FusionAuth Client patch', loginConfiguration: { allowTokenRefresh: true }}};
    let response = await client.patchApplication('e5e2b0b3-c329-4b08-896c-d4f9f612b5c0', applicationRequest);
    chai.assert.isUndefined(response.exception);
    chai.assert.strictEqual(response.statusCode, 200);
    chai.expect(response.response.application.loginConfiguration.allowTokenRefresh).to.be.true;
  });

  /**
   * Tests a connection failure path for fetch exceptions
   */
  it('Failed response', async () => {
    client = new FusionAuthClient('doesntmatter', 'https://local.fusionauth.example.com'); // Doesn't exist

    return client.retrieveTenants()
        .then((_) => {
          chai.assert.fail("This should not have succeeded");
        })
        .catch((response) => {
          chai.assert.instanceOf(response, ClientResponse);
          chai.assert.isNotNull(response.exception);
          chai.assert.isUndefined(response.statusCode);
        });
  });

  /**
   *
   */
  it('Error response', async () => {
    return client.createApplication(null, {application: {name: 'Bad Application', verifyRegistration: true}})
        .then((_) => {
          chai.assert.fail("This should not have succeeded");
        })
        .catch((response) => {
          chai.assert.instanceOf(response, ClientResponse);
          chai.assert.isDefined(response.statusCode);
          chai.expect(response.statusCode).to.be.above(399).and.below(500);
        });
  });
});