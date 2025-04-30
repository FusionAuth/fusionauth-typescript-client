/*
 * Copyright (c) 2019-2025, FusionAuth, All Rights Reserved
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

import {ApplicationRequest, FusionAuthClient, GrantType, SearchResponse} from '../index';
import * as chai from 'chai';
import ClientResponse from "../src/ClientResponse";

let client;
const fusionauthUrl = process.env.FUSIONAUTH_URL || "http://localhost:9011";
const fusionauthApiKey = process.env.FUSIONAUTH_API_KEY || "bf69486b-4733-4470-a592-f1bfce7af580";
const applicationId = "e5e2b0b3-c329-4b08-896c-d4f9f612b5c0";
const tenantId = '65323339-6137-6531-3135-316238623265';
const userId = 'b164fdfc-db57-4da9-b241-8543671c6bb8';

describe('#FusionAuthClient()', function () {

  beforeEach(async () => {
    client = new FusionAuthClient(fusionauthApiKey, fusionauthUrl);

    let response = await client.retrieveTenants();
    let desiredTenant = response.response.tenants.find((tenant) => {
      return tenant.id === tenantId
    });

    if (!desiredTenant) {
      let defaultTenant = response.response.tenants.find((tenant) => {
        return tenant.name === "Default"
      });
      defaultTenant.id = null;
      defaultTenant.name = "Typescript Tenant";
      response = await client.createTenant(tenantId, {tenant: defaultTenant});
      chai.assert.isTrue(response.wasSuccessful(), "Failed to create the tenant");
    }

    // All future requests will use this now
    client.setTenantId(tenantId);

    try {
      await client.deleteApplication(applicationId);
    } catch (ignore) {
    }

    try {
      const applicationRequest: ApplicationRequest = {
        application:
            {
              name: 'TypeScript FusionAuth Client',
              oauthConfiguration: {
                enabledGrants: [
                  GrantType.password,
                  GrantType.authorization_code
                ],
                authorizedRedirectURLs: ["http://localhost"]
              }
            }
      };
      response = await client.createApplication(applicationId, applicationRequest);
    } catch (error) {
      console.error("Failed to setup FusionAuth Client for testing.", error)
      throw new Error(error);
    }

    chai.assert.isUndefined(response.exception);
    chai.assert.strictEqual(response.statusCode, 200);
    chai.assert.isNotNull(response.response);


    // Cleanup the user (just in case a test partially failed)
    try {
      response = await client.retrieveUserByEmail("typescript@fusionauth.io")
      if (response.wasSuccessful()) {
        await client.deleteUser(response.response.user.id)
      }
    } catch (ignore) {
    }

    // Create the user that is expected to exist
    try {
      response = await client.retrieveUser(userId);
    } catch (failed) {
      try {
        await client.createUser(userId, {user: {email: "exampleUser@fusionauth.io", password: "password"}});
      } catch (e) {
        console.error("Failed to create the example user! Some tests may fail.", e);
      }
    }

    // Ensure that CORS allows patch
    try {
      response = await client.retrieveSystemConfiguration();

      if (!response.response.systemConfiguration.corsConfiguration.allowedMethods.some(method => method === 'PATCH')) {
        response.response.systemConfiguration.corsConfiguration.allowedMethods.push('PATCH');

        await client.updateSystemConfiguration({
          systemConfiguration: response.response.systemConfiguration
        });
      }
    } catch (e) {
      console.error("Failed to add patch to the CORS configuration. Your tests may fail!", e);
    }
  });

  it('Create, Patch, Search, and Delete a User', async () => {
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

    const userId = clientResponse.response.user.id;

    // Patch the user
    clientResponse = await client.patchUser(userId, {
      user: {
        firstName: "Jan"
      }
    });
    chai.assert.isUndefined(clientResponse.exception);
    chai.assert.strictEqual(clientResponse.statusCode, 200);
    chai.assert.isNotNull(clientResponse.response);
    chai.expect(clientResponse.response).to.have.property('user');
    chai.expect(clientResponse.response.user.firstName).to.equal("Jan");

    // create a second user and search them both
    clientResponse = await client.createUser(null, {
      user: {
        email: 'node2@fusionauth.io',
        firstName: 'Joan',
        password: 'password'
      },
      skipVerification: true,
      sendSetPasswordEmail: false
    });

    const secondUserId = clientResponse.response.user.id;
    const bothUsers = [userId, secondUserId];

    const searchResp: ClientResponse<SearchResponse> = await client.searchUsersByIds(bothUsers);
    chai.assert.strictEqual(searchResp.statusCode, 200);
    chai.assert.strictEqual(searchResp.response.total, 2);
    // make sure each user was returned
    bothUsers.forEach(id => chai.assert.isNotNull(searchResp.response.users.find(user => user.id = id)));

    // delete both users
    for (const id of bothUsers) {
      clientResponse = await client.deleteUser(id);
      chai.assert.strictEqual(clientResponse.statusCode, 200);
      // Browser will return empty, node will return null, account for both scenarios
      if (clientResponse.response === null) {
        chai.assert.isNull(clientResponse.response);
      } else {
        chai.assert.isUndefined(clientResponse.response);
      }
    }

    // check that they are gone
    for (const email of ['nodejs@fusionauth.io', 'node2@fusionauth.io']) {
      try {
        await client.retrieveUserByEmail(email);
        chai.expect.fail(`The user with ${email} should have been deleted!`);
      } catch (clientResponse) {
        chai.assert.strictEqual(clientResponse.statusCode, 404);
      }
    }
  });

  // Ensure that FusionAuth CORS is configured to support PATCH
  it('Patch Application', async () => {
    const applicationRequest: ApplicationRequest = {
      application: {
        name: 'Node.js FusionAuth Client patch',
        loginConfiguration: {allowTokenRefresh: true}
      }
    };

    let response = await client.patchApplication(applicationId, applicationRequest);
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

  it('Login non existant user', async () => {
    try {
      await client.login({
        loginId: "doesntexist",
        password: "pass"
      });
      chai.assert.fail('This should not be reached');
    } catch (e) {
      chai.assert.equal(e.statusCode, 404);
      // chai.assert.deepStrictEqual(e, {
      //   statusCode: 404
      // }, "Unexpected error");
    }
  });

  it('Retrieve user by loginId - default loginIdTypes', async () => {
    client.setTenantId("30663132-6464-6665-3032-326466613934");
    const dinesh = (await client.retrieveUserByLoginId("dinesh@fusionauth.io")).response.user;
    // it's spelled wrong in kickstart
    chai.assert.equal(dinesh.firstName, "Dinish");
  });

  it('Retrieve user by loginId - specified loginIdTypes', async () => {
    client.setTenantId("30663132-6464-6665-3032-326466613934");
    const dinesh = (await client.retrieveUserByLoginId("dinesh@fusionauth.io", ["email"])).response.user;
    // it's spelled wrong in kickstart
    chai.assert.equal(dinesh.firstName, "Dinish");

    try {
      await client.retrieveUserByLoginId("dinesh@fusionauth.io", ["username"]);
    } catch (e) {
      // there is no one with the username dinesh@fusionauth.io
      chai.assert.equal(e.statusCode, 404);
    }
  });

  it('OAuth login', async () => {
    try {
      let application = await client.retrieveApplication(applicationId);
      const clientId = application.response.application.oauthConfiguration.clientId;
      const clientSecret = application.response.application.oauthConfiguration.clientSecret;

      const accessTokenResponse = await client.exchangeUserCredentialsForAccessToken("exampleUser@fusionauth.io", "password", clientId, clientSecret, "email openid", null);

      // TODO Test the rest of the workflow somehow

      // const authCodeResponse = await client.exchangeOAuthCodeForAccessToken(accessTokenResponse.response.access_token, clientId, clientSecret, "http://localhost");

      // const userResponse = await client.retrieveUserUsingJWT(authCodeResponse.successResponse.access_token);

      // console.log("User:", userResponse.response.user);
    } catch (e) {
      console.error(e);
      chai.assert.fail("Failed to perform an OAuth login");
    }
  });
});
