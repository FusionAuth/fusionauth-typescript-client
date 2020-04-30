/*
 * Copyright (c) 2020, FusionAuth, All Rights Reserved
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

const client = new FusionAuth.FusionAuthClient('bf69486b-4733-4470-a592-f1bfce7af580', 'https://local.fusionauth.io');

client.retrieveUserByEmail('example@example.com')
      .then(clientResponse => {
        console.log("User:", JSON.stringify(clientResponse.response.user, null, 2));
      }).catch(console.error);
