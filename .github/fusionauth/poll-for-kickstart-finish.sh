#
# Copyright (c) 2026, FusionAuth, All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
#

cd $(dirname "$0")

isFusionAuthReady () {
  docker compose logs fusionauth 2>&1 | grep -Fq 'Completed [POST] request to [/api/user/registration/00000000-0000-0000-0000-000000000008]'
}

max_retries=20
i=1
while [ "$i" -le "$max_retries" ]; do
  echo -n "[$i/$max_retries] Waiting for FusionAuth server to start... "

  if isFusionAuthReady; then
    echo "READY"
    exit 0
  fi

  echo "NOT READY"
  sleep 5
  i=$((i + 1))
done

exit 1
