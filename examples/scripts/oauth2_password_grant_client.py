#!/usr/bin/python
# Copyright 2026 Sven Victor
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# encoding: utf-8
import base64
import logging
import sys, requests, json, os

# change it
TOKEN_ENDPOINT = "https://sso.ez-auth.org/api/oauth2/token"
USERINFO_ENDPOINT = "https://sso.ez-auth.org/api/oauth2/userinfo"
CLIENT_ID = "APP-ZOCQLWLEIYA5M7RHBA3E"
CLIENT_SECRET = "603BX3VABE2F8CIO4H8GM6UPY15502F85OF5VXSX"

HEADERS = {"User-Agent": "OAuth2.0 Client;"}


def auth_from_oauth2_password(username: str, password: str):
    """
    Use OAuth2.0 password mode for authentication.
    :type auth_payload: dict[str,str]
    """
    payload = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "password",
        "username": username,
        "password": password,
    }
    headers = {**HEADERS, "Content-Type": "application/json"}

    response = requests.post(TOKEN_ENDPOINT, headers=headers, json=payload)

    r = response.json()  # type: dict
    if r.get("access_token", None):
        response = requests.get(
            USERINFO_ENDPOINT,
            headers={**HEADERS, "Authorization": f"Bearer {r['access_token']}"},
        )
        r = response.json()
        if r.get("preferred_username", None):
            return r
        else:
            logging.error(
                "auth failed: errorCode={}, errorMessage={}".format(
                    r.get("code", 500),
                    r.get("err", r.get("error", "Unknown error")),
                )
            )
            sys.exit(1)
    else:
        logging.error(
            "auth failed: errorCode={}, errorMessage={}".format(
                r.get("code", 500),
                r.get("err", r.get("error", "Unknown error")),
            )
        )
        sys.exit(1)


if __name__ == "__main__":
    input_username = input("Enter your username: ")
    input_password = input("Enter your password: ")
    auth_from_oauth2_password(input_username, input_password)
