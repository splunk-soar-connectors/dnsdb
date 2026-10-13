# Copyright (c) 2016-2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

import json

import httpx
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import MakeRequestParams, Param

from ..asset import Asset
from ..dnsdb_consts import DNSDB_API_KEY_HEADER, DNSDB_BASE_URL, DNSDB_DEFAULT_TIMEOUT


class DnsdbMakeRequestParams(MakeRequestParams):
    endpoint: str = Param(
        description=(
            f"DNSDB API endpoint to call, appended to the base URL ({DNSDB_BASE_URL}). "
            "Do not include the base URL. Example: '/lookup/rrset/name/example.com'"
        ),
        required=True,
    )
    verify_ssl: bool = Param(
        description="Whether to verify the SSL certificate. Default is True.",
        required=False,
        default=True,
    )


class DnsdbMakeRequestOutput(ActionOutput):
    status_code: int = OutputField(example_values=[200])
    response_body: str = OutputField(example_values=["{}"])

    @classmethod
    def from_response(cls, response: httpx.Response) -> "DnsdbMakeRequestOutput":
        return cls(status_code=response.status_code, response_body=response.text)


def http_action(params: DnsdbMakeRequestParams, asset: Asset) -> DnsdbMakeRequestOutput:
    """Make an authenticated request to the DNSDB API."""
    if params.endpoint.startswith(("http://", "https://")):
        raise ActionFailure(
            f"Invalid endpoint: {params.endpoint}. Do not include the base URL — "
            "it is derived from the asset configuration."
        )

    endpoint = "/" + params.endpoint.lstrip("/")
    url = f"{DNSDB_BASE_URL}{endpoint}"

    headers: dict = {DNSDB_API_KEY_HEADER: asset.api_key}
    if params.headers:
        try:
            user_headers = json.loads(params.headers)
        except (json.JSONDecodeError, TypeError) as e:
            raise ActionFailure("The 'headers' parameter must be valid JSON") from e
        if not isinstance(user_headers, dict):
            raise ActionFailure("The 'headers' parameter must be a JSON object")
        headers = {**user_headers, DNSDB_API_KEY_HEADER: asset.api_key}

    query_params = None
    if params.query_parameters:
        try:
            parsed = json.loads(params.query_parameters)
        except (json.JSONDecodeError, TypeError):
            query_string = params.query_parameters.split("#", 1)[0].lstrip("?")
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}{query_string}"
        else:
            if not isinstance(parsed, dict):
                raise ActionFailure(
                    "The 'query_parameters' parameter must be a JSON object "
                    "or a raw query string"
                )
            query_params = parsed

    body = None
    if params.body:
        try:
            body = json.loads(params.body)
        except (json.JSONDecodeError, TypeError) as e:
            raise ActionFailure("The 'body' parameter must be valid JSON") from e

    timeout = params.timeout or DNSDB_DEFAULT_TIMEOUT

    try:
        with httpx.Client(verify=params.verify_ssl) as client:
            response = client.request(
                params.http_method,
                url,
                headers=headers,
                params=query_params,
                json=body,
                timeout=timeout,
            )
    except httpx.HTTPError as error:
        raise ActionFailure(f"Request failed: {error}") from None

    return DnsdbMakeRequestOutput.from_response(response)
