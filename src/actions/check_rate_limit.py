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

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Params

from ..asset import Asset
from ..dnsdb_client import get_client, map_known_dnsdb_error


class CheckRateLimitOutput(ActionOutput):
    reset: int = OutputField(example_values=[1618617600])
    remaining: int = OutputField(example_values=[992])
    limit: int = OutputField(example_values=[1000])
    offset_max: int = OutputField(example_values=[3000000])
    results_max: int = OutputField(example_values=[1000000])


def display_rate_limit(outputs: list[CheckRateLimitOutput]) -> dict:
    return {"results": [{"data": [o.model_dump() for o in outputs]}]}


def check_rate_limit(
    params: Params, soar: SOARClient, asset: Asset
) -> CheckRateLimitOutput:
    try:
        rate = get_client(asset).rate_limit()["rate"]
    except Exception as error:
        known = map_known_dnsdb_error(error)
        if known is not None:
            raise known from error
        raise ActionFailure(str(error)) from error

    soar.set_message("Rate limit details fetched successfully")
    return CheckRateLimitOutput(**rate)
