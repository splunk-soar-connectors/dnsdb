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
from soar_sdk.action_results import OutputField, PermissiveActionOutput
from soar_sdk.params import Params

from ..asset import Asset
from ..test_connectivity import fetch_rate_limit


class CheckRateLimitOutput(PermissiveActionOutput):
    limit: int | None = OutputField(example_values=[1000], column_name="Query quota")
    remaining: int | None = OutputField(
        example_values=[992], column_name="Queries remaining"
    )
    reset: int | None = OutputField(
        example_values=[1618617600], column_name="Limit reset time"
    )
    offset_max: int | None = OutputField(
        example_values=[3000000], column_name="Offset max"
    )
    results_max: int | None = OutputField(
        example_values=[1000000], column_name="Results max"
    )


def check_rate_limit(
    params: Params, soar: SOARClient, asset: Asset
) -> CheckRateLimitOutput:
    rate = fetch_rate_limit(asset)
    soar.set_message("Rate limit details fetched successfully")
    return CheckRateLimitOutput(**rate)
