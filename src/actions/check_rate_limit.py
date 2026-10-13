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

import itertools
from collections.abc import Iterator

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField, OutputFieldSpecification
from soar_sdk.params import Params

from ..asset import Asset
from ..test_connectivity import fetch_rate_limit


class CheckRateLimitOutput(ActionOutput):
    reset: int = OutputField(example_values=[1618617600])
    remaining: int = OutputField(example_values=[992])
    limit: int = OutputField(example_values=[1000])
    offset_max: int = OutputField(example_values=[3000000])
    results_max: int = OutputField(example_values=[1000000])


class CheckRateLimitSummary(ActionOutput):
    @classmethod
    def _to_json_schema(
        cls,
        parent_datapath: str = "action_result.summary",
        column_order_counter: itertools.count | None = None,
    ) -> Iterator[OutputFieldSpecification]:
        yield OutputFieldSpecification(data_path=parent_datapath, data_type="string")


def check_rate_limit(
    params: Params, soar: SOARClient, asset: Asset
) -> CheckRateLimitOutput:
    rate = fetch_rate_limit(asset)
    soar.set_message("Rate limit details fetched successfully")
    return CheckRateLimitOutput(**rate)
