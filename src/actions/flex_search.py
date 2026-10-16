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
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..helpers import (
    format_unknown_error,
    get_client,
    map_known_dnsdb_error,
    validate_integer,
    validate_time_params,
    validate_value_list,
)
from ..dnsdb_consts import (
    DNSDB_DATA_NOT_AVAILABLE_MESSAGE,
    DNSDB_FLEX_SEARCH_TYPE_VALUE_LIST,
    DNSDB_FLEX_TYPE_VALUE_LIST,
)


class FlexSearchParams(Params):
    query: str = Param(description="Flex search query")
    type: str = Param(
        description="DNS record type", value_list=DNSDB_FLEX_TYPE_VALUE_LIST
    )
    search_type: str = Param(
        description="Search syntax type", value_list=DNSDB_FLEX_SEARCH_TYPE_VALUE_LIST
    )
    time_first_after: str | None = Param(
        description="Record first seen after (epoch, relative seconds e.g. -31536000, or UTC timestamp e.g. 2021-01-05T12:06:02Z)"
    )
    time_first_before: str | None = Param(
        description="Record first seen before (epoch, relative seconds e.g. -31536000, or UTC timestamp e.g. 2021-01-05T12:06:02Z)"
    )
    time_last_after: str | None = Param(
        description="Record last seen after (epoch, relative seconds e.g. -31536000, or UTC timestamp e.g. 2021-01-05T12:06:02Z)"
    )
    time_last_before: str | None = Param(
        description="Record last seen before (epoch, relative seconds e.g. -31536000, or UTC timestamp e.g. 2021-01-05T12:06:02Z)"
    )
    exclude: str | None = Param(description="Exclusion pattern (regex)")
    limit: float | None = Param(description="Max records to return", default=10000)


class FlexSearchOutput(PermissiveActionOutput):
    rdata: str | None = OutputField(
        cef_types=["ip", "dnsdb ipv6", "domain"], example_values=["66.160.140.81"]
    )
    count: int | None = None
    rrname: str | None = OutputField(
        cef_types=["domain"], example_values=["farsightsecurity.com"]
    )
    rrtype: str | None = OutputField(cef_types=["dnsdb rrtype"], example_values=["A"])
    bailiwick: str | None = OutputField(
        cef_types=["domain"], example_values=["farsightsecurity.com."]
    )
    time_last: int | None = OutputField(example_values=[1566085287])
    time_first: int | None = OutputField(example_values=[1566085287])
    zone_time_last: int | None = OutputField(example_values=[1566085287])
    zone_time_first: int | None = OutputField(example_values=[1566085287])
    raw_rdata: str | None = OutputField(example_values=["0366736902696f00"])


class FlexSearchSummary(ActionOutput):
    total_items: int | None = None


def flex_search(
    params: FlexSearchParams, soar: SOARClient, asset: Asset
) -> list[FlexSearchOutput]:
    validate_value_list(params.type, DNSDB_FLEX_TYPE_VALUE_LIST, "type", required=True)
    validate_value_list(
        params.search_type,
        DNSDB_FLEX_SEARCH_TYPE_VALUE_LIST,
        "search_type",
        required=True,
    )
    limit = validate_integer(params.limit, "limit")

    time_first_before, time_first_after, time_last_before, time_last_after = (
        validate_time_params(
            params.time_first_before,
            params.time_first_after,
            params.time_last_before,
            params.time_last_after,
        )
    )

    client = get_client(asset)
    flex_method = {
        ("RDATA", "regex"): client.flex_rdata_regex,
        ("RDATA", "glob"): client.flex_rdata_glob,
        ("RRNAMES", "regex"): client.flex_rrnames_regex,
        ("RRNAMES", "glob"): client.flex_rrnames_glob,
    }[(params.type, params.search_type)]

    try:
        responses = list(
            flex_method(
                params.query,
                time_first_before=time_first_before,
                time_first_after=time_first_after,
                time_last_before=time_last_before,
                time_last_after=time_last_after,
                exclude=params.exclude,
                limit=limit,
                ignore_limited=True,
            )
        )
    except Exception as error:
        known = map_known_dnsdb_error(error)
        if known is not None:
            raise known from error
        raise ActionFailure(format_unknown_error(error)) from error

    if not responses:
        soar.set_message(DNSDB_DATA_NOT_AVAILABLE_MESSAGE)
        return []

    results: list[FlexSearchOutput] = []
    for resp in responses:
        if "rrname" in resp:
            resp["rrname"] = resp["rrname"].rstrip(".")
        results.append(FlexSearchOutput(**resp))

    soar.set_summary(FlexSearchSummary(total_items=len(responses)))
    soar.set_message(f"Total items: {len(responses)}")
    return results
