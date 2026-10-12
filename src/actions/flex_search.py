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

from typing import Any, ClassVar

from pydantic.functional_validators import field_validator
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..dnsdb_client import (
    format_unknown_error,
    get_client,
    map_known_dnsdb_error,
    validate_integer,
    validate_time_params,
)
from ..dnsdb_consts import (
    DNSDB_DATA_NOT_AVAILABLE_MESSAGE,
    DNSDB_FLEX_SEARCH_TYPE_VALUE_LIST,
    DNSDB_FLEX_TYPE_VALUE_LIST,
    DNSDB_VALUE_LIST_VALIDATION_MESSAGE,
)
from ..outputs import PassthroughOutput
from ..views import build_flex_view


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
    limit: int | None = Param(description="Max records to return", default=10000)

    @field_validator("type")
    @classmethod
    def _validate_type(cls, value: str) -> str:
        if value not in DNSDB_FLEX_TYPE_VALUE_LIST:
            raise ValueError(
                DNSDB_VALUE_LIST_VALIDATION_MESSAGE.format(
                    value_list=DNSDB_FLEX_TYPE_VALUE_LIST, key="type"
                )
            )
        return value

    @field_validator("search_type")
    @classmethod
    def _validate_search_type(cls, value: str) -> str:
        if value not in DNSDB_FLEX_SEARCH_TYPE_VALUE_LIST:
            raise ValueError(
                DNSDB_VALUE_LIST_VALIDATION_MESSAGE.format(
                    value_list=DNSDB_FLEX_SEARCH_TYPE_VALUE_LIST, key="search_type"
                )
            )
        return value

    @field_validator("limit", mode="before")
    @classmethod
    def _validate_limit(cls, value: Any) -> int | None:
        return validate_integer(value, "limit")


class FlexSearchOutput(PassthroughOutput):
    RDATA_CEF_TYPES: ClassVar[list[str]] = ["ip", "dnsdb ipv6", "domain"]
    RDATA_EXAMPLE: ClassVar[str] = "66.160.140.81"

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


def display_flex_search(outputs: list[FlexSearchOutput]) -> dict:
    rows = [o.model_dump() for o in outputs]
    return build_flex_view(rows)


def flex_search(
    params: FlexSearchParams, soar: SOARClient, asset: Asset
) -> list[FlexSearchOutput]:
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
                limit=params.limit,
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
