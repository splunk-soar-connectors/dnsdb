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

import re

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
    DNSDB_INVALID_HEX_RDATA,
    DNSDB_LOOKUP_TYPE_VALUE_LIST,
    DNSDB_VALUE_LIST_VALIDATION_MESSAGE,
)
from ..outputs import PassthroughOutput
from ..views import build_rdata_lookup_view

_HEX_RE = re.compile(r"[0-9A-Fa-f]+")


class RdataRawLookupParams(Params):
    raw_rdata: str = Param(
        description="An even number of hexadecimal digits specifying a raw octet string",
        primary=True,
        cef_types=["dnsdb rdata"],
    )
    type: str | None = Param(
        description="DNS record type",
        value_list=DNSDB_LOOKUP_TYPE_VALUE_LIST,
        cef_types=["dnsdb rrtype"],
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
    limit: int | None = Param(description="Max records to return", default=200)

    @field_validator("raw_rdata")
    @classmethod
    def _validate_raw_rdata(cls, value: str) -> str:
        if not _HEX_RE.fullmatch(value) or len(value) % 2:
            raise ValueError(DNSDB_INVALID_HEX_RDATA)
        return value

    @field_validator("type")
    @classmethod
    def _validate_type(cls, value: str | None) -> str | None:
        if value and value not in DNSDB_LOOKUP_TYPE_VALUE_LIST:
            raise ValueError(
                DNSDB_VALUE_LIST_VALIDATION_MESSAGE.format(
                    value_list=DNSDB_LOOKUP_TYPE_VALUE_LIST, key="type"
                )
            )
        return value

    @field_validator("limit", mode="before")
    @classmethod
    def _validate_limit(cls, value: Any) -> int | None:
        return validate_integer(value, "limit")


class RdataRawLookupOutput(PassthroughOutput):
    RDATA_CEF_TYPES: ClassVar[list[str]] = ["ip", "dnsdb ipv6"]
    RDATA_EXAMPLE: ClassVar[str] = (
        "fsi.io. hostmaster.fsi.io. 2014052828 7200 3600 25920000 3600"
    )

    count: int | None = OutputField(example_values=[100])
    rrname: str | None = OutputField(
        cef_types=["domain"], example_values=["dnstap.info"]
    )
    rrtype: str | None = OutputField(cef_types=["dnsdb rrtype"], example_values=["A"])
    time_last: int | None = OutputField(example_values=[1566085287])
    time_first: int | None = OutputField(example_values=[1566085287])


class RdataRawLookupSummary(ActionOutput):
    total_domains: int | None = None


def display_rdata_raw_lookup(outputs: list[RdataRawLookupOutput]) -> dict:
    rows = [o.model_dump() for o in outputs]
    return build_rdata_lookup_view(rows, table_title="Raw RDATA Lookup")


def lookup_rdata_raw(
    params: RdataRawLookupParams, soar: SOARClient, asset: Asset
) -> list[RdataRawLookupOutput]:
    time_first_before, time_first_after, time_last_before, time_last_after = (
        validate_time_params(
            params.time_first_before,
            params.time_first_after,
            params.time_last_before,
            params.time_last_after,
        )
    )

    try:
        responses = list(
            get_client(asset).lookup_rdata_raw(
                params.raw_rdata,
                rrtype=params.type,
                limit=params.limit,
                time_first_before=time_first_before,
                time_first_after=time_first_after,
                time_last_before=time_last_before,
                time_last_after=time_last_after,
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

    count_domain: set[str] = set()
    results: list[RdataRawLookupOutput] = []
    for resp in responses:
        if "rrname" in resp:
            resp["rrname"] = resp["rrname"].rstrip(".")
            count_domain.add(resp["rrname"])
        results.append(RdataRawLookupOutput(**resp))

    soar.set_summary(RdataRawLookupSummary(total_domains=len(count_domain)))
    soar.set_message(f"Total domains: {len(count_domain)}")
    return results
