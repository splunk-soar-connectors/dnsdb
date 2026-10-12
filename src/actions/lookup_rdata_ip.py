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

from pydantic import field_validator
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..dnsdb_client import (
    format_unknown_error,
    get_client,
    is_ipv4,
    map_known_dnsdb_error,
    validate_integer,
    validate_time_params,
)
from ..dnsdb_consts import (
    DNSDB_DATA_NOT_AVAILABLE_MESSAGE,
    DNSDB_INVALID_NETWORK_PREFIX,
)
from ..outputs import PassthroughOutput
from ..views import build_rdata_lookup_view


class RdataIpLookupParams(Params):
    ip: str = Param(
        description="IP to resolve", primary=True, cef_types=["ip", "dnsdb ipv6"]
    )
    network_prefix: int | None = Param(description="Network prefix")
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

    @field_validator("limit", "network_prefix", mode="before")
    @classmethod
    def _validate_integer_params(cls, value: Any, info) -> int | None:
        return validate_integer(value, info.field_name)


class RdataIpLookupOutput(PassthroughOutput):
    RDATA_CEF_TYPES: ClassVar[list[str]] = ["ip", "dnsdb ipv6"]
    RDATA_EXAMPLE: ClassVar[str] = "192.0.2.1"

    count: int | None = OutputField(example_values=[100])
    rrname: str | None = OutputField(cef_types=["domain"], example_values=["ns1.uceb.org."])
    rrtype: str | None = OutputField(cef_types=["dnsdb rrtype"], example_values=["A"])
    time_last: int | None = OutputField(example_values=[1566085287])
    time_first: int | None = OutputField(example_values=[1566085287])
    zone_time_last: int | None = OutputField(example_values=[1566085287])
    zone_time_first: int | None = OutputField(example_values=[1566085287])


class RdataIpLookupSummary(ActionOutput):
    total_domains: int | None = None


def display_rdata_ip_lookup(outputs: list[RdataIpLookupOutput]) -> dict:
    rows = [o.model_dump() for o in outputs]
    return build_rdata_lookup_view(rows, table_title="RDATA Lookup")


def lookup_rdata_ip(
    params: RdataIpLookupParams, soar: SOARClient, asset: Asset
) -> list[RdataIpLookupOutput]:
    if params.network_prefix is not None:
        max_prefix = 32 if is_ipv4(params.ip) else 128
        if not (0 <= params.network_prefix <= max_prefix):
            raise ActionFailure(
                DNSDB_INVALID_NETWORK_PREFIX.format(prefix=params.network_prefix)
            )

    ip = f"{params.ip},{params.network_prefix}" if params.network_prefix is not None else params.ip

    time_first_before, time_first_after, time_last_before, time_last_after = validate_time_params(
        params.time_first_before,
        params.time_first_after,
        params.time_last_before,
        params.time_last_after,
    )

    try:
        responses = list(
            get_client(asset).lookup_rdata_ip(
                ip,
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
    results: list[RdataIpLookupOutput] = []
    for resp in responses:
        if "rrname" in resp:
            resp["rrname"] = resp["rrname"].rstrip(".")
            count_domain.add(resp["rrname"])
        results.append(RdataIpLookupOutput(**resp))

    soar.set_summary(RdataIpLookupSummary(total_domains=len(count_domain)))
    soar.set_message(f"Total domains: {len(count_domain)}")
    return results
