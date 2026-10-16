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
    validate_domain,
    validate_integer,
    validate_time_params,
)
from ..dnsdb_consts import DNSDB_DATA_NOT_AVAILABLE_MESSAGE


class RdataNameLookupParams(Params):
    name: str = Param(description="Name to lookup", primary=True, cef_types=["domain"])
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
    limit: float | None = Param(description="Max records to return", default=200)


class RdataNameLookupOutput(PermissiveActionOutput):
    rdata: list[str] | None = OutputField(
        cef_types=["domain"], example_values=["www.farsightsecurity.com"]
    )
    count: int | None = OutputField(example_values=[100])
    rrname: str | None = OutputField(
        cef_types=["domain"], example_values=["207.4.20.149.in-addr.fsi.io."]
    )
    rrtype: str | None = OutputField(example_values=["A"])
    time_last: int | None = OutputField(example_values=[1566085287])
    time_first: int | None = OutputField(example_values=[1566085287])
    zone_time_last: int | None = OutputField(example_values=[1566085287])
    zone_time_first: int | None = OutputField(example_values=[1566085287])


class RdataNameLookupSummary(ActionOutput):
    total_domains: int | None = None


def lookup_rdata_name(
    params: RdataNameLookupParams, soar: SOARClient, asset: Asset
) -> list[RdataNameLookupOutput]:
    validate_domain(params.name, "name")
    limit = validate_integer(params.limit, "limit")

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
            get_client(asset).lookup_rdata_name(
                params.name,
                limit=limit,
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
    results: list[RdataNameLookupOutput] = []
    for resp in responses:
        if "rrname" in resp:
            resp["rrname"] = resp["rrname"].rstrip(".")
            count_domain.add(resp["rrname"])
        results.append(RdataNameLookupOutput(**resp))

    soar.set_summary(RdataNameLookupSummary(total_domains=len(count_domain)))
    soar.set_message(f"Total domains: {len(count_domain)}")
    return results
