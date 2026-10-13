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
from soar_sdk.action_results import (
    ActionOutput,
    OutputField,
    OutputFieldSpecification,
    PermissiveActionOutput,
)
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..dnsdb_client import (
    format_unknown_error,
    get_client,
    map_known_dnsdb_error,
    validate_domain,
    validate_integer,
    validate_time_params,
    validate_value_list,
)
from ..dnsdb_consts import (
    DNSDB_DATA_NOT_AVAILABLE_MESSAGE,
    DNSDB_INVALID_BAILIWICK,
    DNSDB_LOOKUP_TYPE_VALUE_LIST,
)

_SOA_FIELDS = (
    "rdata_origin",
    "rdata_mail_addr",
    "rdata_serial",
    "rdata_refresh",
    "rdata_retry",
    "rdata_expire",
    "rdata_minimum",
)
_MX_FIELDS = ("rdata_preference", "rdata_mail_exchange")


class RrsetLookupParams(Params):
    owner_name: str = Param(
        description="Domain to resolve", primary=True, cef_types=["domain"]
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
    bailiwick: str | None = Param(description="Bailiwick")
    limit: float | None = Param(description="Max records to return", default=200)


class RdataOutput(ActionOutput):
    """Nested SOA/MX fields, declared only to document the manifest paths."""

    rdata_origin: str | None = OutputField(
        cef_types=["host name"], example_values=["fsi.io."]
    )
    rdata_mail_addr: str | None = OutputField(
        cef_types=["email"], example_values=["hostmaster.fsi.io"]
    )
    rdata_serial: str | None = OutputField(example_values=["2015040254"])
    rdata_refresh: str | None = OutputField(example_values=["7200"])
    rdata_retry: str | None = OutputField(example_values=["3600"])
    rdata_expire: str | None = OutputField(example_values=["604800"])
    rdata_minimum: str | None = OutputField(example_values=["3600"])
    rdata_preference: str | None = OutputField(example_values=["10"])
    rdata_mail_exchange: str | None = OutputField(
        cef_types=["domain"], example_values=["ss.vix.su"]
    )


class RrsetLookupOutput(PermissiveActionOutput):
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

    @classmethod
    def _to_json_schema(
        cls,
        parent_datapath: str = "action_result.data.*",
        column_order_counter: itertools.count | None = None,
    ) -> Iterator[OutputFieldSpecification]:
        # rdata mixes plain strings and SOA/MX objects, which one field type can't declare
        yield from super()._to_json_schema(parent_datapath, column_order_counter)
        yield OutputFieldSpecification(
            data_path=f"{parent_datapath}.rdata",
            data_type="string",
            contains=["ip", "dnsdb ipv6", "domain"],
            example_values=["66.160.140.81"],
        )
        yield from RdataOutput._to_json_schema(
            f"{parent_datapath}.rdata.*", column_order_counter
        )


class RrsetLookupSummary(ActionOutput):
    total_items: int | None = None


def _split_rdata(rrtype: str, raw_rdata: list[str]) -> list[dict | str]:
    reshaped: list[dict | str] = []
    for curr_rdata in raw_rdata:
        if rrtype == "SOA":
            parts = [p.rstrip(".") for p in curr_rdata.split(" ")]
            reshaped.append(dict(zip(_SOA_FIELDS, parts, strict=False)))
        elif rrtype == "MX":
            parts = [p.rstrip(".") for p in curr_rdata.split(" ")]
            reshaped.append(dict(zip(_MX_FIELDS, parts, strict=False)))
        else:
            reshaped.append(curr_rdata.rstrip("."))
    return reshaped


def lookup_rrset(
    params: RrsetLookupParams, soar: SOARClient, asset: Asset
) -> list[RrsetLookupOutput]:
    validate_domain(params.owner_name, "owner_name")
    validate_value_list(params.type, DNSDB_LOOKUP_TYPE_VALUE_LIST, "type")
    limit = validate_integer(params.limit, "limit")

    record_type = params.type or "ANY"

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
            get_client(asset).lookup_rrset(
                params.owner_name,
                bailiwick=params.bailiwick,
                rrtype=record_type,
                limit=limit,
                time_first_before=time_first_before,
                time_first_after=time_first_after,
                time_last_before=time_last_before,
                time_last_after=time_last_after,
                ignore_limited=True,
            )
        )
    except UnicodeError as error:
        raise ActionFailure(
            DNSDB_INVALID_BAILIWICK.format(bailiwick=params.bailiwick)
        ) from error
    except Exception as error:
        known = map_known_dnsdb_error(error)
        if known is not None:
            raise known from error
        raise ActionFailure(format_unknown_error(error)) from error

    if not responses:
        soar.set_message(DNSDB_DATA_NOT_AVAILABLE_MESSAGE)
        return []

    results: list[RrsetLookupOutput] = []
    for resp in responses:
        if "rdata" in resp:
            resp["rdata"] = _split_rdata(resp.get("rrtype"), resp["rdata"])
        if "rrname" in resp:
            resp["rrname"] = resp["rrname"].rstrip(".")
        if "bailiwick" in resp:
            resp["bailiwick"] = resp["bailiwick"].rstrip(".")
        results.append(RrsetLookupOutput(**resp))

    soar.set_summary(RrsetLookupSummary(total_items=len(responses)))
    soar.set_message(f"Total items: {len(responses)}")
    return results
