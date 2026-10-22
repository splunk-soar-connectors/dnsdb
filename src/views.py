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

from soar_sdk.action_results import ActionOutput
from soar_sdk.models.view import ViewContext

from .actions.flex_search import FlexSearchOutput
from .actions.lookup_rdata_ip import RdataIpLookupOutput
from .actions.lookup_rdata_name import RdataNameLookupOutput
from .actions.lookup_rdata_raw import RdataRawLookupOutput
from .actions.lookup_rrset import RrsetLookupOutput


def _rows(outputs: list[ActionOutput]) -> list[dict]:
    return [output.model_dump() for output in outputs]


def _rdata_lookup_view(context: ViewContext, kind: str, outputs: list) -> dict:
    rows = _rows(outputs)
    domains = sorted({row["rrname"] for row in rows if row.get("rrname")})
    result = {"kind": kind, "rows": rows, "domains": domains, "total": len(domains)}
    return {"container_id": context.container, "results": [result]}


def display_rdata_name_lookup(
    context: ViewContext, outputs: list[RdataNameLookupOutput]
) -> dict:
    return _rdata_lookup_view(context, "rdata_name", outputs)


def display_rdata_ip_lookup(
    context: ViewContext, outputs: list[RdataIpLookupOutput]
) -> dict:
    return _rdata_lookup_view(context, "rdata_ip", outputs)


def display_rdata_raw_lookup(
    context: ViewContext, outputs: list[RdataRawLookupOutput]
) -> dict:
    return _rdata_lookup_view(context, "rdata_raw", outputs)


def display_rrset_lookup(
    context: ViewContext, outputs: list[RrsetLookupOutput]
) -> dict:
    rows = _rows(outputs)
    groups: dict[str, list] = {}
    for row in rows:
        rrtype = row.get("rrtype")
        if not rrtype:
            continue
        entries = groups.setdefault(rrtype, [])
        for item in row.get("rdata") or []:
            if item not in entries:
                entries.append(item)

    result = {
        "kind": "rrset",
        "rows": rows,
        "groups": [{"rrtype": rrtype, "entries": e} for rrtype, e in groups.items()],
        "total": len(rows),
    }
    return {"container_id": context.container, "results": [result]}


def display_flex_search(context: ViewContext, outputs: list[FlexSearchOutput]) -> dict:
    rows = _rows(outputs)
    groups: dict[str, dict] = {}
    for row in rows:
        group = groups.setdefault(
            row.get("rrtype") or "UNKNOWN", {"rows": [], "is_rdata": False}
        )
        group["rows"].append(row)
        if row.get("rdata") or row.get("raw_rdata"):
            group["is_rdata"] = True

    result = {
        "kind": "flex",
        "rows": rows,
        "groups": [{"rrtype": rrtype, **group} for rrtype, group in groups.items()],
        "total": len(rows),
    }
    return {"container_id": context.container, "results": [result]}
