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

_CEF_BY_RRTYPE = {
    "A": "ip",
    "AAAA": "dnsdb ipv6",
    "NS": "domain",
    "CNAME": "domain",
}


def build_rdata_lookup_view(rows: list[dict], table_title: str) -> dict:
    domains = sorted({row["rrname"] for row in rows if row.get("rrname")})
    return {
        "kind": "rdata_lookup",
        "table_title": table_title,
        "domains": domains,
        "rows": rows,
    }


def build_rrset_view(rows: list[dict]) -> dict:
    groups: dict[str, dict] = {}
    for row in rows:
        rrtype = row.get("rrtype")
        if not rrtype:
            continue
        group = groups.setdefault(
            rrtype,
            {
                "rrtype": rrtype,
                "is_soa": rrtype == "SOA",
                "is_mx": rrtype == "MX",
                "cef_type": _CEF_BY_RRTYPE.get(rrtype),
                "rows": [],
                "values": [],
            },
        )
        rdata = row.get("rdata") or []
        for item in rdata:
            if rrtype in ("SOA", "MX"):
                if item not in group["rows"]:
                    group["rows"].append(item)
            elif item not in group["values"]:
                group["values"].append(item)

    return {"kind": "rrset", "groups": list(groups.values())}


def build_flex_view(rows: list[dict]) -> dict:
    groups: dict[str, dict] = {}
    for row in rows:
        rrtype = row.get("rrtype")
        if not rrtype:
            continue
        group = groups.setdefault(
            rrtype,
            {"rrtype": rrtype, "is_rrnames": False, "values": []},
        )
        if row.get("rrname"):
            group["is_rrnames"] = True
            value = row["rrname"]
        else:
            value = row.get("rdata") or row.get("raw_rdata")
        if value and value not in group["values"]:
            group["values"].append(value)

    return {"kind": "flex", "groups": list(groups.values())}
