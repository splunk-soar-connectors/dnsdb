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
def _parse_data(data, param):
    res = {}

    if "query" in param:
        res["flex"] = {}
        rrtypes = set(map(lambda x: x["rrtype"], data))
        for curr_rrtype in rrtypes:
            res["flex"][curr_rrtype] = []
        for match in data:
            res["flex"][match["rrtype"]].append(match)
    elif "ip" in param or "name" in param:
        res["response"] = {}
        res["response"] = data
        res["ip"] = {}
        res["ip"]["domains"] = set()
        for rdata in data:
            if rdata["rrname"]:
                res["ip"]["domains"].add(rdata["rrname"])

        for rt in res["ip"]:
            if isinstance(res["ip"][rt], set):
                res["ip"][rt] = list(res["ip"][rt])
    elif "raw_rdata" in param:
        res["response"] = {}
        res["response"] = data
        res["raw"] = {}
        res["raw"]["domains"] = set()
        for rdata in data:
            if rdata["rrname"]:
                res["raw"]["domains"].add(rdata["rrname"])

        for rt in res["raw"]:
            if isinstance(res["raw"][rt], set):
                res["raw"][rt] = list(res["raw"][rt])
    elif "owner_name" in param or ("type" in param and param["type"] == "RRSET"):
        res["domain"] = {}
        rrtype = param.get("type") or "ANY"
        rrtypes = set(map(lambda x: x["rrtype"], data))

        if rrtype in ("ANY", "ANY-DNSSEC"):
            for curr_rrtype in rrtypes:
                if curr_rrtype in ["SOA", "MX"]:
                    res["domain"][curr_rrtype] = []
                else:
                    res["domain"][curr_rrtype] = set()

        elif rrtype in ["SOA", "MX"]:
            res["domain"][rrtype] = []
        else:
            res["domain"][rrtype] = set()

        for rrset in data:
            if rrset["rrtype"] in ["SOA", "MX"]:
                res["domain"][rrset["rrtype"]] = (
                    res["domain"][rrset["rrtype"]] + rrset["rdata"]
                )
            else:
                res["domain"][rrset["rrtype"]] = res["domain"][rrset["rrtype"]].union(
                    rrset["rdata"]
                )

        if "SOA" in res["domain"]:
            res["domain"]["SOA"] = [
                dict(s) for s in set(frozenset(d.items()) for d in res["domain"]["SOA"])
            ]
        if "MX" in res["domain"]:
            res["domain"]["MX"] = [
                dict(s) for s in set(frozenset(d.items()) for d in res["domain"]["MX"])
            ]

        for rt in res["domain"]:
            if isinstance(res["domain"][rt], set):
                res["domain"][rt] = list(res["domain"][rt])

    return res


def _get_ctx_result(result):
    ctx_result = {}

    param = result.get_param()
    summary = result.get_summary()
    data = result.get_data()

    ctx_result["param"] = param
    if summary:
        ctx_result["summary"] = summary

    if not data:
        ctx_result["data"] = {}
        return ctx_result

    data = _parse_data(data, ctx_result["param"])

    ctx_result["data"] = data
    return ctx_result


def display_lookup_info(provides, all_app_runs, context):
    context["results"] = results = []
    for _summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = _get_ctx_result(result)
            if not ctx_result:
                continue
            results.append(ctx_result)

    return "templates/dnsdb_lookup_info.html"
