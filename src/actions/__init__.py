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

from soar_sdk.app import App

from .check_rate_limit import check_rate_limit, display_rate_limit
from .flex_search import FlexSearchSummary, display_flex_search, flex_search
from .lookup_rdata_ip import (
    RdataIpLookupSummary,
    display_rdata_ip_lookup,
    lookup_rdata_ip,
)
from .lookup_rdata_name import (
    RdataNameLookupSummary,
    display_rdata_name_lookup,
    lookup_rdata_name,
)
from .lookup_rdata_raw import (
    RdataRawLookupSummary,
    display_rdata_raw_lookup,
    lookup_rdata_raw,
)
from .lookup_rrset import RrsetLookupSummary, display_rrset_lookup, lookup_rrset
from .make_request import http_action


def register_actions(app: App) -> App:
    """Register all DNSDB actions on the provided app."""
    app.make_request()(http_action)
    app.register_action(
        action=check_rate_limit,
        description="Get data of current data limit",
        action_type="investigate",
        read_only=True,
        view_handler=display_rate_limit,
        view_template="dnsdb_rate_limits.html",
    )
    app.register_action(
        action=lookup_rdata_name,
        description="Performs Name RDATA Lookup",
        action_type="investigate",
        read_only=True,
        verbose="If the <b>limit</b> parameter is not specified, the action will use 200.",
        summary_type=RdataNameLookupSummary,
        view_handler=display_rdata_name_lookup,
        view_template="dnsdb_lookup_info.html",
    )
    app.register_action(
        action=lookup_rdata_ip,
        description="Performs IP RDATA Lookup",
        action_type="investigate",
        read_only=True,
        verbose="If the <b>limit</b> parameter is not specified, the action will use 200.",
        summary_type=RdataIpLookupSummary,
        view_handler=display_rdata_ip_lookup,
        view_template="dnsdb_lookup_info.html",
    )
    app.register_action(
        action=lookup_rdata_raw,
        description="Lookup raw RDATA",
        action_type="investigate",
        read_only=True,
        verbose="If the <b>limit</b> parameter is not specified, the action will use 200.",
        summary_type=RdataRawLookupSummary,
        view_handler=display_rdata_raw_lookup,
        view_template="dnsdb_lookup_info.html",
    )
    app.register_action(
        action=lookup_rrset,
        description="Perform a DNSDB RRSET lookup",
        action_type="investigate",
        read_only=True,
        verbose="If the <b>limit</b> parameter is not specified, the action will use 200.",
        summary_type=RrsetLookupSummary,
        view_handler=display_rrset_lookup,
        view_template="dnsdb_lookup_info.html",
    )
    app.register_action(
        action=flex_search,
        description="Perform a Flex search",
        action_type="investigate",
        read_only=True,
        verbose="If the <b>limit</b> parameter is not specified, the action will use default value as 10000.",
        summary_type=FlexSearchSummary,
        view_handler=display_flex_search,
        view_template="dnsdb_lookup_info.html",
    )
    return app
