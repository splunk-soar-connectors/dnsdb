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

from ..views import display_lookup_info, show_rate_limits
from .check_rate_limit import CheckRateLimitSummary, check_rate_limit
from .flex_search import FlexSearchSummary, flex_search
from .lookup_rdata_ip import RdataIpLookupSummary, lookup_rdata_ip
from .lookup_rdata_name import RdataNameLookupSummary, lookup_rdata_name
from .lookup_rdata_raw import RdataRawLookupSummary, lookup_rdata_raw
from .lookup_rrset import RrsetLookupSummary, lookup_rrset
from .make_request import http_action


def register_actions(app: App) -> App:
    app.make_request()(http_action)
    app.action(
        description="Get data of current data limit",
        action_type="investigate",
        read_only=True,
        summary_type=CheckRateLimitSummary,
        view_handler=show_rate_limits,
    )(check_rate_limit)
    app.action(
        name="rdata name lookup",
        description="Performs Name RDATA Lookup",
        action_type="investigate",
        read_only=True,
        verbose="If the <b>limit</b> parameter is not specified, the action will use 200.",
        summary_type=RdataNameLookupSummary,
        view_handler=display_lookup_info,
    )(lookup_rdata_name)
    app.action(
        name="rdata ip lookup",
        description="Performs IP RDATA Lookup",
        action_type="investigate",
        read_only=True,
        verbose="If the <b>limit</b> parameter is not specified, the action will use 200.",
        summary_type=RdataIpLookupSummary,
        view_handler=display_lookup_info,
    )(lookup_rdata_ip)
    app.action(
        name="rdata raw lookup",
        description="Lookup raw RDATA",
        action_type="investigate",
        read_only=True,
        verbose="If the <b>limit</b> parameter is not specified, the action will use 200.",
        summary_type=RdataRawLookupSummary,
        view_handler=display_lookup_info,
    )(lookup_rdata_raw)
    app.action(
        name="rrset lookup",
        description="Perform a DNSDB RRSET lookup",
        action_type="investigate",
        read_only=True,
        verbose="If the <b>limit</b> parameter is not specified, the action will use 200.",
        summary_type=RrsetLookupSummary,
        view_handler=display_lookup_info,
    )(lookup_rrset)
    app.action(
        name="flex search",
        description="Perform a Flex search",
        action_type="investigate",
        read_only=True,
        verbose="If the <b>limit</b> parameter is not specified, the action will use default value as 10000.",
        summary_type=FlexSearchSummary,
        view_handler=display_lookup_info,
    )(flex_search)
    return app
