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
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

from .asset import Asset
from .dnsdb_client import get_client, map_known_dnsdb_error
from .dnsdb_consts import DNSDB_TEST_CONNECTIVITY_FAIL, DNSDB_TEST_CONNECTIVITY_MESSAGE

logger = getLogger()


def run_test_connectivity(soar: SOARClient, asset: Asset) -> None:
    logger.progress(DNSDB_TEST_CONNECTIVITY_MESSAGE)

    try:
        rate = get_client(asset).rate_limit()["rate"]
    except Exception as error:
        known = map_known_dnsdb_error(error)
        if known is not None:
            raise known from error
        logger.debug(str(error))
        raise ActionFailure(DNSDB_TEST_CONNECTIVITY_FAIL) from error

    logger.progress(
        "Test succeeded. Query quota is %s with %s queries remaining. Resets %s",
        rate.get("limit"),
        rate.get("remaining"),
        rate.get("reset"),
    )
    soar.set_message("Rate limit details fetched successfully")
