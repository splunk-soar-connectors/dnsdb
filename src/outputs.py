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
from typing import ClassVar

from soar_sdk.action_results import OutputFieldSpecification, PermissiveActionOutput


class PassthroughOutput(PermissiveActionOutput):
    """Return a DNSDB record exactly as received, like the legacy `add_data(resp)`.

    DNSDB returns `rdata` as a list of strings for the lookup actions (a plain string for flex
    search), while the legacy manifest documents it as a single string. `rdata` is therefore not
    declared as a model field (which would be validated and reject real responses). It is kept
    in the record as an extra value, and declared in the manifest here with the same path and
    CEF types as the legacy manifest.

    Note: this overrides an SDK-internal hook; re-check it when upgrading splunk-soar-sdk.
    """

    RDATA_CEF_TYPES: ClassVar[list[str]] = []
    RDATA_EXAMPLE: ClassVar[str] = ""

    @classmethod
    def _to_json_schema(
        cls,
        parent_datapath: str = "action_result.data.*",
        column_order_counter: itertools.count | None = None,
    ) -> Iterator[OutputFieldSpecification]:
        yield from super()._to_json_schema(parent_datapath, column_order_counter)
        yield OutputFieldSpecification(
            data_path=f"{parent_datapath}.rdata",
            data_type="string",
            contains=cls.RDATA_CEF_TYPES,
            example_values=[cls.RDATA_EXAMPLE],
        )
