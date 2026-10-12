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

import contextlib
import re
import socket
import time
from datetime import UTC, datetime
from typing import Any

import dnsdb2
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

from .asset import Asset
from .dnsdb_consts import (
    DNSDB_ACCESS_DENIED_MESSAGE,
    DNSDB_ERROR_CODE_MESSAGE,
    DNSDB_ERROR_MESSAGE_UNAVAILABLE,
    DNSDB_INVALID_TIME,
    DNSDB_INVALID_TIME_FORMAT,
    DNSDB_NON_NEGATIVE_INTEGER_MESSAGE,
    DNSDB_PARSE_ERROR_MESSAGE,
    DNSDB_QUOTA_EXCEEDED_MESSAGE,
    DNSDB_TIME_FORMAT,
    DNSDB_VALID_INTEGER_MESSAGE,
)


logger = getLogger()


def get_client(asset: Asset) -> dnsdb2.Client:
    return dnsdb2.Client(asset.api_key)


def map_known_dnsdb_error(error: Exception) -> ActionFailure | None:
    if isinstance(error, dnsdb2.exceptions.AccessDenied):
        return ActionFailure(DNSDB_ACCESS_DENIED_MESSAGE)
    if isinstance(error, dnsdb2.exceptions.QuotaExceeded):
        return ActionFailure(DNSDB_QUOTA_EXCEEDED_MESSAGE)
    return None


def log_unknown_error(error: Exception) -> None:
    """Debug-log details that dnsdb2 drops from its exception message.

    dnsdb2 re-raises unmapped HTTP errors as an argless QueryError, so the real HTTP status and
    response body only exist on error.__cause__. Debug level only; the user-facing message is
    unchanged.
    """
    cause = error.__cause__
    response = getattr(cause, "response", None)
    logger.debug(
        f"Unexpected DNSDB error: {type(error).__name__}{error.args!r}; cause={cause!r}; "
        f"http_status={getattr(response, 'status_code', None)}; "
        f"body={(getattr(response, 'text', '') or '')[:500]}"
    )


def format_unknown_error(error: Exception) -> str:
    """Format an unexpected exception exactly like the legacy connector did.

    - no args        -> fixed "unavailable" message
    - one arg        -> that arg as the message
    - two or more    -> first arg is the code, second is the message
    """
    with contextlib.suppress(Exception):
        log_unknown_error(error)

    error_code: Any = DNSDB_ERROR_CODE_MESSAGE
    error_message: Any = DNSDB_ERROR_MESSAGE_UNAVAILABLE
    with contextlib.suppress(Exception):
        if error.args:
            if len(error.args) > 1:
                error_code = error.args[0]
                error_message = error.args[1]
            elif len(error.args) == 1:
                error_message = error.args[0]

    try:
        # Substring check mirrors legacy behavior (including its TypeError on non-string codes)
        if error_code in DNSDB_ERROR_CODE_MESSAGE:
            return f"Error Message: {error_message}"
        return f"Error Code: {error_code}. Error Message: {error_message}"
    except Exception:
        return DNSDB_PARSE_ERROR_MESSAGE


def validate_integer(value: Any, key: str) -> int | None:
    """Validate an integer action parameter exactly like the legacy connector did.

    Raises ValueError with the legacy message for non-integers and negative values.
    """
    if value is None:
        return None

    try:
        if not float(value).is_integer():
            raise ValueError
        number = int(value)
    except Exception:
        raise ValueError(DNSDB_VALID_INTEGER_MESSAGE.format(key=key)) from None

    if number < 0:
        raise ValueError(DNSDB_NON_NEGATIVE_INTEGER_MESSAGE.format(key=key))
    return number


def is_ipv4(value: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, value)
        return True
    except OSError:
        return False


def is_ipv6(value: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6, value)
        return True
    except OSError:
        return False


def is_ip_address(value: str) -> bool:
    return is_ipv4(value) or is_ipv6(value)


_DOMAIN_LABEL_RE = re.compile(r"(?!-)[A-Z\d\-_]{1,63}(?<!-')$", re.IGNORECASE)


def validate_domain(value: str) -> str:
    # NOTE: currently unused (validators are commented out in the lookup actions), kept for the
    # pending team decision. Legacy registered an equivalent validator but never applied it.
    if len(value) > 255:
        raise ValueError("Please provide a valid domain name")

    if is_ip_address(value):
        raise ValueError("Please provide a valid domain name, not an IP address")

    stripped = value[:-1] if value.endswith(".") else value
    parts = stripped.split(".")

    for idx, part in enumerate(parts):
        is_edge = idx == 0 or idx == len(parts) - 1
        if is_edge:
            if not (part == "*" or _DOMAIN_LABEL_RE.match(part)):
                raise ValueError("Please provide a valid domain name")
        elif not _DOMAIN_LABEL_RE.match(part):
            raise ValueError("Please provide a valid domain name")

    return value


def _is_valid_time(time_value: str) -> bool:
    try:
        time.strptime(time_value, DNSDB_TIME_FORMAT)
    except ValueError:
        pass
    else:
        return True

    try:
        int(time_value)
    except ValueError:
        return False

    return len(time_value) == 10 or int(time_value) < 0


def validate_time_params(
    time_first_before: str | None,
    time_first_after: str | None,
    time_last_before: str | None,
    time_last_after: str | None,
) -> tuple[str | None, str | None, str | None, str | None]:
    timestamps = [time_first_before, time_first_after, time_last_before, time_last_after]

    for value in timestamps:
        if value and not _is_valid_time(value):
            raise ActionFailure(DNSDB_INVALID_TIME_FORMAT.format(time=value))

    now = datetime.now(UTC)
    for value in timestamps:
        if not value:
            continue
        try:
            if time.strptime(value, DNSDB_TIME_FORMAT) > now.timetuple():
                raise ActionFailure(DNSDB_INVALID_TIME)
        except ValueError:
            if int(value) > int(now.timestamp()):
                raise ActionFailure(DNSDB_INVALID_TIME)

    return time_first_before, time_first_after, time_last_before, time_last_after
