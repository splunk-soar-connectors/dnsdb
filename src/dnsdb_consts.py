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

# API
DNSDB_BASE_URL = "https://api.dnsdb.info/dnsdb/v2"
DNSDB_API_KEY_HEADER = "X-Api-Key"  # pragma: allowlist secret
DNSDB_DEFAULT_TIMEOUT = 30

# Shared value lists
DNSDB_LOOKUP_TYPE_VALUE_LIST = [
    "ANY",
    "A",
    "A6",
    "AAAA",
    "AFSDB",
    "CNAME",
    "DNAME",
    "HINFO",
    "ISDN",
    "KX",
    "NAPTR",
    "NXT",
    "MB",
    "MD",
    "MF",
    "MG",
    "MINFO",
    "MR",
    "MX",
    "NS",
    "PTR",
    "PX",
    "RP",
    "RT",
    "SIG",
    "SOA",
    "SRV",
    "TXT",
    "ANY-DNSSEC",
    "DLV",
    "DNSKEY",
    "DS",
    "NSEC",
    "NSEC3",
    "NSEC3PARAM",
    "RRSIG",
]
DNSDB_FLEX_TYPE_VALUE_LIST = ["RDATA", "RRNAMES"]
DNSDB_FLEX_SEARCH_TYPE_VALUE_LIST = ["regex", "glob"]

# Time handling
DNSDB_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# Messages
DNSDB_ACCESS_DENIED_MESSAGE = "The API key is invalid"
DNSDB_QUOTA_EXCEEDED_MESSAGE = (
    "The license count usage for the given period has been exceeded."
)
DNSDB_TEST_CONNECTIVITY_MESSAGE = (
    "Running a rate-limit query to check API key with DNSDB"
)
DNSDB_TEST_CONNECTIVITY_FAIL = "Connectivity test failed"
DNSDB_DATA_NOT_AVAILABLE_MESSAGE = "Data not available"
DNSDB_INVALID_TIME_FORMAT = "Invalid time format : {time}"
DNSDB_INVALID_TIME = "Future date value is not allowed. Please provide valid datetime"
DNSDB_INVALID_NETWORK_PREFIX = "Invalid network prefix : {prefix}"
DNSDB_INVALID_BAILIWICK = "Invalid bailiwick : {bailiwick}"
DNSDB_INVALID_DOMAIN = "Please provide a valid domain name in the '{key}' parameter"
DNSDB_INVALID_HEX_RDATA = "raw_rdata must be an even-length hexadecimal string"
DNSDB_VALID_INTEGER_MESSAGE = (
    "Please provide a valid integer value in the '{key}' action parameter"
)
DNSDB_NON_NEGATIVE_INTEGER_MESSAGE = (
    "Please provide a valid non-negative integer value in the '{key}' action parameter"
)
DNSDB_VALUE_LIST_VALIDATION_MESSAGE = (
    "Please provide valid input from {value_list} in '{key}' action parameter"
)

# Error message handling (mirrors legacy _get_error_message_from_exception)
DNSDB_ERROR_CODE_MESSAGE = "Error code unavailable"
DNSDB_ERROR_MESSAGE_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
DNSDB_PARSE_ERROR_MESSAGE = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
