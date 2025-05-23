# File: dnsdb_consts.py
#
# Copyright (c) 2016-2025 Splunk Inc.
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
DNSDB_JSON_RTYPE_IP = "A"
DNSDB_JSON_API_KEY = "api_key"  # pragma: allowlist secret
DNSDB_JSON_OWNER_NAME = "owner_name"
DNSDB_JSON_BAILIWICK = "bailiwick"
DNSDB_JSON_TYPE = "type"
DNSDB_JSON_SEARCH_TYPE = "search_type"
DNSDB_JSON_TYPE_DEFAULT = "ANY"
DNSDB_JSON_QUERY = "query"
DNSDB_JSON_EXCLUDE = "exclude"
DNSDB_JSON_NETWORK_PREFIX = "network_prefix"
DNSDB_JSON_LIMIT = "limit"
DNSDB_JSON_RECORD_SEEN_BEFORE = "record_seen_before"
DNSDB_JSON_RECORD_SEEN_AFTER = "record_seen_after"
DNSDB_JSON_TIME_FIRST_BEFORE = "time_first_before"
DNSDB_JSON_TIME_FIRST_AFTER = "time_first_after"
DNSDB_JSON_TIME_LAST_BEFORE = "time_last_before"
DNSDB_JSON_TIME_LAST_AFTER = "time_last_after"
DNSDB_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DNSDB_JSON_RATE = "rate"
DNSDB_JSON_IP = "ip"
DNSDB_JSON_NAME = "name"
DNSDB_JSON_RRNAME = "rrname"
DNSDB_JSON_RAW_RDATA = "raw_rdata"
DNSDB_JSON_RESPONSE = "json_response"
DNSDB_BASE_URL = "https://api.dnsdb.info/dnsdb/v2/lookup"
DNSDB_ENDPOINT_DOMAIN = "/rrset/name/{domain}"
DNSDB_ENDPOINT_DOMAIN_TYPE = "/rrset/name/{domain}/{type}"
DNSDB_ENDPOINT_DOMAIN_TYPE_ZONE = "/rrset/name/{domain}/{type}/{zone}"
DNSDB_ENDPOINT_IP = "/rdata/ip/{ip}"
DNSDB_ENDPOINT_IP_PREFIX = "/rdata/ip/{ip},{prefix}"
DNSDB_ERROR_API_UNSUPPORTED_METHOD = "Unsupported method : {method}"
DNSDB_ERROR_INVALID_TIME_FORMAT = "Invalid time format : {time}"
DNSDB_ERROR_INVALID_TIME = "Future date value is not allowed. Please provide valid datetime"
DNSDB_ERROR_INVALID_LIMIT = "Invalid response length limit : {limit}"
DNSDB_ERROR_INVALID_NETWORK_PREFIX = "Invalid network prefix : {prefix}"
DNSDB_ERROR_INVALID_BAILIWICK = "Invalid bailiwick : %s"
DNSDB_TEST_CONNECTIVITY_INITIATION = "Testing connectivity"
DNSDB_TEST_CONNECTIVITY_DOMAIN = "www.phantomcyber.com"
DNSDB_TEST_CONNECTIVITY_FAIL = "Connectivity test failed"
DNSDB_TEST_CONNECTIVITY_SUCCESS = "Connectivity test succeeded"
DNSDB_TEST_CONNECTIVITY_MESSAGE = "Running a rate-limit query to check API key with DNSDB"
DNSDB_TEST_CONNECTIVITY_SUCCESS_MESSAGE = "Test succeeded. Query quota is %s with %s queries remaining. Resets %s"
DNSDB_REST_RESP_SUCCESS = 200
DNSDB_REST_RESP_SUCCESS_MESSAGE = "Request Successful"
DNSDB_REST_RESP_RESOURCE_INCORRECT = 400
DNSDB_REST_RESP_RESOURCE_INCORRECT_MESSAGE = "Invalid input. The resource is in an incorrect format"
DNSDB_REST_RESP_ACCESS_DENIED = 403
DNSDB_REST_RESP_ACCESS_DENIED_MESSAGE = "The API key is invalid"
DNSDB_REST_RESP_RESOURCE_NOT_FOUND = 404
DNSDB_REST_RESP_RESOURCE_NOT_FOUND_MESSAGE = "Resource not found"
DNSDB_REST_RESP_LIC_EXCEED = 429
DNSDB_REST_RESP_LIC_EXCEED_MESSAGE = "The license count usage for the given period has been exceeded."
DNSDB_REST_RESP_OVERLOADED = 503
DNSDB_REST_RESP_OVERLOADED_MESSAGE = "Server is overloaded. Retry your call after the time period displayed."
DNSDB_ERROR_JSON_PARSE = "Unable to parse the fields parameter into a dictionary. , Response text - {raw_text}"
DNSDB_ERROR_FROM_SERVER = "API failed, Status code: {status}, Detail: {detail}"
DNSDB_ERROR_SERVER_CONNECTION = "Connection failed"
DNSDB_REST_RESP_OTHER_ERROR_MESSAGE = "Error occurred"
DNSDB_DATA_NOT_AVAILABLE_MESSAGE = "Data not available"

# Error message handling constants
DNSDB_ERROR_CODE_MESSAGE = "Error code unavailable"
DNSDB_ERROR_MESSAGE_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
DNSDB_PARSE_ERROR_MESSAGE = "Unable to parse the error message. Please check the asset configuration and|or action parameters"

# Integer validation constants
DNSDB_VALID_INTEGER_MESSAGE = "Please provide a valid integer value in the {key}"
DNSDB_NON_NEGATIVE_INTEGER_MESSAGE = "Please provide a valid non-negative integer value in the {key}"
DNSDB_LIMIT_KEY = "'limit' action parameter"
DNSDB_NETWORK_PREFIX_KEY = "'network_prefix' action parameter"

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
DNSDB_JSON_TYPE_VALUE_LIST = ["RDATA", "RRNAMES"]
DNSDB_JSON_SEARCH_TYPE_VALUE_LIST = ["regex", "glob"]
DNSDB_VALUE_LIST_VALIDATION_MESSAGE = "Please provide valid input from {} in '{}' action parameter"
