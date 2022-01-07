[comment]: # "Auto-generated SOAR connector documentation"
# DNSDB

Publisher: Splunk  
Connector Version: 2\.0\.3  
Product Vendor: Farsight Security, Inc\.  
Product Name: DNSDB  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.9\.39220  

This app supports investigative DNS lookup actions on DNSDB

[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2016-2021 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
## Description of Action Parameters

1.  ### Test Connectivity (Action Workflow)

    -   This action will test the connectivity with the dnsdb server using the provided API key
        value through the rate_limit API.\[https://api.dnsdb.info/dnsdb/v2/rate_limit\]
    -   The action also validates the required asset parameter values and based on the value API
        response will be displayed.
    -   For successful test connectivity, the query quota details would be shown.  
        For example: “Test succeeded. Query quota is 1000 with 987 queries remaining. Resets
        1618531200”

      

2.  ### RDATA Name Lookup

    -   **<u>Action Parameter</u> ​ - name**
        -   The value is a DNS domain name in presentation format ("www.example.com"), or a
            left-hand (“.example.com”) or right-hand (“www.example.”) wildcard domain name.
        -   Example: www.farsightsecurity.io
    -   **<u>Action Parameter</u> ​ - limit**
        -   Limit for the number of results returned via these lookup methods. The default value of
            limit is ‘200’
        -   For limit=0 , maximum number of results will retrieved.\[ here max = results_max of
            rate_limit\].

      

3.  ### RDATA IP Lookup

    -   **<u>Action Parameter</u> ​ - ip**
        -   The value is one of an IPv4 or IPv6 single address, with a prefix length, or with an
            address range.
        -   Example: 192.18.12.01
    -   **<u>Action Parameter</u> ​ - limit**
        -   Limit for the number of results returned via these lookup methods. The default value of
            limit is ‘200’
        -   For limit=0 , maximum number of results will retrieved.\[ here max = results_max of
            rate_limit\].
    -   **<u>Action Parameter</u> ​ - network prefix**
        -   Network prefix is a numeric parameter which is used to search out the rdata within the
            network prefix range.
        -   Example: 192.0. 2.0/24 , 2001:db8::/128 If ip = 192.0.2.0 then network prefix = 24
    -   **Note:** If a prefix is provided, the delimiter between the network address and prefix
        length is a single comma (“,”) character rather than the usual slash (“/”) character to
        avoid clashing with the HTTP URI path name separator.

      

4.  ### RDATA Raw Lookup

    -   **<u>Action Parameter</u> ​ - raw rdata**
        -   The value is an even number of hexadecimal digits specifying a raw octet string.
        -   Example: 0366736902696f00
    -   **<u>Action Parameter</u> ​ - limit**
        -   Limit for the number of results returned via these lookup methods. The default value of
            limit is ‘200’
        -   For limit=0 , maximum number of results will retrieved.\[ here max = results_max of
            rate_limit\].

      

5.  ### RRSET Lookup

    -   **<u>Action Parameter</u> ​ - owner name**
        -   The value is a DNS owner name in presentation format (www.example.com) or wildcards as
            described below.
        -   Wildcards are one of two forms: a left-hand (\*.example.com) or right-hand
            (www.example.\*) wildcard domain name.
        -   Example: www.farsightsecurity.com
    -   **<u>Action Parameter</u> ​ - type**
        -   Type is a different DNS record type. The supported types are listed below this section.
            For more information check out the dnsdb API documentation.
        -   Default value for ‘type’ is ‘ANY’.
    -   **<u>Action Parameter</u> ​ - bailiwick**
        -   A bailiwick is an enclosing zone for a nameserver that serves the RRset or the name of
            the zone containing the RRset.
        -   Example: owner name = farsightsecurity.com. bailiwick = com.
    -   **<u>Action Parameter</u> ​ - limit**
        -   Limit for the number of results returned via these lookup methods. The default value of
            limit is ‘200’.
        -   For limit=0 , maximum number of results will retrieved.\[ here max = results_max of
            rate_limit\].

      

6.  ### Flex Search

    -   **<u>Action Parameter</u> ​ - query**
        -   Query is a string type of parameter for searching out the specific pattern in rrnames or
            rdata.
        -   Example: ^\[1-3\]\*.\*.com , ns\[0-9\]\*.net.
    -   **<u>Action Parameter</u> ​ - type**
        -   Type parameter is used for what to search for provided query value.Supported type
            values: rrnames, rdata.
        -   rrnames type search in rrnames, supports “forward” searches based on the owner name of
            an RRset.
        -   rdata type search in rdata, supports “inverse” searches based on RData record values.
    -   **<u>Action Parameter</u> ​ - search type**
        -   Two search method supported namely for flex search namely,

              

            1.  ‘regex’ - FCRE supported regex search
            2.  ‘glob’ - Advanced form of wildcard searches

        -   For more information: <https://docs.dnsdb.info/dnsdb-flex-reference-guide>
    -   **<u>Action Parameter</u> ​ - exclude**
        -   The “exclude” parameter is used to exclude (i.e. filter-out) results that match it. Its
            value is a regular expression or glob, depending upon the search_method.
        -   Example: The query value ‘^fsi\\.io’ will search out all the data start with fsi and
            proceed with ‘.io’ \[‘fsi.io.’ , ‘fsi.iota.ca’\] but the exclude=
            ‘\\.(com\|site\|bid\|net\|io)\\.’ will exclude the \[‘fsi.io.’\] values.
    -   **<u>Action Parameter</u> ​ - limit**
        -   Limit for the number of unique rrnames or rdata value results returned via these search
            methods. The default limit is set at 10,000.
        -   For limit=0 , maximum number of results will retrieved.\[ here max = results_max of
            rate_limit\]
    -   **<u>Note</u> ​**
        -   The maximum length of the QUERY path component and the exclude parameter value are 4096
            characters each before URL encoding.
    -   To know more about regex and glob search, visit:
        <https://docs.dnsdb.info/dnsdb-flex-reference-guide/#regex-search>

      

-   ### Time Fencing parameters

      

    -   **<u>Action Parameter</u> ​ - time_first_before**
        -   Provide results before the defined timestamp for when the DNS record was first observed.
            For example, the URL parameter “time_first_before=1420070400” will only provide matching
            DNS records that were first observed before (or older than) January 1, 2015.
    -   **<u>Action Parameter</u> ​ - time_first_after**
        -   Provide results after the defined timestamp for when the DNS record was first observed.
            For example, the URL parameter “time_first_after=-31536000” will only provide results
            that were first observed within the last year.
    -   **<u>Action Parameter</u> ​ - time_last_before**
        -   Provide results before the defined timestamp for when the DNS record was last observed.
            For example, the URL parameter “time_last_before=1356998400” will only provide results
            for DNS records that were last observed before 2013.
    -   **<u>Action Parameter</u> ​ - time_last_after**
        -   Provide results after the defined timestamp for when the DNS record was last observed.
            For example, the URL parameter “time_last_after=-2678400” will only provide results that
            were last observed after 31 days ago
    -   **<u>Note:</u> ​**
        -   Combinations of the time parameters may be used to strictly provide or exclude results
            for specific time-ranges. For example, to only have results when the first observed date
            and the last observed date are both only in 2015, you can use
            “time_first_after=1420070399” combined with “time_last_before=1451606400”. As another
            time combination example, to get DNS records that were first observed before 2012 and
            last observed within the last month (recently-observed records which have not changed in
            a very long time), use “time_first_before=1325376000” and relative
            “time_last_after=-2678400”.

      

-   ### For 'Type' action parameter in RDATA Raw Lookup and RRSET Lookup

      

    -   Supported DNS record **types** :  
        -   ANY
        -   A
        -   A6
        -   AAAA
        -   AFSDB
        -   CNAME
        -   DNAME
        -   HINFO
        -   ISDN
        -   KX
        -   NAPTR
        -   NXT
        -   MB
        -   MD
        -   MF
        -   MG
        -   MINFO
        -   MR
        -   MX
        -   NS
        -   PTR
        -   PX
        -   RP
        -   RT
        -   SIG
        -   SOA
        -   SRV
        -   TXT
        -   ANY-DNSSEC
        -   DLV
        -   DNSKEY
        -   DS
        -   NSEC
        -   NSEC3
        -   NSEC3PARAM
        -   RRSIG
    -   'ANY' returns records from types: A, A6, AAAA, AFSDB, CNAME, DNAME, HINFO, ISDN, KX, NAPTR,
        NXT, MB, MD, MF, MG, MINFO, MR, MX, NS, PTR, PX, RP, RT, SIG, SOA, SRV, TXT.
    -   'ANY-DNSSEC' returns records from types: DLV, DNSKEY, DS, NSEC, NSEC3, NSEC3PARAM, RRSIG.
    -   For types ANY and ANY-DNSSEC, low limit can leave out retrieval of some record types.
    -   If no type is provide, then action will use 'ANY' as default

  

## Playbook Backward Compatibility

-   The existing action names and their parameters have been modified in the actions given below.
    Hence, it is requested to the end-user to please update their existing playbooks by re-inserting
    \| modifying \| deleting the corresponding action blocks or by providing appropriate values to
    these action parameters to ensure the correct functioning of the playbooks created on the
    earlier versions of the app.

      

    -   Lookup IP - This action has been renamed to 'RDATA IP Lookup'.

          

        -   The parameters 'record seen after' and 'record seen below' have been removed.
        -   New parameters 'time first after', 'time first before', 'time last after', and 'time
            last before' have been added

    -   Lookup Domain - This action has been renamed to 'RDATA Name Lookup'.

          

        -   The parameters 'domain', 'type', 'record seen after', and 'record seen below' have been
            removed.
        -   New parameters 'name', 'time first after', 'time first before', 'time last after', and
            'time last before' have been added

-   New actions have been added. Hence, it is requested to the end-user to please update their
    existing playbooks by inserting the corresponding action blocks for this action on the earlier
    versions of the app.

      

    -   Check Rate Limit
    -   Flex Search
    -   RRSET Lookup
    -   RDATA Raw Lookup


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a DNSDB asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api\_key** |  required  | password | API Key

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity  
[check rate limit](#action-check-rate-limit) - Get data of current data limit  
[rdata name lookup](#action-rdata-name-lookup) - Performs Name RDATA Lookup  
[rdata ip lookup](#action-rdata-ip-lookup) - Performs IP RDATA Lookup  
[rdata raw lookup](#action-rdata-raw-lookup) - Lookup raw RDATA  
[rrset lookup](#action-rrset-lookup) - Perform a DNSDB RRSET lookup  
[flex search](#action-flex-search) - Perform a Flex search  

## action: 'test connectivity'
Validate the asset configuration for connectivity

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'check rate limit'
Get data of current data limit

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.reset | numeric | 
action\_result\.data\.\*\.remaining | numeric | 
action\_result\.data\.\*\.limit | numeric | 
action\_result\.data\.\*\.offset\_max | numeric | 
action\_result\.data\.\*\.results\_max | numeric | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'rdata name lookup'
Performs Name RDATA Lookup

Type: **investigate**  
Read only: **True**

If the <b>limit</b> parameter is not specified, the action will use 200\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** |  required  | Name to lookup | string |  `domain` 
**time\_first\_after** |  optional  | Record first seen after \(epoch, relative seconds e\.g\. \-31536000, or UTC timestamp e\.g\. 2021\-01\-05T12\:06\:02Z\) | string | 
**time\_first\_before** |  optional  | Record first seen before \(epoch, relative seconds e\.g\. \-31536000, or UTC timestamp e\.g\. 2021\-01\-05T12\:06\:02Z\) | string | 
**time\_last\_after** |  optional  | Record last seen after \(epoch, relative seconds e\.g\. \-31536000, or UTC timestamp e\.g\. 2021\-01\-05T12\:06\:02Z\) | string | 
**time\_last\_before** |  optional  | Record last seen before \(epoch, relative seconds e\.g\. \-31536000, or UTC timestamp e\.g\. 2021\-01\-05T12\:06\:02Z\) | string | 
**limit** |  optional  | Max records to return | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.name | string |  `domain` 
action\_result\.parameter\.time\_first\_before | string | 
action\_result\.parameter\.time\_first\_after | string | 
action\_result\.parameter\.time\_last\_before | string | 
action\_result\.parameter\.time\_last\_after | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.data\.\*\.count | numeric | 
action\_result\.data\.\*\.rdata | string |  `domain` 
action\_result\.data\.\*\.rrname | string |  `domain` 
action\_result\.data\.\*\.rrtype | string | 
action\_result\.data\.\*\.time\_last | numeric | 
action\_result\.data\.\*\.time\_first | numeric | 
action\_result\.data\.\*\.zone\_time\_last | numeric | 
action\_result\.data\.\*\.zone\_time\_first | numeric | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.total\_domains | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'rdata ip lookup'
Performs IP RDATA Lookup

Type: **investigate**  
Read only: **True**

If the <b>limit</b> parameter is not specified, the action will use 200\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to resolve | string |  `ip`  `dnsdb ipv6` 
**network\_prefix** |  optional  | Network prefix | numeric | 
**time\_first\_after** |  optional  | Record first seen after \(epoch, relative seconds e\.g\. \-31536000, or UTC timestamp e\.g\. 2021\-01\-05T12\:06\:02Z\) | string | 
**time\_first\_before** |  optional  | Record first seen before \(epoch, relative seconds e\.g\. \-31536000, or UTC timestamp e\.g\. 2021\-01\-05T12\:06\:02Z\) | string | 
**time\_last\_after** |  optional  | Record last seen after \(epoch, relative seconds e\.g\. \-31536000, or UTC timestamp e\.g\. 2021\-01\-05T12\:06\:02Z\) | string | 
**time\_last\_before** |  optional  | Record last seen before \(epoch, relative seconds e\.g\. \-31536000, or UTC timestamp e\.g\. 2021\-01\-05T12\:06\:02Z\) | string | 
**limit** |  optional  | Max records to return | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip | string |  `ip`  `dnsdb ipv6` 
action\_result\.parameter\.network\_prefix | numeric | 
action\_result\.parameter\.time\_first\_before | string | 
action\_result\.parameter\.time\_first\_after | string | 
action\_result\.parameter\.time\_last\_before | string | 
action\_result\.parameter\.time\_last\_after | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.data\.\*\.count | numeric | 
action\_result\.data\.\*\.rdata | string |  `ip`  `dnsdb ipv6` 
action\_result\.data\.\*\.rrname | string |  `domain` 
action\_result\.data\.\*\.rrtype | string |  `dnsdb rrtype` 
action\_result\.data\.\*\.time\_last | numeric | 
action\_result\.data\.\*\.time\_first | numeric | 
action\_result\.data\.\*\.zone\_time\_last | numeric | 
action\_result\.data\.\*\.zone\_time\_first | numeric | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.total\_domains | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'rdata raw lookup'
Lookup raw RDATA

Type: **investigate**  
Read only: **True**

If the <b>limit</b> parameter is not specified, the action will use 200\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**raw\_rdata** |  required  | An even number of hexadecimal digits specifying a raw octet string | string |  `dnsdb rdata` 
**type** |  optional  | DNS record type | string |  `dnsdb rrtype` 
**time\_first\_after** |  optional  | Record first seen after \(epoch, relative seconds e\.g\. \-31536000, or UTC timestamp e\.g\. 2021\-01\-05T12\:06\:02Z\) | string | 
**time\_first\_before** |  optional  | Record first seen before \(epoch, relative seconds e\.g\. \-31536000, or UTC timestamp e\.g\. 2021\-01\-05T12\:06\:02Z\) | string | 
**time\_last\_after** |  optional  | Record last seen after \(epoch, relative seconds e\.g\. \-31536000, or UTC timestamp e\.g\. 2021\-01\-05T12\:06\:02Z\) | string | 
**time\_last\_before** |  optional  | Record last seen before \(epoch, relative seconds e\.g\. \-31536000, or UTC timestamp e\.g\. 2021\-01\-05T12\:06\:02Z\) | string | 
**limit** |  optional  | Max records to return | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.raw\_rdata | string |  `dnsdb rdata` 
action\_result\.parameter\.type | string |  `dnsdb rrtype` 
action\_result\.parameter\.time\_first\_before | string | 
action\_result\.parameter\.time\_first\_after | string | 
action\_result\.parameter\.time\_last\_before | string | 
action\_result\.parameter\.time\_last\_after | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.data\.\*\.count | numeric | 
action\_result\.data\.\*\.rdata | string |  `ip`  `dnsdb ipv6` 
action\_result\.data\.\*\.rrname | string |  `domain` 
action\_result\.data\.\*\.rrtype | string |  `dnsdb rrtype` 
action\_result\.data\.\*\.time\_last | numeric | 
action\_result\.data\.\*\.time\_first | numeric | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.total\_domains | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'rrset lookup'
Perform a DNSDB RRSET lookup

Type: **investigate**  
Read only: **True**

If the <b>limit</b> parameter is not specified, the action will use 200\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**owner\_name** |  required  | Domain to resolve | string |  `domain` 
**type** |  optional  | DNS record type | string |  `dnsdb rrtype` 
**time\_first\_after** |  optional  | Record first seen after \(epoch, relative seconds e\.g\. \-31536000, or UTC timestamp e\.g\. 2021\-01\-05T12\:06\:02Z\) | string | 
**time\_first\_before** |  optional  | Record first seen before \(epoch, relative seconds e\.g\. \-31536000, or UTC timestamp e\.g\. 2021\-01\-05T12\:06\:02Z\) | string | 
**time\_last\_after** |  optional  | Record last seen after \(epoch, relative seconds e\.g\. \-31536000, or UTC timestamp e\.g\. 2021\-01\-05T12\:06\:02Z\) | string | 
**time\_last\_before** |  optional  | Record last seen before \(epoch, relative seconds e\.g\. \-31536000, or UTC timestamp e\.g\. 2021\-01\-05T12\:06\:02Z\) | string | 
**bailiwick** |  optional  | Bailiwick | string | 
**limit** |  optional  | Max records to return | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.owner\_name | string |  `domain` 
action\_result\.parameter\.type | string |  `dnsdb rrtype` 
action\_result\.parameter\.bailiwick | string | 
action\_result\.parameter\.time\_first\_before | string | 
action\_result\.parameter\.time\_first\_after | string | 
action\_result\.parameter\.time\_last\_before | string | 
action\_result\.parameter\.time\_last\_after | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.data\.\*\.count | numeric | 
action\_result\.data\.\*\.rdata | string |  `ip`  `dnsdb ipv6`  `domain` 
action\_result\.data\.\*\.rdata\.\*\.rdata\_origin | string |  `host name` 
action\_result\.data\.\*\.rdata\.\*\.rdata\_mail\_addr | string |  `email` 
action\_result\.data\.\*\.rdata\.\*\.rdata\_serial | string | 
action\_result\.data\.\*\.rdata\.\*\.rdata\_refresh | string | 
action\_result\.data\.\*\.rdata\.\*\.rdata\_retry | string | 
action\_result\.data\.\*\.rdata\.\*\.rdata\_expire | string | 
action\_result\.data\.\*\.rdata\.\*\.rdata\_minimum | string | 
action\_result\.data\.\*\.rdata\.\*\.rdata\_preference | string | 
action\_result\.data\.\*\.rdata\.\*\.rdata\_mail\_exchange | string |  `domain` 
action\_result\.data\.\*\.rrname | string |  `domain` 
action\_result\.data\.\*\.rrtype | string |  `dnsdb rrtype` 
action\_result\.data\.\*\.bailiwick | string |  `domain` 
action\_result\.data\.\*\.time\_last | numeric | 
action\_result\.data\.\*\.time\_first | numeric | 
action\_result\.data\.\*\.zone\_time\_last | numeric | 
action\_result\.data\.\*\.zone\_time\_first | numeric | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.total\_items | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'flex search'
Perform a Flex search

Type: **investigate**  
Read only: **True**

If the <b>limit</b> parameter is not specified, the action will use default value as 10000\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | Flex search query | string | 
**type** |  required  | DNS record type | string | 
**search\_type** |  required  | Search syntax type | string | 
**time\_first\_after** |  optional  | Record first seen after \(epoch, relative seconds e\.g\. \-31536000, or UTC timestamp e\.g\. 2021\-01\-05T12\:06\:02Z\) | string | 
**time\_first\_before** |  optional  | Record first seen before \(epoch, relative seconds e\.g\. \-31536000, or UTC timestamp e\.g\. 2021\-01\-05T12\:06\:02Z\) | string | 
**time\_last\_after** |  optional  | Record last seen after \(epoch, relative seconds e\.g\. \-31536000, or UTC timestamp e\.g\. 2021\-01\-05T12\:06\:02Z\) | string | 
**time\_last\_before** |  optional  | Record last seen before \(epoch, relative seconds e\.g\. \-31536000, or UTC timestamp e\.g\. 2021\-01\-05T12\:06\:02Z\) | string | 
**exclude** |  optional  | Exclusion pattern \(regex\) | string | 
**limit** |  optional  | Max records to return | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.search\_type | string | 
action\_result\.parameter\.type | string | 
action\_result\.parameter\.query | string | 
action\_result\.parameter\.time\_first\_after | string | 
action\_result\.parameter\.time\_first\_before | string | 
action\_result\.parameter\.time\_last\_after | string | 
action\_result\.parameter\.time\_last\_before | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.exclude | string | 
action\_result\.data\.\*\.count | numeric | 
action\_result\.data\.\*\.rdata | string |  `ip`  `dnsdb ipv6`  `domain` 
action\_result\.data\.\*\.rdata\.\*\.rdata\_origin | string |  `host name` 
action\_result\.data\.\*\.rdata\.\*\.rdata\_mail\_addr | string |  `email` 
action\_result\.data\.\*\.rdata\.\*\.rdata\_serial | string | 
action\_result\.data\.\*\.rdata\.\*\.rdata\_refresh | string | 
action\_result\.data\.\*\.rdata\.\*\.rdata\_retry | string | 
action\_result\.data\.\*\.rdata\.\*\.rdata\_expire | string | 
action\_result\.data\.\*\.rdata\.\*\.rdata\_minimum | string | 
action\_result\.data\.\*\.rdata\.\*\.rdata\_preference | string | 
action\_result\.data\.\*\.rdata\.\*\.rdata\_mail\_exchange | string |  `domain` 
action\_result\.data\.\*\.rrname | string |  `domain` 
action\_result\.data\.\*\.rrtype | string |  `dnsdb rrtype` 
action\_result\.data\.\*\.bailiwick | string |  `domain` 
action\_result\.data\.\*\.time\_last | numeric | 
action\_result\.data\.\*\.time\_first | numeric | 
action\_result\.data\.\*\.zone\_time\_last | numeric | 
action\_result\.data\.\*\.zone\_time\_first | numeric | 
action\_result\.data\.\*\.raw\_rdata | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.total\_items | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 