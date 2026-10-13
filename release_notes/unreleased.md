**Unreleased**

* Ported the DNSDB connector to the Splunk SOAR SDK with all seven classic actions: test connectivity, check rate limit, RDATA name lookup, RDATA IP lookup, RDATA raw lookup, RRSET lookup, and flex search.
* Added a new make request action for authenticated calls to the DNSDB API.
* **Playbook Backward Compatibility**: The 'test connectivity' action's identifier changed from `test_asset_connectivity` to `test_connectivity`. This is enforced by the SOAR SDK (the identifier cannot be customized) and is not configurable. Any playbook that calls the action by its old identifier must be updated to use `test_connectivity` instead. No other action identifiers changed.
* The minimum supported SOAR version is now 7.0.0 (previously 6.3.0).
* The RDATA name and RRSET lookups now accept domain names with digits in a label (for example, `ns1.example.com` or `1password.com`). Earlier versions rejected them with `Parameter 'name' failed validation` because of an error in the validation pattern.
* UTC timestamps (for example, `2021-01-05T12:06:02Z`) in the time filter parameters now work. The app converts them to epoch seconds before calling DNSDB; earlier versions sent them unchanged and DNSDB rejected them.
* In the app manifest, `rdata` for the RDATA name, IP, and raw lookups is now listed as `action_result.data.*.rdata.*`. Unused SOA/MX datapaths were removed from flex search. Action results are unchanged.
