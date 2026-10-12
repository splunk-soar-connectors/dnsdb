**Unreleased**

* Ported the DNSDB connector to the Splunk SOAR SDK with all seven classic actions: test connectivity, check rate limit, RDATA name lookup, RDATA IP lookup, RDATA raw lookup, RRSET lookup, and flex search.
* Added a new make request action for authenticated calls to the DNSDB API.
* **Playbook Backward Compatibility**: The 'test connectivity' action's identifier changed from `test_asset_connectivity` to `test_connectivity`. This is enforced by the SOAR SDK (the identifier cannot be customized) and is not configurable. Any playbook that calls the action by its old identifier must be updated to use `test_connectivity` instead. No other action identifiers changed.
* The RDATA name, RDATA IP, RDATA raw, RRSET, and flex search actions now also report a success message in `action_result.message` (for example, `Total domains: 5` or `Total items: 5`). The existing `action_result.summary` fields (`total_domains`, `total_items`) are unchanged.
* The check rate limit action now shows the actual error text when an unexpected error occurs, instead of the generic `Connectivity test failed` message. Test connectivity still shows `Connectivity test failed`.
* The flex search output now declares the `rdata` field in `action_result.data`, which the earlier version returned but did not list.
* The custom result views were rebuilt for the SDK. The data tables and record type dropdowns are unchanged, but the input parameter summary table shown at the top of each view is no longer displayed.
* The minimum supported SOAR version is now 7.0.0 (previously 6.3.0).
