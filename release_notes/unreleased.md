**Unreleased**

* Ported the DNSDB connector to the Splunk SOAR SDK with all seven classic actions: test connectivity, check rate limit, RDATA name lookup, RDATA IP lookup, RDATA raw lookup, RRSET lookup, and flex search.
* Added a new make request action for authenticated calls to the DNSDB API.
* **Playbook Backward Compatibility**: The 'test connectivity' action's identifier changed from `test_asset_connectivity` to `test_connectivity`. This is enforced by the SOAR SDK (the identifier cannot be customized) and is not configurable. Any playbook that calls the action by its old identifier must be updated to use `test_connectivity` instead. No other action identifiers changed.
* The minimum supported SOAR version is now 7.0.0 (previously 6.3.0).
