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
from soar_sdk.app import App

from .actions import register_actions
from .asset import Asset
from .test_connectivity import run_test_connectivity


def create_dnsdb_app() -> App:
    app = App(
        name="DNSDB",
        app_type="investigative",
        logo="logo_dnsdb.svg",
        logo_dark="logo_dnsdb_dark.svg",
        product_vendor="Farsight Security, Inc.",
        product_name="DNSDB",
        publisher="Splunk",
        appid="adf140f0-60e3-45ff-8d69-258b3c0a63b1",
        min_phantom_version="7.0.0",
        fips_compliant=True,
        encrypt_cache_state=True,
        encrypt_ingest_state=True,
        asset_cls=Asset,
    )

    @app.test_connectivity()
    def test_connectivity(soar: SOARClient, asset: Asset) -> None:
        """Validate the asset configuration for connectivity."""
        run_test_connectivity(soar, asset)

    return register_actions(app)


app: App = create_dnsdb_app()


if __name__ == "__main__":
    app.cli()
